# Data type

[TOC]

#### 00x01 redisObject 

---

```c
typedef struct redisObject {
    unsigned type:4;
    unsigned encoding:4;
    unsigned lru:LRU_BITS; /* LRU time (relative to global lru_clock) or
                            * LFU data (least significant 8 bits frequency
                            * and most significant 16 bits access time). */
    int refcount;
    void *ptr;
} robj;
```

redis有五种存储数据类型，字符串(string)、列表(list)、散列(hash)、集合(set)、有序集合(zset)。但为了压缩存储空间，并没有显示定义为结构体，而是由redisObject的属性保存一些信息，然后由ptr来指向内存空间，而这些内存块多由ziplist、sds等基本数据类型构建。

##### type

server.h中对此项内容进行了宏定义，与encoding一样是用于在create时作为不同处理的标志

```c
/* The actual Redis Object */
#define OBJ_STRING 0
#define OBJ_LIST 1
#define OBJ_SET 2
#define OBJ_ZSET 3
#define OBJ_HASH 4
```

##### encoding

同样在server.h中对编码方式进行了宏定义

```c
#define OBJ_ENCODING_RAW 0     /* Raw representation */
#define OBJ_ENCODING_INT 1     /* Encoded as integer */
#define OBJ_ENCODING_HT 2      /* Encoded as hash table */
#define OBJ_ENCODING_ZIPMAP 3  /* Encoded as zipmap */
#define OBJ_ENCODING_LINKEDLIST 4 /* No longer used: old list encoding. */
#define OBJ_ENCODING_ZIPLIST 5 /* Encoded as ziplist */
#define OBJ_ENCODING_INTSET 6  /* Encoded as intset */
#define OBJ_ENCODING_SKIPLIST 7  /* Encoded as skiplist */
#define OBJ_ENCODING_EMBSTR 8  /* Embedded sds string encoding */
#define OBJ_ENCODING_QUICKLIST 9 /* Encoded as linked list of ziplists */
```

##### lru

**Least Recently Used 近期最少引用算法**

是redis(也是memcache)所使用的在内存不足时的清理算法，是一种缓存淘汰算法

其核心思想是“如果数据最近被访问过，那么将来被访问的几率也更高”

在object.c的各create函数中使用如下：

```c
if (server.maxmemory_policy & MAXMEMORY_FLAG_LFU) {
        o->lru = (LFUGetTimeInMinutes()<<8) | LFU_INIT_VAL;
    } else {
        o->lru = LRU_CLOCK();
    }
```

redis中实现的LRU比淘汰不如标准LRU严格，但在资源消耗上要低很多，其实现在evict.c中

另外还有两种清理模式，随机淘汰-随机删除一个key，TTL淘汰-删除最快过期的key

##### refcount

引用计数，实际上属于垃圾回收算法，在redis中用于防止多客户端的冲突。

对一个对象的refcount，当客户端初始化时get则+1，del-1，引用+1，引用失效-1，当refcount为0时会被清理。

当一个客户端调用get查看k-v的同时时，另一个客户端用del删除此键值对，此键值对并不会立即被删除，而是在第一个客户端对其引用失效时才会被清理。

##### ptr

指向数据实现内存块的指针

同一种数据类型，根据encoding的不同，也可能会指向不同的结构



#### 00x02 数据与命令

---

object.c内定义了redis所有数据类型的基本相关函数，包括构建、解析、释放与对比等功能，但只有string类型的底层数据实现直接定义在object.c中，其他的都定义在相应的基本数据类型源文件中，zset的数据结构定义在server.h中

`createObject`是一个通用函数，结构比较简单，只负责装配信息，传入的ptr指向已构建好的数据块。并且，在调用这一函数后，o -> encoding常常会被修改。

```c
robj *createObject(int type, void *ptr) {
    robj *o = zmalloc(sizeof(*o));
    o->type = type;
    o->encoding = OBJ_ENCODING_RAW;
    o->ptr = ptr;
    o->refcount = 1;

    /* Set the LRU to the current lruclock (minutes resolution), or
     * alternatively the LFU counter. */
    if (server.maxmemory_policy & MAXMEMORY_FLAG_LFU) {
        o->lru = (LFUGetTimeInMinutes()<<8) | LFU_INIT_VAL;
    } else {
        o->lru = LRU_CLOCK();
    }
    return o;
}
```

数据实现的方式据encoding的不同而改变

关于redis命令

```c
//server.h
typedef void redisCommandProc(client *c);
typedef int *redisGetKeysProc(struct redisCommand *cmd, robj **argv, int argc, int *numkeys);
struct redisCommand {
    char *name;	//命令名称
    redisCommandProc *proc;	//函数指针
    int arity;	//参数个数，-n代表不小于n个参数
    char *sflags; /* Flags as string representation, one char per flag. */ 
    //命令标志位字符串表示，详见下方表格
    int flags;    /* The actual flags, obtained from the 'sflags' field. */
    /* Use a function to determine keys arguments in a command line.
     * Used for Redis Cluster redirect. */ //看起来是与集群有关，后面遇到再说
    redisGetKeysProc *getkeys_proc;	//返回key对应的int*类型位置
    /* What keys should be loaded in background when calling this command? */
    int firstkey; /* The first argument that's a key (0 = no keys) 第一个key的位置*/
    int lastkey;  /* The last argument that's a key 最后一个key的位置*/
    int keystep;  /* The step between first and last key 间距*/
    long long microseconds, calls; //总调用时间，总调用次数
};
//server.c
struct redisCommand redisCommandTable[] = {
    {"module",moduleCommand,-2,"as",0,NULL,0,0,0,0,0},
    {"get",getCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"set",setCommand,-3,"wm",0,NULL,1,1,1,0,0},
    {"setnx",setnxCommand,3,"wmF",0,NULL,1,1,1,0,0},
    {"setex",setexCommand,4,"wm",0,NULL,1,1,1,0,0},
    {"psetex",psetexCommand,4,"wm",0,NULL,1,1,1,0,0},
    {"append",appendCommand,3,"wm",0,NULL,1,1,1,0,0},
    {"strlen",strlenCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"del",delCommand,-2,"w",0,NULL,1,-1,1,0,0},
    {"unlink",unlinkCommand,-2,"wF",0,NULL,1,-1,1,0,0},
    {"exists",existsCommand,-2,"rF",0,NULL,1,-1,1,0,0},
    {"setbit",setbitCommand,4,"wm",0,NULL,1,1,1,0,0},
    {"getbit",getbitCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"bitfield",bitfieldCommand,-2,"wm",0,NULL,1,1,1,0,0},
    {"setrange",setrangeCommand,4,"wm",0,NULL,1,1,1,0,0},
    {"getrange",getrangeCommand,4,"r",0,NULL,1,1,1,0,0},
    {"substr",getrangeCommand,4,"r",0,NULL,1,1,1,0,0},
    {"incr",incrCommand,2,"wmF",0,NULL,1,1,1,0,0},
    {"decr",decrCommand,2,"wmF",0,NULL,1,1,1,0,0},
    {"mget",mgetCommand,-2,"rF",0,NULL,1,-1,1,0,0},
    {"rpush",rpushCommand,-3,"wmF",0,NULL,1,1,1,0,0},
    {"lpush",lpushCommand,-3,"wmF",0,NULL,1,1,1,0,0},
    {"rpushx",rpushxCommand,-3,"wmF",0,NULL,1,1,1,0,0},
    {"lpushx",lpushxCommand,-3,"wmF",0,NULL,1,1,1,0,0},
    {"linsert",linsertCommand,5,"wm",0,NULL,1,1,1,0,0},
    {"rpop",rpopCommand,2,"wF",0,NULL,1,1,1,0,0},
    {"lpop",lpopCommand,2,"wF",0,NULL,1,1,1,0,0},
    {"brpop",brpopCommand,-3,"ws",0,NULL,1,-2,1,0,0},
    {"brpoplpush",brpoplpushCommand,4,"wms",0,NULL,1,2,1,0,0},
    {"blpop",blpopCommand,-3,"ws",0,NULL,1,-2,1,0,0},
    {"llen",llenCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"lindex",lindexCommand,3,"r",0,NULL,1,1,1,0,0},
    {"lset",lsetCommand,4,"wm",0,NULL,1,1,1,0,0},
    {"lrange",lrangeCommand,4,"r",0,NULL,1,1,1,0,0},
    {"ltrim",ltrimCommand,4,"w",0,NULL,1,1,1,0,0},
    {"lrem",lremCommand,4,"w",0,NULL,1,1,1,0,0},
    {"rpoplpush",rpoplpushCommand,3,"wm",0,NULL,1,2,1,0,0},
    {"sadd",saddCommand,-3,"wmF",0,NULL,1,1,1,0,0},
    {"srem",sremCommand,-3,"wF",0,NULL,1,1,1,0,0},
    {"smove",smoveCommand,4,"wF",0,NULL,1,2,1,0,0},
    {"sismember",sismemberCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"scard",scardCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"spop",spopCommand,-2,"wRF",0,NULL,1,1,1,0,0},
    {"srandmember",srandmemberCommand,-2,"rR",0,NULL,1,1,1,0,0},
    {"sinter",sinterCommand,-2,"rS",0,NULL,1,-1,1,0,0},
    {"sinterstore",sinterstoreCommand,-3,"wm",0,NULL,1,-1,1,0,0},
    {"sunion",sunionCommand,-2,"rS",0,NULL,1,-1,1,0,0},
    {"sunionstore",sunionstoreCommand,-3,"wm",0,NULL,1,-1,1,0,0},
    {"sdiff",sdiffCommand,-2,"rS",0,NULL,1,-1,1,0,0},
    {"sdiffstore",sdiffstoreCommand,-3,"wm",0,NULL,1,-1,1,0,0},
    {"smembers",sinterCommand,2,"rS",0,NULL,1,1,1,0,0},
    {"sscan",sscanCommand,-3,"rR",0,NULL,1,1,1,0,0},
    {"zadd",zaddCommand,-4,"wmF",0,NULL,1,1,1,0,0},
    {"zincrby",zincrbyCommand,4,"wmF",0,NULL,1,1,1,0,0},
    {"zrem",zremCommand,-3,"wF",0,NULL,1,1,1,0,0},
    {"zremrangebyscore",zremrangebyscoreCommand,4,"w",0,NULL,1,1,1,0,0},
    {"zremrangebyrank",zremrangebyrankCommand,4,"w",0,NULL,1,1,1,0,0},
    {"zremrangebylex",zremrangebylexCommand,4,"w",0,NULL,1,1,1,0,0},
    {"zunionstore",zunionstoreCommand,-4,"wm",0,zunionInterGetKeys,0,0,0,0,0},
    {"zinterstore",zinterstoreCommand,-4,"wm",0,zunionInterGetKeys,0,0,0,0,0},
    {"zrange",zrangeCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"zrangebyscore",zrangebyscoreCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"zrevrangebyscore",zrevrangebyscoreCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"zrangebylex",zrangebylexCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"zrevrangebylex",zrevrangebylexCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"zcount",zcountCommand,4,"rF",0,NULL,1,1,1,0,0},
    {"zlexcount",zlexcountCommand,4,"rF",0,NULL,1,1,1,0,0},
    {"zrevrange",zrevrangeCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"zcard",zcardCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"zscore",zscoreCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"zrank",zrankCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"zrevrank",zrevrankCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"zscan",zscanCommand,-3,"rR",0,NULL,1,1,1,0,0},
    {"hset",hsetCommand,-4,"wmF",0,NULL,1,1,1,0,0},
    {"hsetnx",hsetnxCommand,4,"wmF",0,NULL,1,1,1,0,0},
    {"hget",hgetCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"hmset",hsetCommand,-4,"wmF",0,NULL,1,1,1,0,0},
    {"hmget",hmgetCommand,-3,"rF",0,NULL,1,1,1,0,0},
    {"hincrby",hincrbyCommand,4,"wmF",0,NULL,1,1,1,0,0},
    {"hincrbyfloat",hincrbyfloatCommand,4,"wmF",0,NULL,1,1,1,0,0},
    {"hdel",hdelCommand,-3,"wF",0,NULL,1,1,1,0,0},
    {"hlen",hlenCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"hstrlen",hstrlenCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"hkeys",hkeysCommand,2,"rS",0,NULL,1,1,1,0,0},
    {"hvals",hvalsCommand,2,"rS",0,NULL,1,1,1,0,0},
    {"hgetall",hgetallCommand,2,"r",0,NULL,1,1,1,0,0},
    {"hexists",hexistsCommand,3,"rF",0,NULL,1,1,1,0,0},
    {"hscan",hscanCommand,-3,"rR",0,NULL,1,1,1,0,0},
    {"incrby",incrbyCommand,3,"wmF",0,NULL,1,1,1,0,0},
    {"decrby",decrbyCommand,3,"wmF",0,NULL,1,1,1,0,0},
    {"incrbyfloat",incrbyfloatCommand,3,"wmF",0,NULL,1,1,1,0,0},
    {"getset",getsetCommand,3,"wm",0,NULL,1,1,1,0,0},
    {"mset",msetCommand,-3,"wm",0,NULL,1,-1,2,0,0},
    {"msetnx",msetnxCommand,-3,"wm",0,NULL,1,-1,2,0,0},
    {"randomkey",randomkeyCommand,1,"rR",0,NULL,0,0,0,0,0},
    {"select",selectCommand,2,"lF",0,NULL,0,0,0,0,0},
    {"swapdb",swapdbCommand,3,"wF",0,NULL,0,0,0,0,0},
    {"move",moveCommand,3,"wF",0,NULL,1,1,1,0,0},
    {"rename",renameCommand,3,"w",0,NULL,1,2,1,0,0},
    {"renamenx",renamenxCommand,3,"wF",0,NULL,1,2,1,0,0},
    {"expire",expireCommand,3,"wF",0,NULL,1,1,1,0,0},
    {"expireat",expireatCommand,3,"wF",0,NULL,1,1,1,0,0},
    {"pexpire",pexpireCommand,3,"wF",0,NULL,1,1,1,0,0},
    {"pexpireat",pexpireatCommand,3,"wF",0,NULL,1,1,1,0,0},
    {"keys",keysCommand,2,"rS",0,NULL,0,0,0,0,0},
    {"scan",scanCommand,-2,"rR",0,NULL,0,0,0,0,0},
    {"dbsize",dbsizeCommand,1,"rF",0,NULL,0,0,0,0,0},
    {"auth",authCommand,2,"sltF",0,NULL,0,0,0,0,0},
    {"ping",pingCommand,-1,"tF",0,NULL,0,0,0,0,0},
    {"echo",echoCommand,2,"F",0,NULL,0,0,0,0,0},
    {"save",saveCommand,1,"as",0,NULL,0,0,0,0,0},
    {"bgsave",bgsaveCommand,-1,"a",0,NULL,0,0,0,0,0},
    {"bgrewriteaof",bgrewriteaofCommand,1,"a",0,NULL,0,0,0,0,0},
    {"shutdown",shutdownCommand,-1,"alt",0,NULL,0,0,0,0,0},
    {"lastsave",lastsaveCommand,1,"RF",0,NULL,0,0,0,0,0},
    {"type",typeCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"multi",multiCommand,1,"sF",0,NULL,0,0,0,0,0},
    {"exec",execCommand,1,"sM",0,NULL,0,0,0,0,0},
    {"discard",discardCommand,1,"sF",0,NULL,0,0,0,0,0},
    {"sync",syncCommand,1,"ars",0,NULL,0,0,0,0,0},
    {"psync",syncCommand,3,"ars",0,NULL,0,0,0,0,0},
    {"replconf",replconfCommand,-1,"aslt",0,NULL,0,0,0,0,0},
    {"flushdb",flushdbCommand,-1,"w",0,NULL,0,0,0,0,0},
    {"flushall",flushallCommand,-1,"w",0,NULL,0,0,0,0,0},
    {"sort",sortCommand,-2,"wm",0,sortGetKeys,1,1,1,0,0},
    {"info",infoCommand,-1,"lt",0,NULL,0,0,0,0,0},
    {"monitor",monitorCommand,1,"as",0,NULL,0,0,0,0,0},
    {"ttl",ttlCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"touch",touchCommand,-2,"rF",0,NULL,1,1,1,0,0},
    {"pttl",pttlCommand,2,"rF",0,NULL,1,1,1,0,0},
    {"persist",persistCommand,2,"wF",0,NULL,1,1,1,0,0},
    {"slaveof",slaveofCommand,3,"ast",0,NULL,0,0,0,0,0},
    {"role",roleCommand,1,"lst",0,NULL,0,0,0,0,0},
    {"debug",debugCommand,-1,"as",0,NULL,0,0,0,0,0},
    {"config",configCommand,-2,"lat",0,NULL,0,0,0,0,0},
    {"subscribe",subscribeCommand,-2,"pslt",0,NULL,0,0,0,0,0},
    {"unsubscribe",unsubscribeCommand,-1,"pslt",0,NULL,0,0,0,0,0},
    {"psubscribe",psubscribeCommand,-2,"pslt",0,NULL,0,0,0,0,0},
    {"punsubscribe",punsubscribeCommand,-1,"pslt",0,NULL,0,0,0,0,0},
    {"publish",publishCommand,3,"pltF",0,NULL,0,0,0,0,0},
    {"pubsub",pubsubCommand,-2,"pltR",0,NULL,0,0,0,0,0},
    {"watch",watchCommand,-2,"sF",0,NULL,1,-1,1,0,0},
    {"unwatch",unwatchCommand,1,"sF",0,NULL,0,0,0,0,0},
    {"cluster",clusterCommand,-2,"a",0,NULL,0,0,0,0,0},
    {"restore",restoreCommand,-4,"wm",0,NULL,1,1,1,0,0},
    {"restore-asking",restoreCommand,-4,"wmk",0,NULL,1,1,1,0,0},
    {"migrate",migrateCommand,-6,"w",0,migrateGetKeys,0,0,0,0,0},
    {"asking",askingCommand,1,"F",0,NULL,0,0,0,0,0},
    {"readonly",readonlyCommand,1,"F",0,NULL,0,0,0,0,0},
    {"readwrite",readwriteCommand,1,"F",0,NULL,0,0,0,0,0},
    {"dump",dumpCommand,2,"r",0,NULL,1,1,1,0,0},
    {"object",objectCommand,-2,"r",0,NULL,2,2,2,0,0},
    {"memory",memoryCommand,-2,"r",0,NULL,0,0,0,0,0},
    {"client",clientCommand,-2,"as",0,NULL,0,0,0,0,0},
    {"eval",evalCommand,-3,"s",0,evalGetKeys,0,0,0,0,0},
    {"evalsha",evalShaCommand,-3,"s",0,evalGetKeys,0,0,0,0,0},
    {"slowlog",slowlogCommand,-2,"a",0,NULL,0,0,0,0,0},
    {"script",scriptCommand,-2,"s",0,NULL,0,0,0,0,0},
    {"time",timeCommand,1,"RF",0,NULL,0,0,0,0,0},
    {"bitop",bitopCommand,-4,"wm",0,NULL,2,-1,1,0,0},
    {"bitcount",bitcountCommand,-2,"r",0,NULL,1,1,1,0,0},
    {"bitpos",bitposCommand,-3,"r",0,NULL,1,1,1,0,0},
    {"wait",waitCommand,3,"s",0,NULL,0,0,0,0,0},
    {"command",commandCommand,0,"lt",0,NULL,0,0,0,0,0},
    {"geoadd",geoaddCommand,-5,"wm",0,NULL,1,1,1,0,0},
    {"georadius",georadiusCommand,-6,"w",0,georadiusGetKeys,1,1,1,0,0},
    {"georadius_ro",georadiusroCommand,-6,"r",0,georadiusGetKeys,1,1,1,0,0},
    {"georadiusbymember",georadiusbymemberCommand,-5,"w",0,georadiusGetKeys,1,1,1,0,0},
    {"georadiusbymember_ro",georadiusbymemberroCommand,-5,"r",0,georadiusGetKeys,1,1,1,0,0},
    {"geohash",geohashCommand,-2,"r",0,NULL,1,1,1,0,0},
    {"geopos",geoposCommand,-2,"r",0,NULL,1,1,1,0,0},
    {"geodist",geodistCommand,-4,"r",0,NULL,1,1,1,0,0},
    {"pfselftest",pfselftestCommand,1,"a",0,NULL,0,0,0,0,0},
    {"pfadd",pfaddCommand,-2,"wmF",0,NULL,1,1,1,0,0},
    {"pfcount",pfcountCommand,-2,"r",0,NULL,1,-1,1,0,0},
    {"pfmerge",pfmergeCommand,-2,"wm",0,NULL,1,-1,1,0,0},
    {"pfdebug",pfdebugCommand,-3,"w",0,NULL,0,0,0,0,0},
    {"post",securityWarningCommand,-1,"lt",0,NULL,0,0,0,0,0},
    {"host:",securityWarningCommand,-1,"lt",0,NULL,0,0,0,0,0},
    {"latency",latencyCommand,-2,"aslt",0,NULL,0,0,0,0,0}
};
```

命令标志位

| 标志 | 解释                                                         |
| ---- | ------------------------------------------------------------ |
| w    | write command (may modify the key space).                    |
| r    | read command  (will never modify the key space).             |
| m    | may increase memory usage once called. Don't allow if out of memory. |
| a    | admin command, like SAVE or SHUTDOWN.                        |
| p    | Pub/Sub related command.                                     |
| f    | force replication of this command, regardless of server.dirty. |
| s    | command not allowed in scripts.                              |
| R    | random command. Command is not deterministic, that is, the same command   with the same arguments, with the same key space, may have different   results. For instance SPOP and RANDOMKEY are two random commands. |
| S    | Sort command output array if called from script, so that the output is deterministic. |
| l    | Allow command while loading the database.                    |
| t    | Allow command while a slave has stale data but is not allowed to server this data. Normally no command is accepted in this condition but just a few. |
| M    | Do not automatically propagate the command on MONITOR.       |
| k    | Perform an implicit ASKING for this command, so the command will be  accepted in cluster mode if the slot is marked as 'importing'. |
| F    | Fast command: O(1) or O(log(N)) command that should never delay its execution as long as the kernel scheduler is giving us time. Note that commands that may trigger a DEL as a side effect (like SET) are not fast commands. |


#### 00x03 string

---

##### 数据实现

```c
//object.c
#define OBJ_ENCODING_EMBSTR_SIZE_LIMIT 44
robj *createStringObject(const char *ptr, size_t len) {
    if (len <= OBJ_ENCODING_EMBSTR_SIZE_LIMIT)
        return createEmbeddedStringObject(ptr,len);
    else
        return createRawStringObject(ptr,len);
}
```

| encoding            | ptr                        |
| ------------------- | -------------------------- |
| OBJ_ENCODING_RAW    | 简单动态字符串             |
| OBJ_ENCODING_INT    | 整数值实现的字符串对象     |
| OBJ_ENCODING_EMBSTR | embstr编码的简单动态字符串 |

OBJ_ENCODING_RAW

调用`sdsnewlen()`创建简单动态字符串

```c
//object.c
robj *createRawStringObject(const char *ptr, size_t len) {
    return createObject(OBJ_STRING, sdsnewlen(ptr,len));
}
```

OBJ_ENCODING_EMBSTR

这种编码方式适用于长度小于44bytes的字符串，其与robj结构的内存空间是连续的，而OBJ_ENCODING_RAW中，两者的内存空间是分开的

sdshdr8的大小为3bytes，加上1个结束符共4bytes；redisObject的大小为16bytes<br>
redis使用jemalloc内存分配器时会被分配8，16，32，64等字节的内存<br>
一个空embstr的大小为4+16=20bytes，最多留给字符串信息的则为64-20=44bytes

不调用createObject，即不用指针指向分离的内存块，而是拼接到robj后

```c
//object.c
robj *createEmbeddedStringObject(const char *ptr, size_t len) {
    robj *o = zmalloc(sizeof(robj)+sizeof(struct sdshdr8)+len+1);
    struct sdshdr8 *sh = (void*)(o+1);

    o->type = OBJ_STRING;
    o->encoding = OBJ_ENCODING_EMBSTR;
    o->ptr = sh+1;
    o->refcount = 1;
    if (server.maxmemory_policy & MAXMEMORY_FLAG_LFU) {
        o->lru = (LFUGetTimeInMinutes()<<8) | LFU_INIT_VAL;
    } else {
        o->lru = LRU_CLOCK();
    }

    sh->len = len;
    sh->alloc = len;
    sh->flags = SDS_TYPE_8;
    if (ptr) {
        memcpy(sh->buf,ptr,len);
        sh->buf[len] = '\0';
    } else {
        memset(sh->buf,0,len+1);
    }
    return o;
}
```

OBJ_ENCODING_INT

仅在特殊形况下才会使用过这种编码，以整数保存字符串数据，仅限能用long类型表达的字符串

FromLongLong是其中一种实现，还有IntsetObject

```c
//object.c
robj *createStringObjectFromLongLong(long long value) {
    robj *o;
    if (value >= 0 && value < OBJ_SHARED_INTEGERS) {
        incrRefCount(shared.integers[value]);
        o = shared.integers[value];
    } else {
        if (value >= LONG_MIN && value <= LONG_MAX) {
            o = createObject(OBJ_STRING, NULL);
            o->encoding = OBJ_ENCODING_INT;
            o->ptr = (void*)((long)value);
        } else {
            o = createObject(OBJ_STRING,sdsfromlonglong(value));
        }
    }
    return o;
}
```

`shared.intergers`是全局变量，在server.c中定义，encoding为OBJ_ENCODING_INT

```c
for (j = 0; j < OBJ_SHARED_INTEGERS; j++) {
        shared.integers[j] =
            makeObjectShared(createObject(OBJ_STRING,(void*)(long)j));
        shared.integers[j]->encoding = OBJ_ENCODING_INT;
    }
```

决定编码类型的函数在object.c中

```c
/* Try to encode a string object in order to save space */
robj *tryObjectEncoding(robj *o) {	//client接受到的命令内容都会转换成robj对象
    long value;						//存放在[client].argv中，这里传入c.argv[2]
    sds s = o->ptr;
    size_t len;

    /* Make sure this is a string object, the only type we encode
     * in this function. Other types use encoded memory efficient
     * representations but are handled by the commands implementing
     * the type. */
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);

    /* We try some specialized encoding only for objects that are
     * RAW or EMBSTR encoded, in other words objects that are still
     * in represented by an actually array of chars. */
    if (!sdsEncodedObject(o)) return o;

    /* It's not safe to encode shared objects: shared objects can be shared
     * everywhere in the "object space" of Redis and may end in places where
     * they are not handled. We handle them only as values in the keyspace. */
     if (o->refcount > 1) return o;

    /* Check if we can represent this string as a long integer.
     * Note that we are sure that a string larger than 20 chars is not
     * representable as a 32 nor 64 bit integer. */
    len = sdslen(s);	//检查此字符串是否可当作数字
    if (len <= 20 && string2l(s,len,&value)) {
        /* This object is encodable as a long. Try to use a shared object.
         * Note that we avoid using shared integers when maxmemory is used
         * because every object needs to have a private LRU field for the LRU
         * algorithm to work well. */
        if ((server.maxmemory == 0 ||
            !(server.maxmemory_policy & MAXMEMORY_FLAG_NO_SHARED_INTEGERS)) &&
            value >= 0 &&
            value < OBJ_SHARED_INTEGERS)
        {
            decrRefCount(o);
            incrRefCount(shared.integers[value]);
            return shared.integers[value];
        } else {
            if (o->encoding == OBJ_ENCODING_RAW) sdsfree(o->ptr);
            o->encoding = OBJ_ENCODING_INT;
            o->ptr = (void*) value;
            return o;
        }
    }

    /* If the string is small and is still RAW encoded,
     * try the EMBSTR encoding which is more efficient.
     * In this representation the object and the SDS string are allocated
     * in the same chunk of memory to save space and cache misses. */
    if (len <= OBJ_ENCODING_EMBSTR_SIZE_LIMIT) {
        robj *emb;

        if (o->encoding == OBJ_ENCODING_EMBSTR) return o;
        emb = createEmbeddedStringObject(s,sdslen(s));
        decrRefCount(o);
        return emb;
    }

    /* We can't encode the object...
     *
     * Do the last try, and at least optimize the SDS string inside
     * the string object to require little space, in case there
     * is more than 10% of free space at the end of the SDS string.
     *
     * We do that only for relatively large strings as this branch
     * is only entered if the length of the string is greater than
     * OBJ_ENCODING_EMBSTR_SIZE_LIMIT. */
    if (o->encoding == OBJ_ENCODING_RAW &&
        sdsavail(s) > len/10)
    {
        o->ptr = sdsRemoveFreeSpace(o->ptr);
    }

    /* Return the original object. */
    return o;
}
```

##### 命令实现

`setGenericCommand()`函数是SET, SETEX, PSETEX, SETNX的最底层实现

```c
//t_string.c
#define OBJ_SET_NO_FLAGS 0
#define OBJ_SET_NX (1<<0)     /* Set if key not exists. */
#define OBJ_SET_XX (1<<1)     /* Set if key exists. */
#define OBJ_SET_EX (1<<2)     /* Set if time in seconds is given */
#define OBJ_SET_PX (1<<3)     /* Set if time in ms in given */

void setGenericCommand(client *c, int flags, robj *key, robj *val, robj *expire, int unit, robj *ok_reply, robj *abort_reply) {
    //ok_reply abort_reply为回复client的内容
    //flags可以为NX或XX的值，分别代表存在/不存在
    long long milliseconds = 0; /* initialized to avoid any harmness warning */
	//expire代表key的过期时间
    if (expire) {
        //取robj expire的值存到millisecondes里
        if (getLongLongFromObjectOrReply(c, expire, &milliseconds, NULL) != C_OK)
            return;
        //如果expire不大于0，则向c(client)发送错误信息
        if (milliseconds <= 0) {
            addReplyErrorFormat(c,"invalid expire time in %s",c->cmd->name);
            return;
        }
        //unit是expire的单位，有毫秒和秒，这里要统一转换成秒保存
        if (unit == UNIT_SECONDS) milliseconds *= 1000;
    }
	//NX(0001)但数据库中找到key 或 XX(0010)但未找到key
    //都会引发错误并向client返回abort_reply并结束函数
    //lookupKeyWrite将以写入为前提检测key的存在性
    //比lookupKeyRead函数多一行expireIfNeeded(db,key)
    if ((flags & OBJ_SET_NX && lookupKeyWrite(c->db,key) != NULL) ||
        (flags & OBJ_SET_XX && lookupKeyWrite(c->db,key) == NULL))
    {
        addReply(c, abort_reply ? abort_reply : shared.nullbulk);
        return;
    }
    setKey(c->db,key,val);	//保存键值对
    server.dirty++;			//增加数据库的dirty值，作为触发持久化的参考指标
    if (expire) setExpire(c,c->db,key,mstime()+milliseconds);//设置过期时间
    notifyKeyspaceEvent(NOTIFY_STRING,"set",key,c->db->id);//发送set事件通知
    if (expire) notifyKeyspaceEvent(NOTIFY_GENERIC,
        "expire",key,c->db->id);//发送expire事件通知
    addReply(c, ok_reply ? ok_reply : shared.ok);//向client发送ok_reply
}
```

getGenericCommand()是GET,GETSET命令的底层实现

```c
int getGenericCommand(client *c) {
    robj *o;

    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.nullbulk)) == NULL)
        return C_OK;

    if (o->type != OBJ_STRING) {	//检测找到的value是否为string类型
        addReply(c,shared.wrongtypeerr);
        return C_ERR;
    } else {
        addReplyBulk(c,o);
        return C_OK;
    }
}
```

Incr/Decr

操作string类型整数

```c
void incrDecrCommand(client *c, long long incr) {
    //incr : 1 -> incr | -1 -> decr | other -> value += incr
    long long value, oldvalue;
    robj *o, *new;

    o = lookupKeyWrite(c->db,c->argv[1]);	//以写操作获取value对象
    if (o != NULL && checkType(c,o,OBJ_STRING)) return;
    if (getLongLongFromObjectOrReply(c,o,&value,NULL) != C_OK) return;
	//读取的同检测字符串是否可以被读取为数字
    
    oldvalue = value;	//备份原值
    //检测更新后数值是否超出范围
    if ((incr < 0 && oldvalue < 0 && incr < (LLONG_MIN-oldvalue)) ||
        (incr > 0 && oldvalue > 0 && incr > (LLONG_MAX-oldvalue))) {
        addReplyError(c,"increment or decrement would overflow");
        return;
    }
    value += incr;
	
    //原对象 
    //单引用，整数编码，不在共享范围，不超过long类型范围
    if (o && o->refcount == 1 && o->encoding == OBJ_ENCODING_INT &&
        (value < 0 || value >= OBJ_SHARED_INTEGERS) &&
        value >= LONG_MIN && value <= LONG_MAX)
    {
        new = o;
        o->ptr = (void*)((long)value);
    } else {	//不满足则创建新字符串对象
        new = createStringObjectFromLongLong(value);
        if (o) {
            dbOverwrite(c->db,c->argv[1],new);
        } else {
            dbAdd(c->db,c->argv[1],new);
        }
    }
    signalModifiedKey(c->db,c->argv[1]); //数据库中的键被修改时会发送此信号
    notifyKeyspaceEvent(NOTIFY_STRING,"incrby",c->argv[1],c->db->id);
    //发送incrby事件通知
    server.dirty++;	//设置脏键
    
    //向client发送消息
    addReply(c,shared.colon);
    addReply(c,new);
    addReply(c,shared.crlf);
}
```

append实现

在string后拼接

拼接时有可能会改变字符串的编码类型

如 "123" + "abc"，"123"可执行Incr等命令，而"123abc"不行

实际上所有append拼接后的string编码类型都会强制变为

```c
void appendCommand(client *c) {
    size_t totlen;
    robj *o, *append;

    o = lookupKeyWrite(c->db,c->argv[1]);	//以写操作模式获取对象
    if (o == NULL) {	//key不存在时，效果等同于set
        /* Create the key */
        c->argv[2] = tryObjectEncoding(c->argv[2]);	//优化编码
        dbAdd(c->db,c->argv[1],c->argv[2]);	//存储键值对
        incrRefCount(c->argv[2]);	//增加引用计数
        totlen = stringObjectLen(c->argv[2]);	//value的长度
    } else {
        /* Key exists, check type */
        if (checkType(c,o,OBJ_STRING))	//检测是否为string类型
            return;

        /* "append" is an argument, so always an sds */
        append = c->argv[2];	//要追加的内容
        totlen = stringObjectLen(o)+sdslen(append->ptr);	//追加后的长度
        if (checkStringLength(c,totlen) != C_OK)	
            //确保追加后的字符串长度不超出范围
            return;

        /* Append the value */
        //这个函数中强行将目的字符串的encoding转为了OBJ_ENCODING_RAW
        //那么问题来了，"123" append "4" -> "1234"这种为什么仍能够使用Incr/Decr?
        //跟进看下面incrDecrCommand-getLongLongFromObjectOrReply-getLongLongFromObject的代码
        o = dbUnshareStringValue(c->db,c->argv[1],o);
        o->ptr = sdscatlen(o->ptr,append->ptr,sdslen(append->ptr));
        totlen = sdslen(o->ptr);
    }
    signalModifiedKey(c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_STRING,"append",c->argv[1],c->db->id);
    server.dirty++;
    addReplyLongLong(c,totlen);
}

//db.c
robj *dbUnshareStringValue(redisDb *db, robj *key, robj *o) {
    serverAssert(o->type == OBJ_STRING);
    if (o->refcount != 1 || o->encoding != OBJ_ENCODING_RAW) {
        robj *decoded = getDecodedObject(o);
        o = createRawStringObject(decoded->ptr, sdslen(decoded->ptr));
        decrRefCount(decoded);
        dbOverwrite(db,key,o);
    }
    return o;
}

//object.c
int getLongLongFromObject(robj *o, long long *target) {
    long long value;

    if (o == NULL) {
        value = 0;
    } else {
        serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
        if (sdsEncodedObject(o)) {	
            //应该是在这里 string2ll() != 0  所以返回了C_OK
            if (string2ll(o->ptr,sdslen(o->ptr),&value) == 0) return C_ERR;
        } else if (o->encoding == OBJ_ENCODING_INT) {
            value = (long)o->ptr;
        } else {
            serverPanic("Unknown string encoding");
        }
    }
    if (target) *target = value;
    return C_OK;
}
```



#### 00x04 list

---

##### 数据实现

| encoding               | ptr      |
| ---------------------- | -------- |
| OBJ_ENCODING_QUICKLIST | 快速列表 |
| OBJ_ENCODING_ZIPLIST   | 压缩列表 |

```c
//object.c
robj *createQuicklistObject(void) {
    quicklist *l = quicklistCreate(); //in quicklist.c
    robj *o = createObject(OBJ_LIST,l);
    o->encoding = OBJ_ENCODING_QUICKLIST;
    return o;
}

robj *createZiplistObject(void) {
    unsigned char *zl = ziplistNew(); //in ziplist.c
    robj *o = createObject(OBJ_LIST,zl);
    o->encoding = OBJ_ENCODING_ZIPLIST;
    return o;
}
```

实际上quicklist本身就是以ziplist为基础实现的双向链表(每个节点都包含一个ziplist)，而且list类型的encoding也只有`OBJ_ENCODING_QUICKLIST`

> 但quicklist内部的robj，encoding为`OBJ_ENCODING_ZIPLIST`，所以底层实现中包括压缩列表

在t_list.c中定义了list结构的一系列操作，作为命令的基础

```c
//list结构PUSH操作
void listTypePush(robj *subject, robj *value, int where); 
//POP
robj *listTypePop(robj *subject, int where); 
//返回entry节点个数
unsigned long listTypeLength(robj *subject); 
//初始化list迭代器到一个指定下标
listTypeIterator *listTypeInitIterator(robj *subject, long index, unsigned char direction);
//释放迭代器空间
void listTypeReleaseIterator(listTypeIterator *li); 
//读取迭代器当前指向的entry到listTypeEntry中
int listTypeNext(listTypeIterator *li, listTypeEntry *entry);
//根据entry返回value对象
robj *listTypeGet(listTypeEntry *entry); 
//插入value到where的位置
void listTypeInsert(listTypeEntry *entry, robj *value, int where); 
//判断当前entry与o的内容是否相等
int listTypeEqual(listTypeEntry *entry, robj *o); 
//删除迭代器当前指向的节点
void listTypeDelete(listTypeIterator *iter, listTypeEntry *entry); 
//转换ZIPLIST编码类型为quicklist类型，encoding变为OBJ_ENCODING_QUICKLIST
void listTypeConvert(robj *subject, int enc);
```

listTypeIterator内包含的是quicklist的迭代器与list的信息

listTypeEntry则包含了quicklistEntry

关于entry，list与quicklist的entry实际上是ziplist的entry，在存储空间中为连续的内存块，在修改这个内存块之前要先将其信息读出来。在ziplist中这个结构为zlEntry，这里的quicklistEntry与ziplist功能相同，只不过为了适应quicklist而定义了新的结构。

```c
typedef struct {
    robj *subject;	//当前指向的对象
    unsigned char encoding;
    unsigned char direction; //迭代器方向
    quicklistIter *iter;	
} listTypeIterator;

typedef struct {
    listTypeIterator *li;
    quicklistEntry entry; /* Entry in quicklist */
} listTypeEntry;
```

比较难懂的是quicklistEntry结构中的zi指针

```c
typedef struct quicklistEntry {
    const quicklist *quicklist;
    quicklistNode *node;		//所属的节点(一个节点包含一条zl的多个entry)
    unsigned char *zi;			//???
    unsigned char *value;		//读出的值(字符串)
    long long longval;			//值(整数)
    unsigned int sz;		//字节大小
    int offset;				//相对ziplist的偏移量
} quicklistEntry;

int listTypeEqual(listTypeEntry *entry, robj *o) {
    if (entry->li->encoding == OBJ_ENCODING_QUICKLIST) {
        //确保o->ptr的encoding是string类型的RAW/EMBSTR
        //从这里可以推断出entry->entrt.zi也应当是相同的类型
        //所以quicklistEntry中的zi应该指向ziplist中的entry内存块而不是ziplist
        serverAssertWithInfo(NULL,o,sdsEncodedObject(o));
        return quicklistCompare(entry->entry.zi,o->ptr,sdslen(o->ptr));
    } else {
        serverPanic("Unknown list encoding");
    }
}
```

##### 命令实现

> list与其他类型的命令不同的是，`B-`(blocking)类命令如BLPOP是阻塞的，其他命令为非阻塞执行

之前给出的一系列函数是直接对quicklist操作，是list底层操作的实现，而不是list命令底层操作的实现

在命令中要考虑到原子操作、事务、脏键等必要元素

push类命令底层实现，包括LPUSH，RPUSH

```c
//where表示push的位置
void pushGenericCommand(client *c, int where) {
    int j, pushed = 0;
    robj *lobj = lookupKeyWrite(c->db,c->argv[1]); //以写操作获取list对象
	
    //obj存在但不是list，向客户端发送错误信息并结束
    if (lobj && lobj->type != OBJ_LIST) {
        addReply(c,shared.wrongtypeerr);
        return;
    }
	
    //从c->argv中第一个'value'开始遍历
    for (j = 2; j < c->argc; j++) {
        if (!lobj) {//不存在list时创建list对象
            lobj = createQuicklistObject();
            //设置list-quicklist中ziplist的最大长度与压缩
            quicklistSetOptions(lobj->ptr, server.list_max_ziplist_size,
                                server.list_compress_depth);
            //向数据库中存入键值对(列表名):(新列表对象)
            dbAdd(c->db,c->argv[1],lobj);
        }
        //调用listType基本操作，插入对象，where直接传入由listTypePush处理
        listTypePush(lobj,c->argv[j],where);
        //记录本次执行已存入数
        pushed++;
    }
    //发送消息、信号、事件
    addReplyLongLong(c, (lobj ? listTypeLength(lobj) : 0));
    if (pushed) {
        //确认事件类型
        char *event = (where == LIST_HEAD) ? "lpush" : "rpush";

        signalModifiedKey(c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_LIST,event,c->argv[1],c->db->id);
    }
    //更新脏键
    server.dirty += pushed;
}
```

`pushxGenericCommand()`与`pushGenericCommand()`不同，只对已存在的list有效，不会创建新list

```c
void pushxGenericCommand(client *c, int where) {
    int j, pushed = 0;
    robj *subject;
	
    //不存在或类型不同就向客户端发送错误信息
    if ((subject = lookupKeyWriteOrReply(c,c->argv[1],shared.czero)) == NULL ||
        checkType(c,subject,OBJ_LIST)) return;

    for (j = 2; j < c->argc; j++) {
        listTypePush(subject,c->argv[j],where);
        pushed++;
    }

    addReplyLongLong(c,listTypeLength(subject));

    if (pushed) {
        char *event = (where == LIST_HEAD) ? "lpush" : "rpush";
        signalModifiedKey(c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_LIST,event,c->argv[1],c->db->id);
    }
    server.dirty += pushed;
}
```

非阻塞POP底层实现

```c
void popGenericCommand(client *c, int where) {
    //以写操作获取对象，与lookupKeyWrite不同的是，
    //lookupKeyWriteOrReply检测到key对应对象不存在时会向客户端发送消息
    robj *o = lookupKeyWriteOrReply(c,c->argv[1],shared.nullbulk);	
    if (o == NULL || checkType(c,o,OBJ_LIST)) return;
	
    //按照where弹出一个值
    robj *value = listTypePop(o,where);
    if (value == NULL) {
        //值为空则发送‘空’消息
        addReply(c,shared.nullbulk);
    } else {
        char *event = (where == LIST_HEAD) ? "lpop" : "rpop";

        addReplyBulk(c,value);
        decrRefCount(value);	//引用计数-1
        //发送通知
        notifyKeyspaceEvent(NOTIFY_LIST,event,c->argv[1],c->db->id);
        //列表为空时删除list的键值对
        if (listTypeLength(o) == 0) {
            notifyKeyspaceEvent(NOTIFY_GENERIC,"del",
                                c->argv[1],c->db->id);
            dbDelete(c->db,c->argv[1]);
        }
        //发送键被改动的信号
        signalModifiedKey(c->db,c->argv[1]);
        server.dirty++;	//更新脏键
    }
}
```

INSERT命令则是单独用一个函数来实现的

```c
void linsertCommand(client *c) {
    int where;
    robj *subject;
    listTypeIterator *iter;
    listTypeEntry entry;
    int inserted = 0;
    
	//命令格式 LINSERT key BEFORE|AFTER pivot value
    //如 LINSERT namelist BEFORE "Alice" "Bob" 在"Alice"前方置入"Bob"
    if (strcasecmp(c->argv[2]->ptr,"after") == 0) {
        where = LIST_TAIL;
    } else if (strcasecmp(c->argv[2]->ptr,"before") == 0) {
        where = LIST_HEAD;
    } else {
        //发送消息，命令格式错误
        addReply(c,shared.syntaxerr);
        return;
    }
    
	//与PUSHX类型，同样只对已有列表有效
    if ((subject = lookupKeyWriteOrReply(c,c->argv[1],shared.czero)) == NULL ||
        checkType(c,subject,OBJ_LIST)) return;

    /* Seek pivot from head to tail */
    //创建一个subject(当前操作列表)的迭代器
    iter = listTypeInitIterator(subject,0,LIST_TAIL);
    while (listTypeNext(iter,&entry)) {
        //遍历查找基准值(如上面示例中的"Alice")位置
        if (listTypeEqual(&entry,c->argv[3])) {
            //在基准位置前/后插入元素
            listTypeInsert(&entry,c->argv[4],where);
            inserted = 1;//已插入
            break;
        }
    }
    listTypeReleaseIterator(iter);
	
    //插入成功
    if (inserted) {
        signalModifiedKey(c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_LIST,"linsert",
                            c->argv[1],c->db->id);
        server.dirty++;
    //插入失败
    } else {
        /* Notify client of a failed insert */
        addReply(c,shared.cnegone);
        return;
    }

    addReplyLongLong(c,listTypeLength(subject));
}
```

阻塞POP底层实现(BRPOPLPUSH是单独实现的)

> 阻塞命令包括BLPOP，BRPOP和BRPOPLPUSH

在list为空时，调用此命令的client会处于阻塞状态

```c
void blockingPopGenericCommand(client *c, int where) {
    robj *o;
    mstime_t timeout;
    int j;
	
    //以秒为单位获取超时时长存储在timeout中
    if (getTimeoutFromObjectOrReply(c,c->argv[c->argc-1],&timeout,UNIT_SECONDS)
        != C_OK) return;

    for (j = 1; j < c->argc-1; j++) {
        o = lookupKeyWrite(c->db,c->argv[j]);
        if (o != NULL) {
            if (o->type != OBJ_LIST) {
                addReply(c,shared.wrongtypeerr);
                return;
            } else {
                if (listTypeLength(o) != 0) {
                    /* Non empty list, this is like a non normal [LR]POP. */
                    char *event = (where == LIST_HEAD) ? "lpop" : "rpop";
                    robj *value = listTypePop(o,where);
                    serverAssert(value != NULL);

                    addReplyMultiBulkLen(c,2);
                    addReplyBulk(c,c->argv[j]);
                    addReplyBulk(c,value);
                    decrRefCount(value);
                    notifyKeyspaceEvent(NOTIFY_LIST,event,
                                        c->argv[j],c->db->id);
                    if (listTypeLength(o) == 0) {
                        dbDelete(c->db,c->argv[j]);
                        notifyKeyspaceEvent(NOTIFY_GENERIC,"del",
                                            c->argv[j],c->db->id);
                    }
                    signalModifiedKey(c->db,c->argv[j]);
                    server.dirty++;

                    /* Replicate it as an [LR]POP instead of B[LR]POP. */
                    rewriteClientCommandVector(c,2,
                        (where == LIST_HEAD) ? shared.lpop : shared.rpop,
                        c->argv[j]);
                    return;
                }
            }
        }
    }
	//如果这条命令在一个事务中，则向客户端发送一个空回复
    /* If we are inside a MULTI/EXEC and the list is empty the only thing
     * we can do is treating it as a timeout (even with timeout 0). */
    if (c->flags & CLIENT_MULTI) {
        addReply(c,shared.nullmultibulk);
        return;
    }
    
    //前面的操作都属于非阻塞操作，真正实现阻塞的是下面的函数
	//如果参数中的所有键在list中都不存在则阻塞
    /* If the list is empty or the key does not exists we must block */
    //c->argv+1 修正数组首地址到第一个key处
    //c->argc-2 key的数量
    blockForKeys(c, c->argv + 1, c->argc - 2, timeout, NULL);
}

//target是push的元素，用于BRPOPLPUSH
void blockForKeys(client *c, robj **keys, int numkeys, mstime_t timeout, robj *target) {
    dictEntry *de;
    list *l;
    int j;
	
    //因为是客户端为主体的阻塞操作，可以直接设置到客户端的参数中
    c->bpop.timeout = timeout;
    c->bpop.target = target;
	
    //操作期间增加target的引用计数
    if (target != NULL) incrRefCount(target);
	
    //遍历所有键
    for (j = 0; j < numkeys; j++) {
        /* If the key already exists in the dict ignore it. */
        //bpop.keys用于记录所有造成client阻塞的键，是一个dict结构
        if (dictAdd(c->bpop.keys,keys[j],NULL) != DICT_OK) continue;
        incrRefCount(keys[j]);
        //之前在append命令中提到过，c->argv不是实际的命令行内容，而是处理成了robj类型
        //所以才有引用计数这一属性

        /* And in the other "side", to map keys -> clients */
        //c->db->blocking_keys是一个dict，
        //其中的key为造成client阻塞的键，value为保存着所有被该键阻塞的client的链表
        de = dictFind(c->db->blocking_keys,keys[j]);//寻找这个键对应的链表
        if (de == NULL) {
            //没有找到则创建新的链表，并将其加入bilocking_keys
            int retval;
            /* For every key we take a list of clients blocked for it */
            l = listCreate();
            retval = dictAdd(c->db->blocking_keys,keys[j],l);
            incrRefCount(keys[j]);
            serverAssertWithInfo(c,keys[j],retval == DICT_OK);
        } else {
            //有则获取这个链表的引用
            l = dictGetVal(de);
        }
        //向这个链表加入新的阻塞client记录
        listAddNodeTail(l,c);
    }
    //阻塞client
    //BLOCK_LIST = 1 表示在阻塞列表中
    blockClient(c,BLOCKED_LIST);
}

//blocked.c
//修改阻塞状态与标志
void blockClient(client *c, int btype) {
    c->flags |= CLIENT_BLOCKED;
    c->btype = btype;
    server.bpop_blocked_clients++;
}

//c->bpop 是 blockingStats结构，定义在server.h中
typedef struct blockingState {
    /* Generic fields. */
    mstime_t timeout;       /* Blocking operation timeout. If UNIX current time
                             * is > timeout then the operation timed out. */

    /* BLOCKED_LIST */
    dict *keys;             /* The keys we are waiting to terminate a blocking
                             * operation such as BLPOP. Otherwise NULL. */
    robj *target;           /* The key that should receive the element,
                             * for BRPOPLPUSH. */

    /* BLOCKED_WAIT */
    int numreplicas;        /* Number of replicas we are waiting for ACK. */
    long long reploffset;   /* Replication offset to reach. */

    /* BLOCKED_MODULE */
    void *module_blocked_handle; /* RedisModuleBlockedClient structure.
                                    which is opaque for the Redis core, only
                                    handled in module.c. */
} blockingState;

//c->db 是 redisDb结构，定义在server.h中
typedef struct redisDb {
    dict *dict;                 /* The keyspace for this DB */
    dict *expires;              /* Timeout of keys with a timeout set */
    dict *blocking_keys;        /* Keys with clients waiting for data (BLPOP)*/
    dict *ready_keys;           /* Blocked keys that received a PUSH */
    dict *watched_keys;         /* WATCHED keys for MULTI/EXEC CAS */
    int id;                     /* Database ID */
    long long avg_ttl;          /* Average TTL, just for stats */
} redisDb;
```

redis中实现的阻塞是修改客户端的状态，而解阻塞的正常触发一般有两种

一种根据timeout等待超时，另一种是另一个客户端对记录blocking的key(list对应的key)的任意一个执行LPUSH或RPUSH命令时

在server.c的processCommand(执行命令)函数的最后，根据server.ready_keys是否有元素来调用t_list.c中的handleClientsBlockedOnLists(void)函数，解除client的阻塞状态

#### 00x05 hash

---

##### 数据实现

默认创建对象为ziplist结构，dict类型的hash对象是在键值对大小(ziplist节点大小或键值对数量(ziplist节点数)达到配置中限制的值后通过转换得到的

redis.conf

>hash-max-ziplist-value 64 <br>hash-max-ziplist-entries 512

| encoding             | ptr      |
| -------------------- | -------- |
| OBJ_ENCODING_HT      | 字典     |
| OBJ_ENCODING_ZIPLIST | 压缩列表 |

```c
robj *createHashObject(void) {
    unsigned char *zl = ziplistNew(); //in ziplist.c
    robj *o = createObject(OBJ_HASH, zl);
    o->encoding = OBJ_ENCODING_ZIPLIST;
    return o;
}
```

类似list类型，hash也对基本操作做了一层封装

```c
//在必要的情况下转换encoding为HT(函数内有检测)
void hashTypeTryConversion(robj *subject, robj **argv, int start, int end);
//从encoding为ziplist的hash对象中获取value信息，保存到vstr,vlen,vll中
int hashTypeGetFromZiplist(robj *o, sds field,unsigned char **vstr,unsigned int *vlen,long long *vll)
//从encoding为HT的hash对象中获取value对象，返回简单动态字符串
sds hashTypeGetFromHashTable(robj *o, sds field)
//判断encoding，调用上面两个函数，获取value信息
int hashTypeGetValue(robj *o, sds field, unsigned char **vstr, unsigned int *vlen, long long *vll)
//根据在GetValue基础上用value信息创建value对象
robj *hashTypeGetValueObject(robj *o, sds field)
//value长度，0为不存在
size_t hashTypeGetValueLength(robj *o, sds field)
//判断hash对象中key是否存在
int hashTypeExists(robj *o, robj *key);
//设置k-v
int hashTypeSet(robj *o, robj *key, robj *value);
//删除k-v 
int hashTypeDelete(robj *o, robj *key);
//返回键值对个数
unsigned long hashTypeLength(robj *o);
//返回一个初始化的hash类型迭代器
hashTypeIterator *hashTypeInitIterator(robj *subject);
//释放迭代器空间
void hashTypeReleaseIterator(hashTypeIterator *hi);
//迭代器指向下个节点
int hashTypeNext(hashTypeIterator *hi);
//类似hashTypeGetFromZiplist，这个是适用于迭代器的
void hashTypeCurrentFromZiplist(hashTypeIterator *hi, int what, unsigned char **vstr, unsigned int *vlen, long long *vll);
//同上，类似hashTypeGetFromHashTable
void hashTypeCurrentFromHashTable(hashTypeIterator *hi, int what, robj **dst);
//类似hashTypeGetValueObject
robj *hashTypeCurrentObject(hashTypeIterator *hi, int what);
//以sds类型返回当前元素
sds hashTypeCurrentObjectNewSds(hashTypeIterator *hi, int what)
//以写操作查找key对应的hash对象，如果不存在则创建
robj *hashTypeLookupWriteOrCreate(client *c, robj *key);
//转换encoding为ziplist
void hashTypeConvertZiplist(robj *o, int enc)
//转换一个hashobj的encoding，enc为新编码类型
void hashTypeConvert(robj *o, int enc);
```

##### 命令实现


HSET,HGET,HINCRBY,HLEN等命令基本都是执行hash对象的基本操作加上信号，反馈与记录

HINCRBYFLOAT实现

```c
void hincrbyfloatCommand(client *c) {
    long double value, incr;
    long long ll;
    robj *o;
    sds new;
    unsigned char *vstr;
    unsigned int vlen;
	
    //从命令获取长双浮点数类型的增量存入incr
    if (getLongDoubleFromObjectOrReply(c,c->argv[3],&incr,NULL) != C_OK) return;
    //写操作取出hash对象，或创建新hash对象
    if ((o = hashTypeLookupWriteOrCreate(c,c->argv[1])) == NULL) return;
    //读取目标对象信息，并检查是否为浮点数类型
    if (hashTypeGetValue(o,c->argv[2]->ptr,&vstr,&vlen,&ll) == C_OK) {
        if (vstr) {
            if (string2ld((char*)vstr,vlen,&value) == 0) {
                addReplyError(c,"hash value is not a float");
                return;
            }
        } else {
            value = (long double)ll;
        }
    } else {//没有这一对象则默认值为0
        value = 0;
    }
	
    //计算新值
    value += incr;
    char buf[256];
    int len = ld2string(buf,sizeof(buf),value,1); //浮点数转字符数组
    new = sdsnewlen(buf,len);	//字符串转sds
    hashTypeSet(o,c->argv[2]->ptr,new,HASH_SET_TAKE_VALUE); //更新key的对象
    addReplyBulkCBuffer(c,buf,len); //将新值返回给客户端
    signalModifiedKey(c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_HASH,"hincrbyfloat",c->argv[1],c->db->id);
    server.dirty++;

    /* Always replicate HINCRBYFLOAT as an HSET command with the final value
     * in order to make sure that differences in float pricision or formatting
     * will not create differences in replicas or after an AOF restart. */
    //修改当前命令为HSET，避免AOF恢复时不同浮点精度造成的误差
    //不会执行，只在记录中代替
    robj *aux, *newobj;
    aux = createStringObject("HSET",4);
    newobj = createRawStringObject(buf,len);
    rewriteClientCommandArgument(c,0,aux);
    decrRefCount(aux);
    rewriteClientCommandArgument(c,3,newobj);
    decrRefCount(newobj);
}
```

HKEYS，HCALS，HGETALL底层实现

```c
//server.h
#define OBJ_HASH_KEY 1
#define OBJ_HASH_VALUE 2
//t_hash.h
void genericHgetallCommand(client *c, int flags) {
    robj *o;
    hashTypeIterator *hi;
    int multiplier = 0;
    int length, count = 0;
	
    //读操作取，检查类型
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.emptymultibulk)) == NULL
        || checkType(c,o,OBJ_HASH)) return;
	
    //根据flag判断取键值对中的key还是value还是都取
    if (flags & OBJ_HASH_KEY) multiplier++;
    if (flags & OBJ_HASH_VALUE) multiplier++;
    
	//取出对象的个数(包括key和value)
    length = hashTypeLength(o) * multiplier;
    addReplyMultiBulkLen(c, length);//发送个数给客户端

    hi = hashTypeInitIterator(o);
    //迭代所有节点根据情况取键值
    while (hashTypeNext(hi) != C_ERR) {
        if (flags & OBJ_HASH_KEY) {
            addHashIteratorCursorToReply(c, hi, OBJ_HASH_KEY);
            count++;
            
        }
        if (flags & OBJ_HASH_VALUE) {
            addHashIteratorCursorToReply(c, hi, OBJ_HASH_VALUE);
            count++;
        }
    }

    hashTypeReleaseIterator(hi);
    serverAssert(count == length);
}
```

HSCAN

```c
void hscanCommand(client *c) {
    robj *o;
    unsigned long cursor;
	//获取scan命令的curser
    if (parseScanCursorOrReply(c,c->argv[2],&cursor) == C_ERR) return;
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.emptyscan)) == NULL ||
        checkType(c,o,OBJ_HASH)) return;
    //调用server.c中的函数，时所有scan类命令的底层实现
    //parseScanCursorOrReply也定义在server.c中
    scanGenericCommand(c,o,cursor);
}
```


#### 00x06 set

---

set为不重复无序集合

##### 数据实现

| encoding            | ptr      |
| ------------------- | -------- |
| OBJ_ENCODING_HT     | 字典     |
| OBJ_ENCODING_INTSET | 整数集合 |

```c
robj *createSetObject(void) {
    dict *d = dictCreate(&setDictType,NULL); //in dict.c
    robj *o = createObject(OBJ_SET,d);
    o->encoding = OBJ_ENCODING_HT;
    return o;
}

robj *createIntsetObject(void) {
    intset *is = intsetNew(); //in intset.c
    robj *o = createObject(OBJ_SET,is);
    o->encoding = OBJ_ENCODING_INTSET;
    return o;
}
```

如果集合中的对象都为整数，则encoding默认为OBJ_ENCODING_INTSET，由整数集合实现。

转换为OBJ_ENCODING_HT的条件为(满足其一)

- 整数集合内元素超过redis.conf中的set-max-intset-entries
- 插入了字符串对象

集合类型定义的基本操作

```c
//创建set，并带有value这个元素，元素为0的set是不能存在的
robj *setTypeCreate(robj *value);
//向subject中添加value，成功返回1，已经存在返回0
int setTypeAdd(robj *subject, robj *value);
//删除值为value的元素
int setTypeRemove(robj *subject, robj *value);
//检查否存在值为value的元素
int setTypeIsMember(robj *subject, robj *value);
//创建并初始化set类型的迭代器
setTypeIterator *setTypeInitIterator(robj *subject);
//释放空间
void setTypeReleaseIterator(setTypeIterator *si);
//将迭代器当前指向的元素保存在objele或llele中，迭代完毕返回-1
//返回的对象的引用技术不增加，支持 读时共享写时复制
int setTypeNext(setTypeIterator *si, robj **objele, int64_t *llele);
//返回迭代器当前指向的元素的地址，需要手动释放返回的对象
robj *setTypeNextObject(setTypeIterator *si);
//随机取出set中一个对象，保存在参数中
int setTypeRandomElement(robj *setobj, robj **objele, int64_t *llele);
unsigned long setTypeRandomElements(robj *set, unsigned long count, robj *aux_set);
//set元素数量
unsigned long setTypeSize(robj *subject);
//OBJ_ENCODING_INTSET转换为enc的类型
//实际上enc只有为OBJ_ENCODING_HT时函数才有效，否则会调用serverPanic()报错，也就是说只能intset转hashtable
void setTypeConvert(robj *subject, int enc);
```

##### 命令实现

SADD，SREM，SMOVE，SISMUMBER，SCARD等单一命令在set基本操作基础上实现并不复杂，这里以SMOVE为例

```c
//将一个set的元素移动到另一个set
//移动一个目的set已存在的元素，目的set不变，源set删除此元素
void smoveCommand(client *c) {
    robj *srcset, *dstset, *ele;	//根据命令结构结构，argv[0]是命令名，不属于参数
    srcset = lookupKeyWrite(c->db,c->argv[1]);	//命令中第一个参数为源set的key
    dstset = lookupKeyWrite(c->db,c->argv[2]);	//第二个参数为目的set的key
    ele = c->argv[3];					//第三个参数为要移动的元素的value

    /* If the source key does not exist return 0 */
    if (srcset == NULL) {	//检查源set是否存在
        addReply(c,shared.czero);
        return;
    }

    /* If the source key has the wrong type, or the destination key
     * is set and has the wrong type, return with an error. */
    //源set数据类型错误 或 目的set存在且类型错误 时 结束函数
    if (checkType(c,srcset,OBJ_SET) ||	
        (dstset && checkType(c,dstset,OBJ_SET))) return;

    /* If srcset and dstset are equal, SMOVE is a no-op */
    if (srcset == dstset) {	//检查两set是否是同一个
        addReply(c,setTypeIsMember(srcset,ele->ptr) ?
            shared.cone : shared.czero);
        return;
    }

    /* If the element cannot be removed from the src set, return 0. */
    if (!setTypeRemove(srcset,ele->ptr)) {	//尝试删除元素
        addReply(c,shared.czero);
        return;
    }
    notifyKeyspaceEvent(NOTIFY_SET,"srem",c->argv[1],c->db->id);
	
    /* Remove the src set from the database when empty */
    if (setTypeSize(srcset) == 0) {	//删除后set为空时直接从数据库清除
        dbDelete(c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_GENERIC,"del",c->argv[1],c->db->id);
    }

    /* Create the destination set when it doesn't exist */
    if (!dstset) {	//如果目的set不存在时则创建新的set，并直接插入元素
        dstset = setTypeCreate(ele->ptr);
        dbAdd(c->db,c->argv[2],dstset);
    }

    signalModifiedKey(c->db,c->argv[1]);
    signalModifiedKey(c->db,c->argv[2]);
    server.dirty++;

    /* An extra key has changed when ele was successfully added to dstset */
    if (setTypeAdd(dstset,ele->ptr)) {//重复插入并不影响set
        server.dirty++;
        notifyKeyspaceEvent(NOTIFY_SET,"sadd",c->argv[2],c->db->id);
    }
    addReply(c,shared.cone);
}
```

取set随机元素SRANDMEMBER底层实现

```c
//SRANDMEMBER key [count] 从key对应的set取出随机元素，取出元素数count可选，默认为1个
//负数表示可出现重复元素
void srandmemberWithCountCommand(client *c) {
    long l;
    unsigned long count, size;
    int uniq = 1;	//标记返回元素不重复
    robj *set;
    sds ele;
    int64_t llele;
    int encoding;

    dict *d;
	//记录要弹出的元素个数
    if (getLongFromObjectOrReply(c,c->argv[2],&l,NULL) != C_OK) return;
    if (l >= 0) {
        count = (unsigned long) l;
    } else { //为负数时转正并取消元素不重复的标志
        /* A negative count means: return the same elements multiple times
         * (i.e. don't remove the extracted element after every extraction). */
        count = -l;
        uniq = 0;	
    }
	
    //读操作取set
    if ((set = lookupKeyReadOrReply(c,c->argv[1],shared.emptymultibulk))
        == NULL || checkType(c,set,OBJ_SET)) return;
    size = setTypeSize(set);
	
    //取0个元素，直接发送empty信息，返回
    /* If count is zero, serve it ASAP to avoid special cases later. */
    if (count == 0) {
        addReply(c,shared.emptymultibulk);
        return;
    }

    /* CASE 1: The count was negative, so the extraction method is just:
     * "return N random elements" sampling the whole set every time.
     * This case is trivial and can be served without auxiliary data
     * structures. */
    //1. 可取重复元素
    if (!uniq) {
        addReplyMultiBulkLen(c,count);	//向客户端发送弹出个数信息
        while(count--) {
            //从set中随机取出元素，并获取encoding类型
            encoding = setTypeRandomElement(set,&ele,&llele);
            //向客户端发送信息
            if (encoding == OBJ_ENCODING_INTSET) {
                addReplyBulkLongLong(c,llele);
            } else {
                addReplyBulkCBuffer(c,ele,sdslen(ele));
            }
        }
        return;
    }

    /* CASE 2:
     * The number of requested elements is greater than the number of
     * elements inside the set: simply return the whole set. */
    //2. 前提是元素不重复，并且set中元素不够取
    //直接返回全部元素
    if (count >= size) {
        sunionDiffGenericCommand(c,c->argv+1,1,NULL,SET_OP_UNION);
        return;
    }

    /* For CASE 3 and CASE 4 we need an auxiliary dictionary. */
    //后两种情况需要一个字典
    d = dictCreate(&objectKeyPointerValueDictType,NULL);

    /* CASE 3:
     * The number of elements inside the set is not greater than
     * SRANDMEMBER_SUB_STRATEGY_MUL times the number of requested elements.
     * In this case we create a set from scratch with all the elements, and
     * subtract random elements to reach the requested number of elements.
     *
     * This is done because if the number of requsted elements is just
     * a bit less than the number of elements in the set, the natural approach
     * used into CASE 3 is highly inefficient. */
    //3. count*3 > size，取元素超过1/3，则先将所有元素加到字典中再作处理
    //应该是考虑到不重复，在set中不好操作
    if (count*SRANDMEMBER_SUB_STRATEGY_MUL > size) {
        setTypeIterator *si;

        /* Add all the elements into the temporary dictionary. */
        si = setTypeInitIterator(set);
        //用迭代器遍历set，将元素存到dict里
        while((encoding = setTypeNext(si,&ele,&llele)) != -1) {
            int retval = DICT_ERR;

            if (encoding == OBJ_ENCODING_INTSET) {
                retval = dictAdd(d,createStringObjectFromLongLong(llele),NULL);
            } else {
                retval = dictAdd(d,createStringObject(ele,sdslen(ele)),NULL);
            }
            serverAssert(retval == DICT_OK);
        }
        setTypeReleaseIterator(si);
        serverAssert(dictSize(d) == size);

        /* Remove random elements to reach the right count. */
        //随机修剪，直到留下count个元素
        while(size > count) {
            dictEntry *de;

            de = dictGetRandomKey(d);
            dictDelete(d,dictGetKey(de));
            size--;
        }
    }

    /* CASE 4: We have a big set compared to the requested number of elements.
     * In this case we can simply get random elements from the set and add
     * to the temporary set, trying to eventually get enough unique elements
     * to reach the specified count. */
    //取出元素小于set元素总数的1/3
    else {
        unsigned long added = 0;
        robj *objele;
		//随机取元素加入dict，直到dict内有count个元素
        while(added < count) {
            encoding = setTypeRandomElement(set,&ele,&llele);
            if (encoding == OBJ_ENCODING_INTSET) {
                objele = createStringObjectFromLongLong(llele);
            } else {
                objele = createStringObject(ele,sdslen(ele));
            }
            /* Try to add the object to the dictionary. If it already exists
             * free it, otherwise increment the number of objects we have
             * in the result dictionary. */
            if (dictAdd(d,objele,NULL) == DICT_OK)
                added++;
            else
                //如果已存在此元素，则sds对象引用计数-1，此时为0，空间会被清除
                decrRefCount(objele);
        }
    }

    /* CASE 3 & 4: send the result to the user. */
    {
        dictIterator *di;
        dictEntry *de;
        //将最终dict的内容返回给客户端
        addReplyMultiBulkLen(c,count);
        di = dictGetIterator(d);
        while((de = dictNext(di)) != NULL)
            addReplyBulk(c,dictGetKey(de));
        dictReleaseIterator(di);
        dictRelease(d);
    }
}
```

交集底层实现

SINTER，SINTERSTORE

```c
//setkeys源set数组
void sinterGenericCommand(client *c, robj **setkeys,
                          unsigned long setnum, robj *dstkey) {
    robj **sets = zmalloc(sizeof(robj*)*setnum);	//给涉及到的set分配足够空间
    setTypeIterator *si;
    robj *dstset = NULL;
    sds elesds;
    int64_t intobj;
    void *replylen = NULL;
    unsigned long j, cardinality = 0;
    int encoding;

    //取所有涉及的数组
    for (j = 0; j < setnum; j++) {
        //dstkey空时为SINTER，否则为SINTERSTORE命令，取对象方式不同
        robj *setobj = dstkey ?
            lookupKeyWrite(c->db,setkeys[j]) :
            lookupKeyRead(c->db,setkeys[j]);
        //集合不存在时清理内存并结束命令
        if (!setobj) {
            zfree(sets);
            //对于SINTERSTORE命令，要清理目标set，更新server脏键
            if (dstkey) {
                if (dbDelete(c->db,dstkey)) {
                    signalModifiedKey(c->db,dstkey);
                    server.dirty++;
                }
                addReply(c,shared.czero);
            } else {	//SINTER因为未做任何修改，只需要向客户端发送empty信息
                addReply(c,shared.emptymultibulk);
            }
            return;
        }
        //每一个对象读取成功，先检查数据类型，确认后存入sets数组
        if (checkType(c,setobj,OBJ_SET)) {
            zfree(sets);
            return;
        }
        sets[j] = setobj;
    }
    /* Sort sets from the smallest to largest, this will improve our
     * algorithm's performance */
    //先根据set大小进行快排(小到大)，能提高算法性能
    qsort(sets,setnum,sizeof(robj*),qsortCompareSetsByCardinality);

    /* The first thing we should output is the total number of elements...
     * since this is a multi-bulk write, but at this stage we don't know
     * the intersection set size, so we use a trick, append an empty object
     * to the output list and save the pointer to later modify it with the
     * right length */
    //SINTER，因为返回信息不定长，所以创建临时链表；
    if (!dstkey) {
        replylen = addDeferredMultiBulkLength(c);
    //SINTERSTRORE，创建整数集合
    } else {
        /* If we have a target key where to store the resulting set
         * create this key with an empty set inside */
        dstset = createIntsetObject();
    }

    /* Iterate all the elements of the first (smallest) set, and test
     * the element against all the other sets, if at least one set does
     * not include the element it is discarded */
    //对最小的set的所有元素遍历并在后面的set中查找
    //只要有一个set不存在这个元素，则这个元素不属于交集
    si = setTypeInitIterator(sets[0]);
    //用迭代器遍历最小set的每一个元素，根据set的encoding，ht存入elesds，intset存入intobj
    while((encoding = setTypeNext(si,&elesds,&intobj)) != -1) {
        for (j = 1; j < setnum; j++) {
            //相同的set直接跳过
            if (sets[j] == sets[0]) continue;
            //如果最小set的encoding为intset
            if (encoding == OBJ_ENCODING_INTSET) {
                /* intset with intset is simple... and fast */
                //要对比的set也是intset，就直接用intset的操作函数(直接传入int64_t)
                if (sets[j]->encoding == OBJ_ENCODING_INTSET &&
                    !intsetFind((intset*)sets[j]->ptr,intobj))
                {
                    break;
                /* in order to compare an integer with an object we
                 * have to use the generic function, creating an object
                 * for this */
                //如果要对比的set是hashtable，要把intobj转换为sds对象才能对比
                } else if (sets[j]->encoding == OBJ_ENCODING_HT) {
                    elesds = sdsfromlonglong(intobj);
                    if (!setTypeIsMember(sets[j],elesds)) {
                        sdsfree(elesds);
                        break;
                    }
                    sdsfree(elesds);
                }
            //如果最小set的encoding为ht，则无法转换sds为int64_t，只能直接用IsMember对比
            } else if (encoding == OBJ_ENCODING_HT) {
                if (!setTypeIsMember(sets[j],elesds)) {
                    break;
                }
            }
        }

        /* Only take action when all sets contain the member */
        //for循环结束后，当前 elesds或intobj中的元素为交集中的元素
        if (j == setnum) {
            //这里encoding是最小set的encoding
            //因为交集的所有元素必然属于这个set，所以直接沿用这个属性
            if (!dstkey) {//SINTER，直接发送信息到客户端
                if (encoding == OBJ_ENCODING_HT)
                    addReplyBulkCBuffer(c,elesds,sdslen(elesds));
                else
                    addReplyBulkLongLong(c,intobj);
                cardinality++;
            } else {//SINTERSTORE要先保存到set中
                if (encoding == OBJ_ENCODING_INTSET) {
                    //int转sds再保存到新set中
                    elesds = sdsfromlonglong(intobj);
                    setTypeAdd(dstset,elesds);
                    sdsfree(elesds);
                } else {
                    setTypeAdd(dstset,elesds);
                }
            }
        }
    }
    setTypeReleaseIterator(si);
    
	//SINTERSTORE命令，交集确定后的存储
    if (dstkey) {
        /* Store the resulting set into the target, if the intersection
         * is not an empty set. */
        //删除已存在的同名set
        int deleted = dbDelete(c->db,dstkey);
        //交集飞空则保存，空集则清理空间
        if (setTypeSize(dstset) > 0) {
            dbAdd(c->db,dstkey,dstset);
            addReplyLongLong(c,setTypeSize(dstset));
            notifyKeyspaceEvent(NOTIFY_SET,"sinterstore",
                dstkey,c->db->id);
        } else {
            decrRefCount(dstset);
            addReply(c,shared.czero);	//返回数量为0
            if (deleted)
                notifyKeyspaceEvent(NOTIFY_GENERIC,"del",
                    dstkey,c->db->id);
        }
        signalModifiedKey(c->db,dstkey);
        server.dirty++;
    } else {
        setDeferredMultiBulkLength(c,replylen,cardinality);
    }
    //释放之前占用的临时set数组空间
    zfree(sets);
}
```

并集，差集底层实现

SUNION，SUNIONSTORE，SDIFF，SDIFFSTORE

```c
#define SET_OP_UNION 0
#define SET_OP_DIFF 1
void sunionDiffGenericCommand(client *c, robj **setkeys, int setnum,
                              robj *dstkey, int op) {
    robj **sets = zmalloc(sizeof(robj*)*setnum);
    setTypeIterator *si;
    robj *dstset = NULL;
    sds ele;
    int j, cardinality = 0;
    int diff_algo = 1;
	
    for (j = 0; j < setnum; j++) {
        robj *setobj = dstkey ?
            lookupKeyWrite(c->db,setkeys[j]) :
            lookupKeyRead(c->db,setkeys[j]);
        if (!setobj) {
            //不存在的set设置为NULL
            sets[j] = NULL;
            continue;
        }
        //但key对应的不是set类型则会开始清理空间并结束命令
        if (checkType(c,setobj,OBJ_SET)) {
            zfree(sets);
            return;
        }
        sets[j] = setobj;
    }
	//上面的操作与交集类似，分配空间，读取set
    /* Select what DIFF algorithm to use.
     *
     * Algorithm 1 is O(N*M) where N is the size of the element first set
     * and M the total number of sets.
     *
     * Algorithm 2 is O(N) where N is the total number of elements in all
     * the sets.
     *
     * We compute what is the best bet with the current input here. */
    //下面是差集操作的预处理
    //对差集实现了两种算法，时间复杂度分别为
    //1. O(N*M)，N为第一个set的元素个数，M为set个数
    //2. O(N)，N为总元素个数
    if (op == SET_OP_DIFF && sets[0]) {
        long long algo_one_work = 0, algo_two_work = 0;

        for (j = 0; j < setnum; j++) {
            if (sets[j] == NULL) continue;
            //分别计算当前情况下两个算法的资源消耗
            algo_one_work += setTypeSize(sets[0]);
            algo_two_work += setTypeSize(sets[j]);
        }

        /* Algorithm 1 has better constant times and performs less operations
         * if there are elements in common. Give it some advantage. */
        algo_one_work /= 2;	//相对来说算法1有优势，施加一些倾向性
        diff_algo = (algo_one_work <= algo_two_work) ? 1 : 2;

        if (diff_algo == 1 && setnum > 1) {
            /* With algorithm 1 it is better to order the sets to subtract
             * by decreasing size, so that we are more likely to find
             * duplicated elements ASAP. */
            //除sets中第一个意外的其他set，按照(set大小)元素数量排序(降序)
            qsort(sets+1,setnum-1,sizeof(robj*),qsortCompareSetsByRevCardinality);
        }
    }

    /* We need a temp set object to store our union. If the dstkey
     * is not NULL (that is, we are inside an SUNIONSTORE operation) then
     * this set object will be the resulting object to set into the target key*/
    //创建临时set作为结果集
    dstset = createIntsetObject();
	
    //如果是执行并集操作，只要向结果集中加入所有元素即可
    if (op == SET_OP_UNION) {
        /* Union is trivial, just add every element of every set to the
         * temporary set. */
        for (j = 0; j < setnum; j++) {
            if (!sets[j]) continue; /* non existing keys are like empty sets */

            si = setTypeInitIterator(sets[j]);
            while((ele = setTypeNextObject(si)) != NULL) {
                if (setTypeAdd(dstset,ele)) cardinality++;
                sdsfree(ele);
            }
            setTypeReleaseIterator(si);
        }
    //若使用算法1执行差集操作
    } else if (op == SET_OP_DIFF && sets[0] && diff_algo == 1) {
        /* DIFF Algorithm 1:
         *
         * We perform the diff by iterating all the elements of the first set,
         * and only adding it to the target set if the element does not exist
         * into all the other sets.
         *
         * This way we perform at max N*M operations, where N is the size of
         * the first set, and M the number of sets. */
        si = setTypeInitIterator(sets[0]);
        //遍历第一个set中的所有元素，将其他set中都不存在的元素加入结果集
        while((ele = setTypeNextObject(si)) != NULL) {
            for (j = 1; j < setnum; j++) {
                //set不存在则直接跳到下一set
                if (!sets[j]) continue; /* no key is an empty set. */
                //set相同差集为空
                if (sets[j] == sets[0]) break; /* same set! */
                //检查每个set中是否有迭代器当前指向的元素
                if (setTypeIsMember(sets[j],ele)) break;
            }
            //已经通过了所有set的检查，将此元素加入差集
            if (j == setnum) {
                /* There is no other set with this element. Add it. */
                setTypeAdd(dstset,ele);
                cardinality++;
            }
            sdsfree(ele);	//清理临时对象
        }
        setTypeReleaseIterator(si);	//清理临时迭代器
    //使用算法2执行差集操作
    } else if (op == SET_OP_DIFF && sets[0] && diff_algo == 2) {
        /* DIFF Algorithm 2:
         *
         * Add all the elements of the first set to the auxiliary set.
         * Then remove all the elements of all the next sets from it.
         *
         * This is O(N) where N is the sum of all the elements in every
         * set. */
        //只对第一个set的元素向结果集作ADD，其余后方元素作删除操作(无则不变，有则删除)
        for (j = 0; j < setnum; j++) {
            //跳过空集合
            if (!sets[j]) continue; /* non existing keys are like empty sets */

            si = setTypeInitIterator(sets[j]);
            while((ele = setTypeNextObject(si)) != NULL) {
                if (j == 0) {
                    //加入第一个set的元素
                    if (setTypeAdd(dstset,ele)) cardinality++;
                } else {
                    //删除其他元素
                    if (setTypeRemove(dstset,ele)) cardinality--;
                }
                sdsfree(ele);
            }
            setTypeReleaseIterator(si);

            /* Exit if result set is empty as any additional removal
             * of elements will have no effect. */
            if (cardinality == 0) break;
        }
    }

    /* Output the content of the resulting set, if not in STORE mode */
    //非-STORE命令，只发送消息
    if (!dstkey) {
        addReplyMultiBulkLen(c,cardinality);
        si = setTypeInitIterator(dstset);
        while((ele = setTypeNextObject(si)) != NULL) {
            addReplyBulkCBuffer(c,ele,sdslen(ele));
            sdsfree(ele);
        }
        setTypeReleaseIterator(si);
        decrRefCount(dstset);
    //需要储存结果的命令
    } else {
        /* If we have a target key where to store the resulting set
         * create this key with the result set inside */
        //先删后存，同SINTERSTORE
        int deleted = dbDelete(c->db,dstkey);
        if (setTypeSize(dstset) > 0) {
            dbAdd(c->db,dstkey,dstset);
            addReplyLongLong(c,setTypeSize(dstset));
            notifyKeyspaceEvent(NOTIFY_SET,
                op == SET_OP_UNION ? "sunionstore" : "sdiffstore",
                dstkey,c->db->id);
        } else {
            decrRefCount(dstset);
            addReply(c,shared.czero);
            if (deleted)
                notifyKeyspaceEvent(NOTIFY_GENERIC,"del",
                    dstkey,c->db->id);
        }
        signalModifiedKey(c->db,dstkey);
        server.dirty++;
    }
    zfree(sets);
}
```

#### 00x07 zset

---

##### 数据实现

| encoding              | ptr          |
| --------------------- | ------------ |
| OBJ_ENCODING_SKIPLIST | 跳跃表和字典 |
| OBJ_ENCODING_ZIPLIST  | 压缩列表     |

```c
robj *createZsetObject(void) {
    zset *zs = zmalloc(sizeof(*zs));
    robj *o;

    zs->dict = dictCreate(&zsetDictType,NULL);
    zs->zsl = zslCreate();  //in t_zset.c
    o = createObject(OBJ_ZSET,zs);
    o->encoding = OBJ_ENCODING_SKIPLIST;
    return o;
}

robj *createZsetZiplistObject(void) {
    unsigned char *zl = ziplistNew();
    robj *o = createObject(OBJ_ZSET,zl);
    o->encoding = OBJ_ENCODING_ZIPLIST;
    return o;
}
```

hash, set, zset 都有含有dict的实现方法，但创建时的传入的参数不同，其结构定义在server.c种

```c
/* Set dictionary type. Keys are SDS strings, values are ot used. */
dictType setDictType = {
    dictSdsHash,               /* hash function */
    NULL,                      /* key dup */
    NULL,                      /* val dup */
    dictSdsKeyCompare,         /* key compare */
    dictSdsDestructor,         /* key destructor */
    NULL                       /* val destructor */
};

/* Sorted sets hash (note: a skiplist is used in addition to the hash table) */
dictType zsetDictType = {
    dictSdsHash,               /* hash function */
    NULL,                      /* key dup */
    NULL,                      /* val dup */
    dictSdsKeyCompare,         /* key compare */
    NULL,                      /* Note: SDS string shared & freed by skiplist */
    NULL                       /* val destructor */
};

/* Db->dict, keys are sds strings, vals are Redis objects. */
dictType dbDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    dictSdsDestructor,          /* key destructor */
    dictObjectDestructor   /* val destructor */
};
```

##### 命令实现











1. 对象系统 object.c *
2. 字串键 t_string.c *
3. 列表键 t_list.c *
4. 散列键 t_hash.c *
5. 集合键 t_set.c *
6. 有序集合键 t_zset.c中除 zsl 开头的函数之外的所有函数 *