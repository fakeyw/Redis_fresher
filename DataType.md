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
    server.dirty++;			//增加数据库的dirty值，作为持久化的参考指标
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
void listTypeTryConversion(robj *subject, robj *value);
void listTypePush(robj *subject, robj *value, int where); // PUSH底层实现
robj *listTypePop(robj *subject, int where); // POP底层实现
unsigned long listTypeLength(robj *subject); // 返回entry节点个数
// 初始化列表类型的迭代器为一个指定的下标
listTypeIterator *listTypeInitIterator(robj *subject, long index, unsigned char direction);
void listTypeReleaseIterator(listTypeIterator *li); // 释放迭代器空间
// 将列表类型的迭代器指向的entry保存在提供的listTypeEntry结构中，并且更新迭代器，1表示成功，0失败
int listTypeNext(listTypeIterator *li, listTypeEntry *entry);
robj *listTypeGet(listTypeEntry *entry); // 根据迭代器当前的指向返回value对象
void listTypeInsert(listTypeEntry *entry, robj *value, int where); // 插入value到where位置
int listTypeEqual(listTypeEntry *entry, robj *o); //判断节点
void listTypeDelete(listTypeIterator *iter, listTypeEntry *entry); // 删除迭代器当前指向的节点
// 转换ZIPLIST编码类型为quicklist类型，encoding变为OBJ_ENCODING_QUICKLIST
void listTypeConvert(robj *subject, int enc);
```

listTypeIterator内包含的是quicklist的迭代器与list的信息

listTypeEntry则包含了quicklistEntry

关于entry，list与quicklist的entry实际上是ziplist的entry，在存储空间中为连续的内存块，在修改这个内存块之前要先将其信息读出来。在ziplist中这个结构为ziplistEntry，这里的quicklistEntry与ziplist功能相同，只不过为了适应quicklist而定义了新的结构。

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



##### 命令实现





#### 00x05 hash

---

##### 数据实现

默认创建对象为ziplist结构，dict类型的hash对象是在数据量达到配置中限制的值后通过转换获得的

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

##### 命令实现

#### 00x06 set

---

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

##### 命令实现

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