# Memory&Storage

#### 内存

**00x01 zmalloc 内存分配** 

---

redis本身没有实现内存池，其内存分配方式在预编译时确定<br>选择对象有libc的标准库、jemalloc与google的tcmalloc<br>其中jemalloc依赖在源码的dep中存在，其相对于glibc的malloc的标准库的优势主要体现在避免内存碎片与并发扩展上<br>而tcmalloc则需要主动安装才能使用<br>

zmalloc.h中关于内存库的宏：

```c
#if defined(USE_TCMALLOC)
	#define ZMALLOC_LIB ("tcmalloc-" __xstr(TC_VERSION_MAJOR) "." __xstr(TC_VERSION_MINOR))
	#include <google/tcmalloc.h>
	#if (TC_VERSION_MAJOR == 1 && TC_VERSION_MINOR >= 6) || (TC_VERSION_MAJOR > 1)
		#define HAVE_MALLOC_SIZE 1
		#define zmalloc_size(p) tc_malloc_size(p)
	#else
		#error "Newer version of tcmalloc required"
	#endif

#elif defined(USE_JEMALLOC)
	#define ZMALLOC_LIB ("jemalloc-" __xstr(JEMALLOC_VERSION_MAJOR) "." __xstr(JEMALLOC_VERSION_MINOR) "." __xstr(JEMALLOC_VERSION_BUGFIX))
	#include <jemalloc/jemalloc.h>
	#if (JEMALLOC_VERSION_MAJOR == 2 && JEMALLOC_VERSION_MINOR >= 1) || (JEMALLOC_VERSION_MAJOR > 2)
		#define HAVE_MALLOC_SIZE 1
		#define zmalloc_size(p) je_malloc_usable_size(p)
	#else
		#error "Newer version of jemalloc required"
	#endif

#elif defined(__APPLE__)
	#include <malloc/malloc.h>
	#define HAVE_MALLOC_SIZE 1
	#define zmalloc_size(p) malloc_size(p)
#endif
```

在zmalloc.c中，根据预编译宏对malloc系列函数进行覆盖

```c
#if defined(USE_TCMALLOC)
	#define malloc(size) tc_malloc(size)
	#define calloc(count,size) tc_calloc(count,size)
	#define realloc(ptr,size) tc_realloc(ptr,size)
	#define free(ptr) tc_free(ptr)
#elif defined(USE_JEMALLOC)
	#define malloc(size) je_malloc(size)
	#define calloc(count,size) je_calloc(count,size)
	#define realloc(ptr,size) je_realloc(ptr,size)
	#define free(ptr) je_free(ptr)
	#define mallocx(size,flags) je_mallocx(size,flags)
	#define dallocx(ptr,flags) je_dallocx(ptr,flags)
#endif
```



下面是zmalloc.c中主要函数的实现：

**zmalloc()**

```c
void *zmalloc(size_t size) {
    void *ptr = malloc(size+PREFIX_SIZE); 
    if (!ptr) zmalloc_oom_handler(size); //未成功分配空间时报错并退出
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE; //将指针向右偏移到可用内存块
#endif
}
```

分配长度要在size上加一个PREFIX_SIZE，根据平台不同确定是否在内存头部写入这块内存的大小<br>其中PREFIX_SIZE的定义为

```c
#ifdef HAVE_MALLOC_SIZE //HAVE_MALLOC_SIZE用来确定系统是否有函数malloc_size,在zmalloc.h中定义
	#define PREFIX_SIZE (0)	
#else
	#if defined(__sun) || defined(__sparc) || defined(__sparc__)
		#define PREFIX_SIZE (sizeof(long long)) //Solaris
	#else
		#define PREFIX_SIZE (sizeof(size_t))	//others
	#endif
#endif
```

关于`HAVE_MALLOC_SIZE`标记的是，所调用的库中是否带有检测内存长度的函数malloc_size()。如果有，则zmalloc_size则指向malloc_size，如果没有这一函数，则在zmalloc.c中以为内存块添加头部信息的方式实现zmalloc_size。故这一标记实际上实在区别是否有这一头部信息，据此对内存块的分配作不同处理。

zmalloc中使用到的` update_zmalloc_stat_alloc()` 宏函数

其作用是增加已分配的内存大小的记录

```c
#define update_zmalloc_stat_alloc(__n) do { \
    size_t _n = (__n); \
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \
    atomicIncr(used_memory,__n); \
} while(0)
```

`_n&(sizeof(long)-1) `  得出的结果是：\_n是否是`long`的倍数，\_n&7 == _n%8 而位操作要更快一些<br>所以，如果不是`long`的倍数则会补上一个偏移量使之成为`long`的倍数

跟进一下`atomicIncr()`，是个包装了获取/释放互斥锁操作的宏函数，用于线程安全地增加某个变量的值<br>(在atomicvar.h中定义的atomic*系列函数都是需要获取锁的原子操作)

```c
#define atomicIncr(var,count) do { \
    pthread_mutex_lock(&var ## _mutex); \
    var += (count); \
    pthread_mutex_unlock(&var ## _mutex); \
} while(0)
```

同样地，`update_zmalloc_stat_free`则是调用了`atomcDecr`，作线程安全减

> 另，关于宏函数定义中的`do{...}while(0)`这一无限循环：<br>[do{...}while(0)的意义和用法](http://www.spongeliu.com/415.html) 这篇博客解释得非常清楚



**zcalloc()**

```c
void *zcalloc(size_t size) {
    void *ptr = calloc(1, size+PREFIX_SIZE);

    if (!ptr) zmalloc_oom_handler(size);
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;
#endif
}
```

与zmalloc()几乎没有差别，没有特别使用calloc的第一个参数来分配成倍空间。<br>两者调用方式一致，唯一区别在于zcalloc()会对分配的空间进行初始化。



**zrealloc()**

```c
void *zrealloc(void *ptr, size_t size) {	//传入起始地址指针
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
#endif
    size_t oldsize;
    void *newptr;

    if (ptr == NULL) return zmalloc(size);
#ifdef HAVE_MALLOC_SIZE 				//区分内存块是否带有保存内存块大小信息的头部
    oldsize = zmalloc_size(ptr);
    newptr = realloc(ptr,size);
    if (!newptr) zmalloc_oom_handler(size); //错误处理

    update_zmalloc_stat_free(oldsize);		//更新已使用内存大小
    update_zmalloc_stat_alloc(zmalloc_size(newptr)); 
    return newptr;
#else
    realptr = (char*)ptr-PREFIX_SIZE;		//指向带有信息的头部
    oldsize = *((size_t*)realptr);
    newptr = realloc(realptr,size+PREFIX_SIZE);
    if (!newptr) zmalloc_oom_handler(size);

    *((size_t*)newptr) = size;				//更换头部信息
    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(size);
    return (char*)newptr+PREFIX_SIZE;		//指向内存块实际位置
#endif
}
```



**zfree()**

```c
void zfree(void *ptr) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
    size_t oldsize;
#endif
    if (ptr == NULL) return;
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_free(zmalloc_size(ptr));
    free(ptr);
#else
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    update_zmalloc_stat_free(oldsize+PREFIX_SIZE);
    free(realptr);
#endif
}
```

根据上面三个函数的源码解读，应该很容易读懂这一函数。



**zstrdup()** 复制一个字符串，并返回新的指针

```c
char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = zmalloc(l);
    memcpy(p,s,l);
    return p;
}
```



**zmalloc_get_rss()** 

> **VSS**- Virtual Set Size 虚拟耗用内存（包含共享库占用的内存）
>
> **RSS**- Resident Set Size 实际使用物理内存（包含共享库占用的内存）
>
> **PSS**- Proportional Set Size 实际使用的物理内存（比例分配共享库占用的内存）
>
> **USS**- Unique Set Size 进程独自占用的物理内存（不包含共享库占用的内存）
>
> 一般地：VSS >= RSS >= PSS >= USS

```c
#if defined(HAVE_PROC_STAT) //Linux下可以读取/proc/(pid)/stat 
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

size_t zmalloc_get_rss(void) {
    int page = sysconf(_SC_PAGESIZE);			//当前系统内存页的大小
    size_t rss;
    char buf[4096];
    char filename[256];
    int fd, count;
    char *p, *x;

    snprintf(filename,256,"/proc/%d/stat",getpid()); //pid:进程号,读取到的是内存页数
    if ((fd = open(filename,O_RDONLY)) == -1) return 0;
    if (read(fd,buf,4096) <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    p = buf;
    count = 23; /* RSS is the 24th field in /proc/<pid>/stat */
    while(p && count--) {
        p = strchr(p,' ');
        if (p) p++;
    }
    if (!p) return 0;
    x = strchr(p,' ');
    if (!x) return 0;
    *x = '\0';

    rss = strtoll(p,NULL,10);
    rss *= page; //页数*页大小
    return rss;
}
#elif defined(HAVE_TASKINFO)	//Unix系列 读取task_info
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/task.h>
#include <mach/mach_init.h>

size_t zmalloc_get_rss(void) {
    task_t task = MACH_PORT_NULL;
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (task_for_pid(current_task(), getpid(), &task) != KERN_SUCCESS)
        return 0;
    task_info(task, TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count);

    return t_info.resident_size;
}
#else	//无法测量，假装是实际占用内存，无碎片
size_t zmalloc_get_rss(void) {
    /* If we can't get the RSS in an OS-specific way for this system just
     * return the memory usage we estimated in zmalloc()..
     *
     * Fragmentation will appear to be always 1 (no fragmentation)
     * of course... */
    return zmalloc_used_memory();
}
#endif
```

> 关于内存碎片：调用malloc的时候，malloc并不是严格按照参数的值来分配内存，多出的空间就是内存碎片



**00x02 ziplist 压缩列表**

---

> redis创建hash表、有序集合与链表时使用的存储结构，能够使内存排列更紧密，藉此提高访存性能。

**ziplist结构**

> 在ziplist.c的前部注释中：
>
> The general layout of the ziplist is as follows:
>
> \<zlbytes> \<zltail> \<zllen> \<entry> \<entry> ... \<entry> \<zlend>
>
> zlbytes：4子节无符号整型，ziplist占用的字节数，主要在重新分配内存时使用
>
> zltail：4子节无符号整型，最后一个节点的偏移值，用于找到尾节点
>
> zllen：2字节无符号整型，节点总数，当超过2^16-2时需要遍历整个链表来获取节点总数
>
> zlend：1字节占位符，值为255，表示链表结束

<img src='https://img-blog.csdn.net/20160406131926268' />

在4.0.8版本中，ziplist并不存在定义的struct，而是由ziplistNew()创建的一段内存块

```c
unsigned char *ziplistNew(void) {
    unsigned int bytes = ZIPLIST_HEADER_SIZE+1;
    unsigned char *zl = zmalloc(bytes);
    ZIPLIST_BYTES(zl) = intrev32ifbe(bytes); 
    ZIPLIST_TAIL_OFFSET(zl) = intrev32ifbe(ZIPLIST_HEADER_SIZE);
    ZIPLIST_LENGTH(zl) = 0;
    zl[bytes-1] = ZIP_END;
    return zl;
}
```

但定义了元素实体zlentry(节点)，但仅用于描述而非存储，与实际结构不同

```c
typedef struct zlentry {
    unsigned int prevrawlensize; /* 编码 prevrawlen 所需的字节大小 */
    unsigned int prevrawlen;     /* 上一节点长度 */
    unsigned int lensize;        /* 编码 len 所需的字节大小 */
    unsigned int len;            /* 当前节点长度 */
    unsigned int headersize;     /* prevrawlensize + lensize. */
    unsigned char encoding;      /* 编码类型 */
    unsigned char *p;            /* 节点值的指针 */
} zlentry;
```

实际结构为 <上一个链表节点占用的长度><编码方式 & 当前链表节点占用的长度><当前节点数据>

**上一个链表结点占用的长度的编码规则：**

- 当长度值小于254时使用1个字节存储，该字节存储的数值就是上一个节点的长度值。
- 当长度值大于或等于254时使用5个字节存储，第1个字节的数值为254，表示上一个节点的长度值大于等于254接下来的4个字节才是真正的长度

**编码方式 & 当前链表节点占用的长度：**

字符串，encoding域 为 00、01、10

| 编码                                         | 编码长度      | 含义                                                         |
| ----------------------------------------- | ------------------- | ------------------------------------------------- |
| 00pppppp                                     | 1 byte       | 表示长度小于等于63（只有后六位存放字符串长度，2^6 - 1 = 63)字节的字符串，后6位用于存储字符串长度。 |
| 01pppppp,qqqqqqqq                            | 2 bytes      | 表示长度小于等于16383（2^14 - 1）字节的字符串，后14用于存储字符串长度 |
| 10______,qqqqqqqq,rrrrrrrr,ssssssss,tttttttt | 5 bytes      | 表示长度大于等于16384字节的字符串，前1个字节的后6位无意义，后4个字节用来存储字符串长度 |

整型，encoding域 为 11

| 编码     | 编码长度 | 含义                               |
| -------- | -------- | ---------------------------------- |
| 11000000 | 1 byte   | int16_t整型                        |
| 11010000 | 1 byte   | int32_t整型                        |
| 11100000 | 1 byte   | int64_t整型                        |
| 11110000 | 1 byte   | 24bit有符号整数                    |
| 11111110 | 1 byte   | 8bit有符号整型                     |
| 1111xxxx | 1 byte   | 4bit无符号整型，表示[0,12]范围的数 |

**当前节点数据：**

类型由前一部分决定

将一个ziplist元素内存块转换为zlentry结构储存到e中的函数
```c
void zipEntry(unsigned char *p, zlentry *e) {
    ZIP_DECODE_PREVLEN(p, e->prevrawlensize, e->prevrawlen);
    ZIP_DECODE_LENGTH(p + e->prevrawlensize, e->encoding, e->lensize, e->len);
    e->headersize = e->prevrawlensize + e->lensize;
    e->p = p;
}
```
跟进ZIP_DECODE_PREVLEN() 和 ZIP_DECODE_LENGTH() 两个工具宏函数

```c
#define ZIP_DECODE_PREVLEN(ptr, prevlensize, prevlen) do {                     \
    ZIP_DECODE_PREVLENSIZE(ptr, prevlensize);                                  \
    if ((prevlensize) == 1) {                                                  \
        (prevlen) = (ptr)[0];                                                  \
    } else if ((prevlensize) == 5) {                                           \
        assert(sizeof((prevlen)) == 4);                                    \
        memcpy(&(prevlen), ((char*)(ptr)) + 1, 4);                             \
        memrev32ifbe(&prevlen);                                                \
    }                                                                          \
} while(0);
```

```c
#define ZIP_STR_MASK 0xc0 		// 字符串编码  < 0xc0 (1100,0000)
#define ZIP_STR_06B (0 << 6)
#define ZIP_STR_14B (1 << 6)
#define ZIP_STR_32B (2 << 6)     //↓判断是否为字符串编码
#define ZIP_ENTRY_ENCODING(ptr, encoding) do {  \
    (encoding) = (ptr[0]); \
    if ((encoding) < ZIP_STR_MASK) (encoding) &= ZIP_STR_MASK; \
} while(0)
#define ZIP_DECODE_LENGTH(ptr, encoding, lensize, len) do {                    \
    ZIP_ENTRY_ENCODING((ptr), (encoding));                                     \
    if ((encoding) < ZIP_STR_MASK) {                                           \
        if ((encoding) == ZIP_STR_06B) {                                       \
            (lensize) = 1;                                                     \
            (len) = (ptr)[0] & 0x3f;                                           \
        } else if ((encoding) == ZIP_STR_14B) {                                \
            (lensize) = 2;                                                     \
            (len) = (((ptr)[0] & 0x3f) << 8) | (ptr)[1];                       \
        } else if ((encoding) == ZIP_STR_32B) {                                \
            (lensize) = 5;                                                     \
            (len) = ((ptr)[1] << 24) |                                         \
                    ((ptr)[2] << 16) |                                         \
                    ((ptr)[3] <<  8) |                                         \
                    ((ptr)[4]);                                                \
        } else {                                                               \
            panic("Invalid string encoding 0x%02X", (encoding));               \
        }                                                                      \
    } else {                                                                   \
        (lensize) = 1;                                                         \
        (len) = zipIntSize(encoding);                                          \
    }                                                                          \
} while(0);
```

而创建ziplist元素内存块的函数为 `ziplistPush()` 和 `ziplistInsert()` 

```c
unsigned char *ziplistPush(unsigned char *zl, unsigned char *s, unsigned int slen, int where) {
    unsigned char *p;
    p = (where == ZIPLIST_HEAD) ? ZIPLIST_ENTRY_HEAD(zl) : ZIPLIST_ENTRY_END(zl);
    return __ziplistInsert(zl,p,s,slen);
```

向头部插入特定值的节点，实际上是调用了`__ziplistInsert()`

```c
unsigned char *ziplistInsert(unsigned char *zl, unsigned char *p, unsigned char *s, unsigned int slen) {
    return __ziplistInsert(zl,p,s,slen);
}
/*
 zl：ziplist首地址
 p：插入位置
 s：待插入字符串的首地址
 slen：带插入字符串长度
*/
unsigned char *__ziplistInsert(unsigned char *zl, unsigned char *p, unsigned char *s, unsigned int slen) {
    size_t curlen = intrev32ifbe(ZIPLIST_BYTES(zl)), reqlen;
    //reqlen为新插入节点的长度
    unsigned int prevlensize, prevlen = 0;
    size_t offset;
    int nextdiff = 0;
    unsigned char encoding = 0;
    long long value = 123456789; /* initialized to avoid warning. Using a value
                                    that is easy to see if for some reason
                                    we use it uninitialized. */
    zlentry tail;

    /* Find out prevlen for the entry that is inserted. */
    if (p[0] != ZIP_END) {
        //如果p不是结束符，则取p前节点的信息
        ZIP_DECODE_PREVLEN(p, prevlensize, prevlen);
    } else {
        //如果是的话，取出尾节点
        unsigned char *ptail = ZIPLIST_ENTRY_TAIL(zl);
        if (ptail[0] != ZIP_END) {
            prevlen = zipRawEntryLength(ptail);
        }
    }

    /* 如果当前节点可以被编码为【整型】数据则返回1，且value和encoding分别保存新值和编码信息*/
    if (zipTryEncoding(s,slen,&value,&encoding)) {
        /* 可以则计算其占用字节数 */
        reqlen = zipIntSize(encoding);
    } else {
        /* 不可以则直接使用长度 */
        reqlen = slen;
    }
    /* 带上占用空间的信息 */
    reqlen += zipStorePrevEntryLength(NULL,prevlen); 
    reqlen += zipStoreEntryEncoding(NULL,encoding,slen); 
    //reqlen = len(data)+len(prevlen)+len(encoding&slen)

    /* When the insert position is not equal to the tail, we need to
     * make sure that the next entry can hold this entry's length in
     * its prevlen field. */
    int forcelarge = 0; /* 检查后一元素的prevlen是否足够保存 */
    nextdiff = (p[0] != ZIP_END) ? zipPrevLenByteDiff(p,reqlen) : 0;
    if (nextdiff == -4 && reqlen < 4) {
        nextdiff = 0;
        forcelarge = 1;
    }

    /* Store offset because a realloc may change the address of zl. */
    offset = p-zl;
    zl = ziplistResize(zl,curlen+reqlen+nextdiff);
    p = zl+offset;

    /* Apply memory move when necessary and update tail offset. */
    if (p[0] != ZIP_END) {
        /* 将p后所有内容移到p+reqlen */
        memmove(p+reqlen,p-nextdiff,curlen-offset-1+nextdiff);

        /* Encode this entry's raw length in the next entry. */
        if (forcelarge) //扩展
            zipStorePrevEntryLengthLarge(p+reqlen,reqlen);
        else
            zipStorePrevEntryLength(p+reqlen,reqlen);

        /* 更新ztail */
        ZIPLIST_TAIL_OFFSET(zl) =
            intrev32ifbe(intrev32ifbe(ZIPLIST_TAIL_OFFSET(zl))+reqlen);

        /* When the tail contains more than one entry, we need to take
         * "nextdiff" in account as well. Otherwise, a change in the
         * size of prevlen doesn't have an effect on the *tail* offset. */
        zipEntry(p+reqlen, &tail);
        if (p[reqlen+tail.headersize+tail.len] != ZIP_END) {
            ZIPLIST_TAIL_OFFSET(zl) =
                intrev32ifbe(intrev32ifbe(ZIPLIST_TAIL_OFFSET(zl))+nextdiff);
        }
    } else {
        /* This element will be the new tail. */
        ZIPLIST_TAIL_OFFSET(zl) = intrev32ifbe(p-zl);
    }

    /* 后一节点的prevlen变更了，要执行级联更新 */
    if (nextdiff != 0) {
        offset = p-zl;
        zl = __ziplistCascadeUpdate(zl,p+reqlen);
        p = zl+offset;
    }

    /* 写入，前面都是计算 */
    p += zipStorePrevEntryLength(p,prevlen);
    p += zipStoreEntryEncoding(p,encoding,slen);
    if (ZIP_IS_STR(encoding)) {
        memcpy(p,s,slen);
    } else {
        zipSaveInteger(p,value,encoding);
    }
    ZIPLIST_INCR_LENGTH(zl,1);
    return zl;
}
```

级联更新 `__ziplistCascadeUpdate()` 

原则：prevlen可扩展，不可缩小，避免连续变更的抖动现象

这是保证ziplist链表结构灵活性的最重要的函数

```c
unsigned char *__ziplistCascadeUpdate(unsigned char *zl, unsigned char *p) {
    size_t curlen = intrev32ifbe(ZIPLIST_BYTES(zl)), rawlen, rawlensize;
    size_t offset, noffset, extra;
    unsigned char *np;
    zlentry cur, next;
							//循环检查下个节点是否需要扩展（不考虑缩小）
    while (p[0] != ZIP_END) {	//当不需要扩展时，只改一下数值，而后级联更新结束
        zipEntry(p, &cur);	//将自p起的内存块表达为zlentry对象 cur
        rawlen = cur.headersize + cur.len;
        rawlensize = zipStorePrevEntryLength(NULL,rawlen);

        /* 读到了结束符，即本块只有结束符 */
        if (p[rawlen] == ZIP_END) break;
        zipEntry(p+rawlen, &next);

        /* 后块(next)长度足够 */
        if (next.prevrawlen == rawlen) break;

        if (next.prevrawlensize < rawlensize) {
            /* The "prevlen" field of "next" needs more bytes to hold
             * the raw length of "cur". */
            offset = p-zl;	//记录偏移量，记录增量，重新分配空间
            extra = rawlensize-next.prevrawlensize;
            zl = ziplistResize(zl,curlen+extra);
            p = zl+offset;

            /* Current pointer and offset for next element. */
            np = p+rawlen;
            noffset = np-zl;

            /* 如果下一块不是尾部，则更新尾偏移量 
          	   ZIPLIST_TAIL_OFFSET(zl)是最后一个节点的首地址  */
            if ((zl+intrev32ifbe(ZIPLIST_TAIL_OFFSET(zl))) != np) {
                ZIPLIST_TAIL_OFFSET(zl) =
                    intrev32ifbe(intrev32ifbe(ZIPLIST_TAIL_OFFSET(zl))+extra);
            }

            /* 后部全体右移 */
            memmove(np+rawlensize,
                np+next.prevrawlensize,
                curlen-noffset-next.prevrawlensize-1);
            //空出来的部分存储上个节点的长度
            zipStorePrevEntryLength(np,rawlen);

            /* 指向下一块 */
            p += rawlen;
            curlen += extra;
        } else {
            if (next.prevrawlensize > rawlensize) {
                /* This would result in shrinking, which we want to avoid.
                 * So, set "rawlen" in the available bytes. */
                zipStorePrevEntryLengthLarge(p+rawlen,rawlen); //更改数值
            } else {
                zipStorePrevEntryLength(p+rawlen,rawlen); //更改数值
            }

            /* Stop here, as the raw length of "next" has not changed. */
            break;
        }
    }
    return zl;
}
```

跟进 `zipStorePrevEntryLength()` `zipStorePrevEntryLengthLarge()`

```c
int zipStorePrevEntryLengthLarge(unsigned char *p, unsigned int len) {
    if (p != NULL) {
        p[0] = ZIP_BIG_PREVLEN;
        memcpy(p+1,&len,sizeof(len));
        memrev32ifbe(p+1);
    }
    return 1+sizeof(len);
}
```

```c
unsigned int zipStorePrevEntryLength(unsigned char *p, unsigned int len) {
    if (p == NULL) {
        return (len < ZIP_BIG_PREVLEN) ? 1 : sizeof(len)+1;
    } else {
        if (len < ZIP_BIG_PREVLEN) {
            p[0] = len;
            return 1;
        } else {
            return zipStorePrevEntryLengthLarge(p,len);
        }
    }
}
```

可以看出是根据参数len将prevlen域的内容写入p指向的内存，并返回1或5，即”长度“信息所占的长度

另外，前面的函数中用了很多次`intrev32ifbe`在endianconv.h定义

```c
#if (BYTE_ORDER == LITTLE_ENDIAN)
#define memrev16ifbe(p)
#define memrev32ifbe(p)
#define memrev64ifbe(p)
#define intrev16ifbe(v) (v)
#define intrev32ifbe(v) (v)
#define intrev64ifbe(v) (v)
#else
#define memrev16ifbe(p) memrev16(p)
#define memrev32ifbe(p) memrev32(p)
#define memrev64ifbe(p) memrev64(p)
#define intrev16ifbe(v) intrev16(v)
#define intrev32ifbe(v) intrev32(v)
#define intrev64ifbe(v) intrev64(v)
#endif
```

endian是字节存储顺序(字节序)的意思，big/little endian即大端序/小端序

[关于Big Endian 和 Little Endian](https://blog.csdn.net/sunshine1314/article/details/2309655) 可以看一下这篇博文

`__ziplistDelete()`，用于删除从p所指位置开始的num个节点

```c
unsigned char *__ziplistDelete(unsigned char *zl, unsigned char *p, unsigned int num) {
    unsigned int i, totlen, deleted = 0;
    size_t offset;
    int nextdiff = 0;
    zlentry first, tail;

    zipEntry(p, &first);
    for (i = 0; p[0] != ZIP_END && i < num; i++) {
        p += zipRawEntryLength(p); //让p指向待删除节点后第一个不被删除的节点
        deleted++;
    }

    totlen = p-first.p; /* 要删除的长度 */
    if (totlen > 0) {
        if (p[0] != ZIP_END) {
            /* Storing `prevrawlen` in this entry may increase or decrease the
             * number of bytes required compare to the current `prevrawlen`.
             * There always is room to store this, because it was previously
             * stored by an entry that is now being deleted. */
            nextdiff = zipPrevLenByteDiff(p,first.prevrawlen);//
            
            /* Note that there is always space when p jumps backward: if
             * the new previous entry is large, one of the deleted elements
             * had a 5 bytes prevlen header, so there is for sure at least
             * 5 bytes free and we need just 4. */
            p -= nextdiff;//根据first与p处节点的prevlen差值，为p的prevlen域留出足够空间
            zipStorePrevEntryLength(p,first.prevrawlen);

            /* 更新最后一个节点的偏移量 */
            ZIPLIST_TAIL_OFFSET(zl) =
                intrev32ifbe(intrev32ifbe(ZIPLIST_TAIL_OFFSET(zl))-totlen);

            /* When the tail contains more than one entry, we need to take
             * "nextdiff" in account as well. Otherwise, a change in the
             * size of prevlen doesn't have an effect on the *tail* offset. */
            zipEntry(p, &tail);
            if (p[tail.headersize+tail.len] != ZIP_END) {
                ZIPLIST_TAIL_OFFSET(zl) = //若p不是最后一个节点，则还要加nextdiff
                   intrev32ifbe(intrev32ifbe(ZIPLIST_TAIL_OFFSET(zl))+nextdiff);
            }

            /* Move tail to the front of the ziplist */
            memmove(first.p,p, //尾部左移，-1是因为zlend不需要处理
                intrev32ifbe(ZIPLIST_BYTES(zl))-(p-zl)-1);
        } else {
            /* 如果p后面全删完了，那前一个节点就是最后一个节点，据此更新尾偏移 */
            ZIPLIST_TAIL_OFFSET(zl) =
                intrev32ifbe((first.p-zl)-first.prevrawlen);
        }

        /* Resize and update length */
        offset = first.p-zl;
        zl = ziplistResize(zl, intrev32ifbe(ZIPLIST_BYTES(zl))-totlen+nextdiff);
        ZIPLIST_INCR_LENGTH(zl,-deleted);
        p = zl+offset;

        /* When nextdiff != 0, the raw length of the next entry has changed, so
         * we need to cascade the update throughout the ziplist */
        if (nextdiff != 0) //p的prevlen长度变了，要对其后节点级联更新
            zl = __ziplistCascadeUpdate(zl,p);
    }
    return zl;
}
```

`ziplistMerge`用于合并两块ziplist，将second的节点附加到first节点后

返回地址以两者较长的那个为基础，first较长，则向first后添加second的节点，second较长则向second节点前插入first的节点

```c
unsigned char *ziplistMerge(unsigned char **first, unsigned char **second) {
    //出错时返回NULL
    /* If any params are null, we can't merge, so NULL. */
    if (first == NULL || *first == NULL || second == NULL || *second == NULL)
        return NULL;

    /* Can't merge same list into itself. */
    if (*first == *second)
        return NULL;

    size_t first_bytes = intrev32ifbe(ZIPLIST_BYTES(*first));
    size_t first_len = intrev16ifbe(ZIPLIST_LENGTH(*first));

    size_t second_bytes = intrev32ifbe(ZIPLIST_BYTES(*second));
    size_t second_len = intrev16ifbe(ZIPLIST_LENGTH(*second));

    int append;
    unsigned char *source, *target;
    size_t target_bytes, source_bytes;
    /* Pick the largest ziplist so we can resize easily in-place.
     * We must also track if we are now appending or prepending to
     * the target ziplist. */
    if (first_len >= second_len) {	//确定主体和插入方式
        /* retain first, append second to first. */
        target = *first;
        target_bytes = first_bytes;
        source = *second;
        source_bytes = second_bytes;
        append = 1;
    } else {
        /* else, retain second, prepend first to second. */
        target = *second;
        target_bytes = second_bytes;
        source = *first;
        source_bytes = first_bytes;
        append = 0;
    }

    /* Calculate final bytes (subtract one pair of metadata) */
    size_t zlbytes = first_bytes + second_bytes -
                     ZIPLIST_HEADER_SIZE - ZIPLIST_END_SIZE;
    size_t zllength = first_len + second_len;

    /* Combined zl length should be limited within UINT16_MAX */
    zllength = zllength < UINT16_MAX ? zllength : UINT16_MAX;

    /* Save offset positions before we start ripping memory apart. */
    size_t first_offset = intrev32ifbe(ZIPLIST_TAIL_OFFSET(*first));
    size_t second_offset = intrev32ifbe(ZIPLIST_TAIL_OFFSET(*second));

    /* Extend target to new zlbytes then append or prepend source. */
    target = zrealloc(target, zlbytes);
    if (append) {
        /* append == appending to target */
        /* Copy source after target (copying over original [END]):
         *   [TARGET - END, SOURCE - HEADER] */
        memcpy(target + target_bytes - ZIPLIST_END_SIZE,
               source + ZIPLIST_HEADER_SIZE,
               source_bytes - ZIPLIST_HEADER_SIZE);
    } else {
        /* !append == prepending to target */
        /* Move target *contents* exactly size of (source - [END]),
         * then copy source into vacataed space (source - [END]):
         *   [SOURCE - END, TARGET - HEADER] */
        memmove(target + source_bytes - ZIPLIST_END_SIZE,
                target + ZIPLIST_HEADER_SIZE,
                target_bytes - ZIPLIST_HEADER_SIZE);
        memcpy(target, source, source_bytes - ZIPLIST_END_SIZE);
    }

    /* Update header metadata. */
    ZIPLIST_BYTES(target) = intrev32ifbe(zlbytes);
    ZIPLIST_LENGTH(target) = intrev16ifbe(zllength);
    /* New tail offset is:
     *   + N bytes of first ziplist
     *   - 1 byte for [END] of first ziplist
     *   + M bytes for the offset of the original tail of the second ziplist
     *   - J bytes for HEADER because second_offset keeps no header. */
    ZIPLIST_TAIL_OFFSET(target) = intrev32ifbe(
                                   (first_bytes - ZIPLIST_END_SIZE) +
                                   (second_offset - ZIPLIST_HEADER_SIZE));

    /* __ziplistCascadeUpdate just fixes the prev length values until it finds a
     * correct prev length value (then it assumes the rest of the list is okay).
     * We tell CascadeUpdate to start at the first ziplist's tail element to fix
     * the merge seam. */
    target = __ziplistCascadeUpdate(target, target+first_offset); //后半级联更新

    /* Now free and NULL out what we didn't realloc */
    if (append) {
        zfree(*second);
        *second = NULL;
        *first = target;
    } else {
        zfree(*first);
        *first = NULL;
        *second = target;
    }
    return target;
}
```



