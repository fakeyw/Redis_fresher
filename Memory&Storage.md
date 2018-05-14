# Memory&Storage

[TOC]

#### 内存

##### 00x01 zmalloc 内存分配 

---

redis本身没有实现内存池，其内存分配方式在预编译时确定<br>选择对象有libc的标准库、jemalloc与google的tcmalloc<br>其中jemalloc依赖在源码的dep中存在，其相对于glibc的malloc标准库的优势主要体现在避免内存碎片与并发扩展上<br>而tcmalloc则需要主动安装才能使用<br>

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



##### 00x02 ziplist 压缩列表

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



##### 00x03 skiplist 跳跃表

---

skiplist的数据实现定义在t_zset.c中，以zsl开头的函数为相关函数

跳跃表时以链表为基础改进的，结点的next指针可以有多个，除了指向临近的下一个外还可指向越过多个节点的后方节点，这样有序链表中查找时就有很大可能跳过中间多个节点，快速接近想要定位的节点

图示跳跃表能将链表查找所需时间降低到O(n/2)

<img src='/skiplist_div2.png' />

>Skip lists  are data structures  that use probabilistic  balancing rather  than  strictly  enforced balancing. As a result, the algorithms  for insertion  and deletion in skip lists  are much simpler and significantly  faster  than  equivalent  algorithms  for balanced trees.
>
>跳跃表使用概率均衡技术而不是使用强制性均衡，因此，对于插入和删除结点比传统上的平衡树算法更为简洁高效。

跳跃表可以粗略地理解为多层的链表，其底层是包含所有元素的有序链表。

每向多一层，就从下层元素中拿出头尾与随机选出的部分元素，并将其以指针连接。

<img src='/skiplist_divR.png' />

这也是skiplist被解释为probabilistic  balancing的原因

**Redis中的skiplist实现**

定义结构

节点中嵌套定义了一个zskiplistlevel的结构，用于存储某一层后继节点的地址与本层两节点之间的跨度

```c
//server.h
typedef struct zskiplistNode {
    sds ele; //sds类型 在sds.h中定义 'typedef char *sds;' 即字符串指针
    double score;
    struct zskiplistNode *backward; //前驱，只存在于最底层
    struct zskiplistLevel {
        struct zskiplistNode *forward; //后继
        unsigned int span; //节点跨度
    } level[]; //不定层级
} zskiplistNode;

typedef struct zskiplist {
    struct zskiplistNode *header, *tail;
    unsigned long length;
    int level;
} zskiplist;
```

> 关于 span ：指的是本节点到下一节点跟随指针走过的节点数，如头节点所有层span都为1

节点操作

`zslCreateNode()` `zslFreeNode()`

```c
zskiplistNode *zslCreateNode(int level, double score, sds ele) {
    zskiplistNode *zn =
        zmalloc(sizeof(*zn)+level*sizeof(struct zskiplistLevel));
    zn->score = score;			//按照节点所需层级分配空间
    zn->ele = ele;
    return zn;
}

void zslFreeNode(zskiplistNode *node) {
    sdsfree(node->ele);
    zfree(node);
}
```

跳跃表创建

这里只创建了单层链表，没有进一步创建跳跃结构

```c
#define ZSKIPLIST_MAXLEVEL 32 /* Should be enough for 2^32 elements */
zskiplist *zslCreate(void) {
    int j;
    zskiplist *zsl;

    zsl = zmalloc(sizeof(*zsl));
    zsl->level = 1;
    zsl->length = 0;
    zsl->header = zslCreateNode(ZSKIPLIST_MAXLEVEL,0,NULL);
    //创建一个32层的节点
    for (j = 0; j < ZSKIPLIST_MAXLEVEL; j++) {
        zsl->header->level[j].forward = NULL;	//初始化后继指针
        zsl->header->level[j].span = 0;			//跨度初始化为0
    }
    zsl->header->backward = NULL;
    zsl->tail = NULL;
    return zsl;
}
```

插入节点，涉及更高一层的创建

skiplist是一个有序链表，而这里的排序依据为score

```c
zskiplistNode *zslInsert(zskiplist *zsl, double score, sds ele) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    unsigned int rank[ZSKIPLIST_MAXLEVEL];
    int i, level;

    serverAssert(!isnan(score));
    x = zsl->header;
    //在每一层找到新节点的插入位置，是否插入不确定
    for (i = zsl->level-1; i >= 0; i--) {	//最高层开始逐层遍历
        /* store rank that is crossed to reach the insert position */
        rank[i] = i == (zsl->level-1) ? 0 : rank[i+1];//最外层rank初始为0，之后初始值继承上层rank
        while (x->level[i].forward && 					//指针非空
                (x->level[i].forward->score < score ||	  //当前指向节点的下一节点的score较小
                    (x->level[i].forward->score == score && 
                    sdscmp(x->level[i].forward->ele,ele) < 0))) //score相等但携带信息不同
        {	
            rank[i] += x->level[i].span; 
            x = x->level[i].forward;	//继续指向本层下一节点
        }
        //每层循环结束时，x指向的节点后方就是新节点的位置，每层的位置保存在update中
        //而rank[i]则累加到x指向节点的前一个节点的span
        //x前驱节点与头节点的距离
        update[i] = x;
        //这里不需要将x重新指向首部，可以在节点更密集的较下一层继续寻找位置
        //而这个位置必然在本轮的x与其后继节点之间
    }
    /* we assume the element is not already inside, since we allow duplicated
     * scores, reinserting the same element should never happen since the
     * caller of zslInsert() should test in the hash table if the element is
     * already inside or not. zslInsert() 的调用者会确保同分值且同成员的元素不会出现 */
    level = zslRandomLevel(); //据幂次定律得出一个层数，作为新节点的层数，并不影响其他节点
    if (level > zsl->level) {	//有新层出现时（可能不只一层）
        for (i = zsl->level; i < level; i++) {
            rank[i] = 0;	//初始化新层所需信息
            update[i] = zsl->header;
            update[i]->level[i].span = zsl->length;
        }
        zsl->level = level; //更新skiplist的最高层级
    }
    x = zslCreateNode(level,score,ele);
    for (i = 0; i < level; i++) { //在x与其后继间插入新节点
        x->level[i].forward = update[i]->level[i].forward;
        update[i]->level[i].forward = x;

        /* update span covered by update[i] as x is inserted here */
        //update[i]->level[i].span为原跨度，包括前驱到x、x到后继的长度
        //|rank[0] - rank[i]|为x实际位置(底层)前驱与本层前驱的差值，相减为x到后继在本层实际的span
        x->level[i].span = update[i]->level[i].span - (rank[0] - rank[i]);
        //更新x前驱结点span
        update[i]->level[i].span = (rank[0] - rank[i]) + 1;
    }

    /* increment span for untouched levels */
    for (i = level; i < zsl->level; i++) {
        update[i]->level[i].span++;
        //因为x的level为随机，可能有一些层不存在x元素，但跨度已经变更，所以需要更新
    }

    //更新前驱指针
    x->backward = (update[0] == zsl->header) ? NULL : update[0];
    if (x->level[0].forward)
        x->level[0].forward->backward = x;
    else
        zsl->tail = x;
    zsl->length++;
    return x;
}
```

其中获取随机level的函数

```c
#define ZSKIPLIST_MAXLEVEL 32 /* Should be enough for 2^32 elements */
#define ZSKIPLIST_P 0.25      /* Skiplist P = 1/4 */
int zslRandomLevel(void) {
    int level = 1;
    while ((random()&0xFFFF) < (ZSKIPLIST_P * 0xFFFF))
        level += 1;
    return (level<ZSKIPLIST_MAXLEVEL) ? level : ZSKIPLIST_MAXLEVEL;
}
```

设ZSKIPLIST_P = a，达到后一层的概率都为a，则达到本层(不是等于)的概率：

| 层数(x) | 概率p(x) |
| :-----: | :------: |
|    1    |    1     |
|    2    |    a     |
|    3    |   a^2    |
|    4    |   a^3    |
|   ...   |   ...    |
|    k    | a^(k-1)  |

$$
\begin{align}
PointerCost &= \sum_\infty^1p(x)\\
&=\sum_\infty^1a^{x-1}\\
&=\lim_{x\overrightarrow{}\infty}1+a+a^2+\cdots+a^{x-1}\\
&=\lim_{x\overrightarrow{}\infty}\frac{1-a^x}{1-a}\\
&=\frac{1}{1-a}
\end{align}
$$

redis中默认设置p为0.25，则每个节点约占有1.33个指针(不包括前驱)，内存空间额外消耗较小，同时也有效提高了搜索速度。

删除操作

```c
void zslDeleteNode(zskiplist *zsl, zskiplistNode *x, zskiplistNode **update) {
    int i;	//x是要删除的节点
    for (i = 0; i < zsl->level; i++) { //逐层遍历更新update节点(删除节点的前节点)信息
        if (update[i]->level[i].forward == x) {
            update[i]->level[i].span += x->level[i].span - 1;
            update[i]->level[i].forward = x->level[i].forward;
        } else {
            update[i]->level[i].span -= 1;
        }
    }
    if (x->level[0].forward) {	//补全前驱指针
        x->level[0].forward->backward = x->backward;
    } else {
        zsl->tail = x->backward;
    }
    while(zsl->level > 1 && zsl->header->level[zsl->level-1].forward == NULL)
        zsl->level--;	//更新层级
    zsl->length--;
}

int zslDelete(zskiplist *zsl, double score, sds ele, zskiplistNode **node) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    int i;

    x = zsl->header;	//从顶层开始遍历，找出每层要删除节点的前驱
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward &&
                (x->level[i].forward->score < score ||
                    (x->level[i].forward->score == score &&
                     sdscmp(x->level[i].forward->ele,ele) < 0)))
        {
            x = x->level[i].forward;
        }
        update[i] = x;
    }
    /* We may have multiple elements with the same score, what we need
     * is to find the element with both the right score and object. */
    x = x->level[0].forward; //将x修正指向要删除的节点
    if (x && score == x->score && sdscmp(x->ele,ele) == 0) {
        zslDeleteNode(zsl, x, update);
        if (!node)
            zslFreeNode(x);
        else
            *node = x;
        return 1;
    }
    return 0; /* not found */
}
```

区间操作(之一)  按score区间删除

```c
typedef struct {	//range定义结构
    double min, max;
    int minex, maxex; /* are min or max exclusive? */
} zrangespec;

unsigned long zslDeleteRangeByScore(zskiplist *zsl, zrangespec *range, dict *dict) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    unsigned long removed = 0;
    int i;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {	//记录要删除的一组节点中，第一个节点的前驱
        while (x->level[i].forward && (range->minex ?
            x->level[i].forward->score <= range->min :
            x->level[i].forward->score < range->min))
                x = x->level[i].forward;
        update[i] = x;
    }

    /* Current node is the last with score < or <= min. */
    x = x->level[0].forward;	//修正x指向第一个要删除的节点

    /* Delete nodes while in range. */
    while (x &&	//逐个向后删除
           (range->maxex ? x->score < range->max : x->score <= range->max))
    {
        zskiplistNode *next = x->level[0].forward;
        zslDeleteNode(zsl,x,update);
        dictDelete(dict,x->ele);
        zslFreeNode(x); /* Here is where x->ele is actually released. */
        removed++;
        x = next;
    }
    return removed; //返回值为删除节点的数量
}
```

#### 存储

##### 00x04 数据库实现

---

> 建议先了解各数据类型与命令实现

redis数据库的结构，定义在server.h中

```c
typedef struct redisDb {
    //记录所有的数据结构的键值对 str - robj
    dict *dict;                 /* The keyspace for this DB */
    //记录过期时间，由EXPIRE命令设定
    //string类型也可由SETEX命令在生成的同时设定
    dict *expires;              /* Timeout of keys with a timeout set */
    //与阻塞操作相关
    //dict中的key为造成client阻塞的键，value为所有被该键阻塞的client构成的链表
    dict *blocking_keys;        /* Keys with clients waiting for data (BLPOP)*/
    //key为阻塞中的键，value为NULL，与解阻塞的操作相关
    dict *ready_keys;           /* Blocked keys that received a PUSH */
    //保存watch命令监视的键
    dict *watched_keys;         /* WATCHED keys for MULTI/EXEC CAS */
    int id;                     /* Database ID */
    //键的平均过期时间
    long long avg_ttl;          /* Average TTL, just for stats */
} redisDb;

//server.c 数据库dict结构
dictType dbDictType = {
   dictSdsHash,                /* hash function */
   NULL,                       /* key dup */
   NULL,                       /* val dup */
   dictSdsKeyCompare,          /* key compare */
   dictSdsDestructor,          /* key destructor */
   dictObjectDestructor   /* val destructor */
};
```

redisDb对象保存在client与redisServer对象中

> 这里的client不是实际的客户端，是server接收到连接后对客户端当前状态的建模，也包括虚拟客户端(Lua脚本)
>
> 实际的客户端由redis-cli.c实现

```c
typedef struct client {
    uint64_t id;            /* Client incremental unique ID. */
    int fd;                 /* Client socket. */
    redisDb *db;            /* Pointer to currently SELECTed DB. */
    /*	...
    	...
    	...	 */
} client;

struct redisServer {
    /* General */
    pid_t pid;                  /* Main process pid. */
    char *configfile;           /* Absolute config file path, or NULL */
    char *executable;           /* Absolute executable file path. */
    char **exec_argv;           /* Executable argv vector (copy). */
    int hz;                     /* serverCron() calls frequency in hertz */
    redisDb *db;
    /*	...
    	...
    	...	 */
};
```

**数据库创建**

服务器启动时，会默认创建一个长度为16的redisDb指针数组

用户登陆后，client当前数据库默认指针指向db[0]

```c
//server.c
void initServer(void) {
   /*	...
    	...	 */
    server.db = zmalloc(sizeof(redisDb)*server.dbnum);
   	/*	...
    	...	 */
}
```

**数据库切换**

对于创建的多个数据库，client可以用SELECT (index)命令切换

```c
//db.c
int selectDb(client *c, int id) {
    //检测id范围
    if (id < 0 || id >= server.dbnum)
        return C_ERR;
    //更新指针
    c->db = &server.db[id];
    return C_OK;
}
```

**数据操作**

所有数据的键值对都保存在db->dict中，key为对象名称，类型为string，value为保存的数据的结构，类型为string，list，hash，set，zset中的一种。

添加新键值对到数据库/更改某key对应的value对象

```c
void dbAdd(redisDb *db, robj *key, robj *val) {
    sds copy = sdsdup(key->ptr);  //从key robj复制出字符串
    int retval = dictAdd(db->dict, copy, val);  //记录新k-v到dict中

    serverAssertWithInfo(NULL,key,retval == DICT_OK);
    //与解阻塞有关，会将此list对象的key存入db->ready_keys中
    if (val->type == OBJ_LIST) signalListAsReady(db, key);
    if (server.cluster_enabled) slotToKeyAdd(key);  //集群相关
 }

void dbOverwrite(redisDb *db, robj *key, robj *val) {
    dictEntry *de = dictFind(db->dict,key->ptr);  //找到原key

    serverAssertWithInfo(NULL,key,de != NULL);
    //检查内存清理策略
    if (server.maxmemory_policy & MAXMEMORY_FLAG_LFU) {
        robj *old = dictGetVal(de);
        int saved_lru = old->lru;  //value的替换不会更新lru
        dictReplace(db->dict, key->ptr, val);
        val->lru = saved_lru;
        /* LFU should be not only copied but also updated
         * when a key is overwritten. */
        updateLFU(val);
    } else {
        dictReplace(db->dict, key->ptr, val);
    }
}
```

修改数据对象

为保证数据操作的安全性，需要获取数据时会用db.c中定义的`lookupKeyRead()`,`lookupKeyWrite()`，`lookupKeyWriteorReply()`等函数来取出对象

lookupKey()是这些函数的底层实现

```c
robj *lookupKey(redisDb *db, robj *key, int flags) {
    dictEntry *de = dictFind(db->dict,key->ptr);
    if (de) {
        robj *val = dictGetVal(de);  //取出value

        /* Update the access time for the ageing algorithm.
         * Don't do it if we have a saving child, as this will trigger
         * a copy on write madness. */
        if (server.rdb_child_pid == -1 &&
            server.aof_child_pid == -1 &&
            !(flags & LOOKUP_NOTOUCH))
        {	//更新LRU记录
            if (server.maxmemory_policy & MAXMEMORY_FLAG_LFU) {
                updateLFU(val);
            } else {
                val->lru = LRU_CLOCK();
            }
        }
        return val;
    } else {
        return NULL;  //未找到对象时返回NULL
    }
}
```

lookupKeyRead()调用的是lookupKeyReadWithFlags()，后者会将参数中的flag传入lookupKey()

```c
//server.h
#define LOOKUP_NONE 0
#define LOOKUP_NOTOUCH (1<<0)

//这里的flag只有两个值 0 / 1
//lookupKeyRead()使用LOOKUP_NONE，不进行特殊处理(会正常更新LRU)
//LOOKUP_NOTOUCH 则表示不更新LRU，有时会取出数据但不是为了读或写，即不进行引用与操作
//这时，LRU并不需要被更新，就会使用这个flag
//有expire.c中的ttlGenericCommand() 与db.c中的typeCommand()

//db.c
robj *lookupKeyReadWithFlags(redisDb *db, robj *key, int flags) {
    robj *val;
	
    //检查key是否过期(此时查到过期会直接将此对象删除)
    if (expireIfNeeded(db,key) == 1) {	
        /* Key expired. If we are in the context of a master, expireIfNeeded()
         * returns 0 only when the key does not exist at all, so it's safe
         * to return NULL ASAP. */
        //如果处于主节点的上下文(环境)，则这个key与其对象已被彻底删除
        if (server.masterhost == NULL) return NULL;

        /* However if we are in the context of a slave, expireIfNeeded() will
         * not really try to expire the key, it only returns information
         * about the "logical" status of the key: key expiring is up to the
         * master in order to have a consistent view of master's data set.
         *
         * However, if the command caller is not the master, and as additional
         * safety measure, the command invoked is a read-only command, we can
         * safely return NULL here, and provide a more consistent behavior
         * to clients accessign expired values in a read-only fashion, that
         * will say the key as non exisitng.
         *
         * Notably this covers GETs when slaves are used to scale reads. */
        //如果处于从节点上下文(环境)
        //expireIfNeeded()不会真正地使key失效，只返回这个key是否被删除的逻辑值
        //为保持数据一致性，key的失效由主节点管理
        //原文中的accessign大概是作者手滑打错，应该是accessing 访问
        if (server.current_client &&
            server.current_client != server.master &&
            //server.h
            //struct redisCommand *cmd, *lastcmd;  /* Last command executed. */
            //最后一条执行的命令记录不可修改，是附加的保持一致性的手段
            //处于从节点环境且命令记录只读时，可安全地返回NULL
            server.current_client->cmd &&
            server.current_client->cmd->flags & CMD_READONLY)
        {
            return NULL;
        }
    }
    val = lookupKey(db,key,flags);
    //记录key命中情况
    if (val == NULL)
        server.stat_keyspace_misses++;
    else
        server.stat_keyspace_hits++;
    return val;
}
```

只有在读的时候才会记录命中情况，而以写操作取对象的时候不需要记录

**数据过期**

有关过期设置的函数与命令定义在expire.c中

EXPIRE，PEXPIRE，EXPIREAT与PEXPIREAT这四个命令可为key设置过期时间，超时失效

底层实现为expireGenericCommand()

```c
void expireGenericCommand(client *c, long long basetime, int unit) {
    robj *key = c->argv[1], *param = c->argv[2];
    long long when; /* unix time in milliseconds when the key will expire. */
	
    //取出param中的时间存入变量when中
    if (getLongLongFromObjectOrReply(c, param, &when, NULL) != C_OK)
        return;

    //命令中的设置的时间概念可能是绝对的也可能是相对的
    //basetime为相对时间的基准值
    if (unit == UNIT_SECONDS) when *= 1000; //秒转毫秒
    when += basetime;  //修正时间

    /* No key, return zero. */
    //检查key是否存在
    if (lookupKeyWrite(c->db,key) == NULL) {
        addReply(c,shared.czero);
        return;
    }

    /* EXPIRE with negative TTL, or EXPIREAT with a timestamp into the past
     * should never be executed as a DEL when load the AOF or in the context
     * of a slave instance.
     *
     * Instead we take the other branch of the IF statement setting an expire
     * (possibly in the past) and wait for an explicit DEL from the master. */
    //检查过期时间的合法性，不合法会删除
    //但是删除操作不应该在AOF恢复时进行，也不可在从节点环境中进行
    if (when <= mstime() && !server.loading && !server.masterhost) {
        robj *aux;
		
        //lazyfree是redis4.0后引入的机制
        //开启了lazyfree之后，将先从逻辑上删除键值对，实际的数据清理由后台线程操作
        //这种模式是为了防止某键数据过大引起的长时间阻塞
        //(所以这不还是要靠并发嘛)
        int deleted = server.lazyfree_lazy_expire ? dbAsyncDelete(c->db,key) :
                                                    dbSyncDelete(c->db,key);
        serverAssertWithInfo(c,key,deleted);
        server.dirty++;

        /* Replicate/AOF this as an explicit DEL or UNLINK. */
        aux = server.lazyfree_lazy_expire ? shared.unlink : shared.del;
        //将过期命令记录修改为逻辑删除/删除命令
        rewriteClientCommandVector(c,2,aux,key);
        signalModifiedKey(c->db,key);
        notifyKeyspaceEvent(NOTIFY_GENERIC,"del",key,c->db->id);
        addReply(c, shared.cone);
        return;
    } else {
        //正常设置超时时间
        setExpire(c,c->db,key,when);
        addReply(c,shared.cone);
        signalModifiedKey(c->db,key);
        notifyKeyspaceEvent(NOTIFY_GENERIC,"expire",key,c->db->id);
        server.dirty++;
        return;
    }
}
```

TTL，PTTL命令底层实现

```c
void ttlGenericCommand(client *c, int output_ms) {
    long long expire, ttl = -1;

    /* If the key does not exist at all, return -2 */
    //命令用于查看key的剩余生存时间，既不读也不写，所以带LOOKUP_NOTOUCH标志
    if (lookupKeyReadWithFlags(c->db,c->argv[1],LOOKUP_NOTOUCH) == NULL) {
        addReplyLongLong(c,-2);
        return;
    }
    /* The key exists. Return -1 if it has no expire, or the actual
     * TTL value otherwise. */
    expire = getExpire(c->db,c->argv[1]);
    if (expire != -1) {  //计算剩余时间
        ttl = expire-mstime();
        if (ttl < 0) ttl = 0;
    }
    if (ttl == -1) {
        addReplyLongLong(c,-1);
    } else {
        //output_ms 0:以秒位单位，1:以毫秒为单位 （+500向上舍入)
        addReplyLongLong(c,output_ms ? ttl : ((ttl+500)/1000));
    }
}
```

**数据库操作命令实现**

添加键值对的操作只能由PUSH SET等命令执行时调用

但DEL命令(或UNLINK)可独立执行，底层实现

```c
void delGenericCommand(client *c, int lazy) {
    int numdel = 0, j;
	
    //遍历命令中所有key
    for (j = 1; j < c->argc; j++) {
        //过期失效
        expireIfNeeded(c->db,c->argv[j]);
        int deleted  = lazy ? dbAsyncDelete(c->db,c->argv[j]) :
                              dbSyncDelete(c->db,c->argv[j]);
        //删除成功则发送信号与通知
        if (deleted) {
            signalModifiedKey(c->db,c->argv[j]);
            notifyKeyspaceEvent(NOTIFY_GENERIC,
                "del",c->argv[j],c->db->id);
            server.dirty++;	//更新脏键
            numdel++;	//记录删除key的数量
        }
    }
    //向客户端返回信息
    addReplyLongLong(c,numdel);
}
```

SCAN类命令的底层实现

包括SCAN，HSCAN，SSCAN与ZSCAN

```c
void scanGenericCommand(client *c, robj *o, unsigned long cursor) {
    int i, j;
    list *keys = listCreate();
    listNode *node, *nextnode;
    long count = 10;
    sds pat = NULL;
    int patlen = 0, use_pattern = 0;
    dict *ht;
	
    //传入的o必须是hash，set或zset
    //分别用于SSCAN，HSCAN与ZSCAN
    /* Object must be NULL (to iterate keys names), or the type of the object
     * must be Set, Sorted Set, or Hash. */
    serverAssert(o == NULL || o->type == OBJ_SET || o->type == OBJ_HASH ||
                o->type == OBJ_ZSET);
    
    /* Set i to the first option argument. The previous one is the cursor. */
    //o不为NULL时，第一个参数为目标对象的key
    //为NULL时迭代的是数据库中的键值对，没有key参数，其他参数下标从2开始
    i = (o == NULL) ? 2 : 3; /* Skip the key argument if needed. */

    /* Step 1: Parse options. */
    while (i < c->argc) {
        j = c->argc - i;
        //设置每次迭代返回的元素个数count
        //但迭代对象编码为intset或ziplist时，此选项无效
        if (!strcasecmp(c->argv[i]->ptr, "count") && j >= 2) {
            if (getLongFromObjectOrReply(c, c->argv[i+1], &count, NULL)
                != C_OK)
                
            {
                goto cleanup;
            }

            if (count < 1) {
                addReply(c,shared.syntaxerr);
                goto cleanup;
            }

            i += 2;
        //匹配选项，内容为通配符
        } else if (!strcasecmp(c->argv[i]->ptr, "match") && j >= 2) {
            pat = c->argv[i+1]->ptr;
            patlen = sdslen(pat);

            /* The pattern always matches if it is exactly "*", so it is
             * equivalent to disabling it. */
            //只有一个*，即匹配所有，与不进行匹配等效
            use_pattern = !(pat[0] == '*' && patlen == 1);

            i += 2;
        } else {
            addReply(c,shared.syntaxerr);
            goto cleanup;
        }
    }

    /* Step 2: Iterate the collection.
     *
     * Note that if the object is encoded with a ziplist, intset, or any other
     * representation that is not a hash table, we are sure that it is also
     * composed of a small number of elements. So to avoid taking state we
     * just return everything inside the object in a single call, setting the
     * cursor to zero to signal the end of the iteration. */
	//编码为intset或ziplist的对象元素较少
    //执行命令时将无视count命令将所有元素(包括k，v)全部发挥给客户端
    
    /* Handle the case of a hash table. */
    //处理元素较多的，带有hashtable结构的数据类型
    ht = NULL;
    if (o == NULL) {
        ht = c->db->dict;
    } else if (o->type == OBJ_SET && o->encoding == OBJ_ENCODING_HT) {
        ht = o->ptr;
    } else if (o->type == OBJ_HASH && o->encoding == OBJ_ENCODING_HT) {
        ht = o->ptr;
        count *= 2; /* We return key / value for this type. */
    } else if (o->type == OBJ_ZSET && o->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = o->ptr;
        ht = zs->dict;
        count *= 2; /* We return key / value for this type. */
    }
	
    //所有带有hashtable的数据类型
    if (ht) {
        void *privdata[2];
        /* We set the max number of iterations to ten times the specified
         * COUNT, so if the hash table is in a pathological state (very
         * sparsely populated) we avoid to block too much time at the cost
         * of returning no or very few elements. */
        //设置迭代上限为count*10
        //在hashtable出现问题的状况下，以此避免的长时间阻塞后只能返回极少元素
        long maxiterations = count*10;

        /* We pass two pointers to the callback: the list to which it will
         * add new elements, and the object containing the dictionary so that
         * it is possible to fetch more data in a type-dependent way. */
        privdata[0] = keys;
        privdata[1] = o;
        do {
            //从cursor位置开始，逐个用scanCallback将ht中的key提取到列表keys中
            //privdata中的o仅用于判断对象数据类型
            cursor = dictScan(ht, cursor, scanCallback, NULL, privdata);
        } while (cursor &&
              maxiterations-- &&
              listLength(keys) < (unsigned long)count);
   	//encoding为intset的set对象
    } else if (o->type == OBJ_SET) {
        int pos = 0;
        int64_t ll;

        while(intsetGet(o->ptr,pos++,&ll))	//从intset中取对象放入ll
            listAddNodeTail(keys,createStringObjectFromLongLong(ll));
        cursor = 0;	//迭代结束(无视count)
    //encoding为ziplist的hash对象与zset对象
    } else if (o->type == OBJ_HASH || o->type == OBJ_ZSET) {
        unsigned char *p = ziplistIndex(o->ptr,0);
        unsigned char *vstr;
        unsigned int vlen;
        long long vll;

        while(p) {
            ziplistGet(p,&vstr,&vlen,&vll);
            listAddNodeTail(keys,
                (vstr != NULL) ? createStringObject((char*)vstr,vlen) :
                                 createStringObjectFromLongLong(vll));
            p = ziplistNext(o->ptr,p);
        }
        cursor = 0;  //迭代结束
    } else {  //无法应用SCAN类命令的对象
        serverPanic("Not handled encoding in SCAN.");
    }

    /* Step 3: Filter elements. */
    node = listFirst(keys);  //listFirst是一个宏函数，返回list的头节点指针
    while (node) {
        robj *kobj = listNodeValue(node);  //取key
        nextnode = listNextNode(node);     //指向下个节点的指针
        int filter = 0;

        /* Filter element if it does not match the pattern. */
        //(为什么不在取的过程中过滤呢?)
        if (!filter && use_pattern) {
           //如果key是个字符串
            if (sdsEncodedObject(kobj)) {
                //与pattern不匹配时设置过滤标记
                if (!stringmatchlen(pat, patlen, kobj->ptr, sdslen(kobj->ptr), 0))
                    filter = 1;
            //key是整数
            } else { 
                char buf[LONG_STR_SIZE];
                int len;
                
                serverAssert(kobj->encoding == OBJ_ENCODING_INT);
                //先将整数转换为字符串，再匹配
                len = ll2string(buf,sizeof(buf),(long)kobj->ptr);
                if (!stringmatchlen(pat, patlen, buf, len, 0)) filter = 1;
            }
        }

        /* Filter element if it is an expired key. */
        //迭代对象为数据库时，如果key过期则会过滤掉
        if (!filter && o == NULL && expireIfNeeded(c->db, kobj)) filter = 1;

        /* Remove the element and its associted value if needed. */
        //如果确认这个key需要被过滤，则将其从keys中删除
        if (filter) {
            decrRefCount(kobj);
            listDelNode(keys, node);
        }

        /* If this is a hash or a sorted set, we have a flat list of
         * key-value elements, so if this element was filtered, remove the
         * value, or skip it if it was not filtered: we only match keys. */
        //迭代对象为ziplist编码的hash和zset对象
        if (o && (o->type == OBJ_ZSET || o->type == OBJ_HASH)) {
            node = nextnode;
            nextnode = listNextNode(node);
            if (filter) {
                kobj = listNodeValue(node);
                decrRefCount(kobj);
                listDelNode(keys, node);
            }
        }
        node = nextnode;
    }

    /* Step 4: Reply to the client. */
    //发送信号，消息，向客户端返回信息
    addReplyMultiBulkLen(c, 2);
    addReplyBulkLongLong(c,cursor);

    addReplyMultiBulkLen(c, listLength(keys));
    while ((node = listFirst(keys)) != NULL) {
        robj *kobj = listNodeValue(node);
        addReplyBulk(c, kobj);
        decrRefCount(kobj);
        listDelNode(keys, node);
    }

cleanup:
    listSetFreeMethod(keys,decrRefCountVoid);
    listRelease(keys);
}
```

RENAME，RENAMEX底层实现

```c
void renameGenericCommand(client *c, int nx) {
    robj *o;
    long long expire;
    int samekey = 0;

    /* When source and dest key is the same, no operation is performed,
     * if the key exists, however we still return an error on unexisting key. */
    //新旧键名相同，更改samekey标志
    if (sdscmp(c->argv[1]->ptr,c->argv[2]->ptr) == 0) samekey = 1;
	
    //以写操作取对象
    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.nokeyerr)) == NULL)
        return;

    if (samekey) {
        addReply(c,nx ? shared.czero : shared.ok);
        return;
    }
	
    //先增加待操作value对象的引用计数，防止删除key条目导致value对象被清除
    incrRefCount(o);  
    //备份旧key的过期时间，之后将作为新key的过期时间使用
    expire = getExpire(c->db,c->argv[1]);
    //检查新key是否存在，与nx标志(不存在)是否冲突
    if (lookupKeyWrite(c->db,c->argv[2]) != NULL) {
        if (nx) { //冲突则结束命令
            decrRefCount(o);
            addReply(c,shared.czero);
            return;
        }
        /* Overwrite: delete the old key before creating the new one
         * with the same name. */
        dbDelete(c->db,c->argv[2]);  //无nx则删除之前存在的新key条目
    }
    dbAdd(c->db,c->argv[2],o);  //以新key存入value对象
    if (expire != -1) setExpire(c,c->db,c->argv[2],expire);  //设置过期时间
    dbDelete(c->db,c->argv[1]);  //删除旧key
    //发送两个键被修改的信号
    signalModifiedKey(c->db,c->argv[1]);
    signalModifiedKey(c->db,c->argv[2]);
    notifyKeyspaceEvent(NOTIFY_GENERIC,"rename_from",
        c->argv[1],c->db->id);
    notifyKeyspaceEvent(NOTIFY_GENERIC,"rename_to",
        c->argv[2],c->db->id);
    server.dirty++;  //更新脏键
    addReply(c,nx ? shared.cone : shared.ok);
}
```

##### 00x05 RDB持久化

---

RDB模式的持久化是将当前数据生成快照存入硬盘

**优点**

.rdb文件为经过较强压缩的二进制文件，适合转移与复制

因为恢复时只需要读出键值对存入工作内存，所以速度比AOF模式高很多

**缺点**

不同redis版本中.rdb文件的编排方式可能不一致，不过问题不大

每次执行持久化，目标范围都是全部数据，即使调用fork()放在后台操作也将占用大量资源，时间也较长。所以不可能实现高频的持久化，更不可能做到实时备份。

**触发**

有主动和被动两种触发方式

- 主动

  SAVE，BGSAVE命令，其中BGSAVE为并发后台处理

- 被动

  在配置文件中默认有 `save 900 1` `save 300 10` `save 60 1000 ` 等条目，`save M N` 代表计时M秒内对数据库进行了N次修改将触发RDB持久化

  也可用CONFIG SET命令更改配置

**存储方式**

中间结构

```c
typedef struct rdbSaveInfo {
    /* Used saving and loading. */
    int repl_stream_db;  /* DB to select in server.master client. */

    /* Used only loading. */
    int repl_id_is_set;  /* True if repl_id field is set. */
    char repl_id[CONFIG_RUN_ID_SIZE+1];     /* Replication ID. */
    long long repl_offset;                  /* Replication offset. */
} rdbSaveInfo;
```

将rdb文件写入rio中

> rdb文件结构
>
> | "REDIS" | 版本    | 默认辅助信息 | 数据 | EOF    | 校验和  |
> | ------- | ------- | ------------ | ---- | ------ | ------- |
> | 5 bytes | 4 bytes | 不定         | 不定 | 1 byte | 8 bytes |

```c
int rdbSaveRio(rio *rdb, int *error, int flags, rdbSaveInfo *rsi) {
    dictIterator *di = NULL;
    dictEntry *de;
    char magic[10];
    int j;
    long long now = mstime();
    uint64_t cksum;
    size_t processed = 0;
	
    //开启校验和
    if (server.rdb_checksum)
        //设置校验和使用的函数
        rdb->update_cksum = rioGenericUpdateChecksum;
    //向magic中写入redis版本信息
    snprintf(magic,sizeof(magic),"REDIS%04d",RDB_VERSION);
    //将magic写入rio
    if (rdbWriteRaw(rdb,magic,9) == -1) goto werr;
    //将rdb文件辅助信息写入rio
    if (rdbSaveInfoAuxFields(rdb,flags,rsi) == -1) goto werr;

    //遍历所有数据库
    for (j = 0; j < server.dbnum; j++) {
        redisDb *db = server.db+j;
        dict *d = db->dict;
        //跳过空数据库
        if (dictSize(d) == 0) continue;
        di = dictGetSafeIterator(d);
        if (!di) return C_ERR;

        /* Write the SELECT DB opcode */
        //写入选择数据库操作码
        if (rdbSaveType(rdb,RDB_OPCODE_SELECTDB) == -1) goto werr;
        //写入数据库id
        if (rdbSaveLen(rdb,j) == -1) goto werr;

        /* Write the RESIZE DB opcode. We trim the size to UINT32_MAX, which
         * is currently the largest type we are able to represent in RDB sizes.
         * However this does not limit the actual size of the DB to load since
         * these sizes are just hints to resize the hash tables. */
        uint32_t db_size, expires_size;
        //字典大小大于UINT32_MAX，则db_size设置为最大值UINT32_MAX
        //但这不是实际数据库大小，而是作为重新调整hashtable的标志
        db_size = (dictSize(db->dict) <= UINT32_MAX) ?
                                dictSize(db->dict) :
                                UINT32_MAX;
        //过期时间大小作类似处理
        expires_size = (dictSize(db->expires) <= UINT32_MAX) ?
                                dictSize(db->expires) :
                                UINT32_MAX;
        //写入resize的操作码
        if (rdbSaveType(rdb,RDB_OPCODE_RESIZEDB) == -1) goto werr;
        //写入前面确定的两个值
        if (rdbSaveLen(rdb,db_size) == -1) goto werr;
        if (rdbSaveLen(rdb,expires_size) == -1) goto werr;

        /* Iterate this DB writing every entry */
        //遍历当前数据库的键值对
        while((de = dictNext(di)) != NULL) {
            sds keystr = dictGetKey(de);
            robj key, *o = dictGetVal(de);
            long long expire;

            //宏函数，关联key与sds类型的keystr作为key对象
            initStaticStringObject(key,keystr);
            //获取key的过期时间
            expire = getExpire(db,&key);
            //写入键值对与过期时间
            if (rdbSaveKeyValuePair(rdb,&key,o,expire,now) == -1) goto werr;

            /* When this RDB is produced as part of an AOF rewrite, move
             * accumulated diff from parent to child while rewriting in
             * order to have a smaller final write. */
            //当这个RDB持久化操作是在AOF恢复的过程中执行的时侯，
            //子进程会从父进程中读取积累的差异变化到一个缓冲区中
            //在恢复的最后会一并进行处理
            //(不知道是否正确)
            if (flags & RDB_SAVE_AOF_PREAMBLE &&
                rdb->processed_bytes > processed+AOF_READ_DIFF_INTERVAL_BYTES)
            {
                processed = rdb->processed_bytes;
                aofReadDiffFromParent();
            }
        }
        dictReleaseIterator(di);
    }
    di = NULL; /* So that we don't release it again on error. */

    /* If we are storing the replication information on disk, persist
     * the script cache as well: on successful PSYNC after a restart, we need
     * to be able to process any EVALSHA inside the replication backlog the
     * master will send us. */
    //保存脚本
    if (rsi && dictSize(server.lua_scripts)) {
        di = dictGetIterator(server.lua_scripts);
        while((de = dictNext(di)) != NULL) {
            robj *body = dictGetVal(de);
            if (rdbSaveAuxField(rdb,"lua",3,body->ptr,sdslen(body->ptr)) == -1)
                goto werr;
        }
        dictReleaseIterator(di);
    }

    /* EOF opcode */
    //写入结束符 255
    if (rdbSaveType(rdb,RDB_OPCODE_EOF) == -1) goto werr;

    /* CRC64 checksum. It will be zero if checksum computation is disabled, the
     * loading code skips the check in this case. */
    //计算，写入校验和
    cksum = rdb->cksum;
    memrev64ifbe(&cksum);
    if (rioWrite(rdb,&cksum,8) == 0) goto werr;
    return C_OK;

werr:
    //保存错误码
    if (error) *error = errno;
    if (di) dictReleaseIterator(di);
    return C_ERR;
}
```

默认辅助信息

```c
int rdbSaveInfoAuxFields(rio *rdb, int flags, rdbSaveInfo *rsi) {
    //判断主机总线宽度
    int redis_bits = (sizeof(void*) == 8) ? 64 : 32;
    int aof_preamble = (flags & RDB_SAVE_AOF_PREAMBLE) != 0;

    /* Add a few fields about the state when the RDB was created. */
    //写入状态信息，版本，位数，当前时间，已使用内存
    if (rdbSaveAuxFieldStrStr(rdb,"redis-ver",REDIS_VERSION) == -1) return -1;
    if (rdbSaveAuxFieldStrInt(rdb,"redis-bits",redis_bits) == -1) return -1;
    if (rdbSaveAuxFieldStrInt(rdb,"ctime",time(NULL)) == -1) return -1;
    if (rdbSaveAuxFieldStrInt(rdb,"used-mem",zmalloc_used_memory()) == -1) return -1;

    /* Handle saving options that generate aux fields. */
    //处理生成辅助域的选项
    if (rsi) {
        if (rdbSaveAuxFieldStrInt(rdb,"repl-stream-db",rsi->repl_stream_db)
            == -1) return -1;
        if (rdbSaveAuxFieldStrStr(rdb,"repl-id",server.replid)
            == -1) return -1;
        if (rdbSaveAuxFieldStrInt(rdb,"repl-offset",server.master_repl_offset)
            == -1) return -1;
    }
    if (rdbSaveAuxFieldStrInt(rdb,"aof-preamble",aof_preamble) == -1) return -1;
    return 1;
}
```

**执行**

持久化底层实现

```c
int rdbSave(char *filename, rdbSaveInfo *rsi) {
    char tmpfile[256];
    char cwd[MAXPATHLEN]; /* Current working dir path for error messages. */
    FILE *fp;
    rio rdb;
    int error = 0;
	
    //将文件名写入tmpfile中
    snprintf(tmpfile,256,"temp-%d.rdb", (int) getpid());
    fp = fopen(tmpfile,"w");
    //文件无法打开
    if (!fp) {
        //获取当前路径，报错，写入日志
        char *cwdp = getcwd(cwd,MAXPATHLEN);
        serverLog(LL_WARNING,
            "Failed opening the RDB file %s (in server root dir %s) "
            "for saving: %s",
            filename,
            cwdp ? cwdp : "unknown",
            strerror(errno));
        return C_ERR;
    }

    //将二进制数据写入文件
    rioInitWithFile(&rdb,fp);
    if (rdbSaveRio(&rdb,&error,RDB_SAVE_NONE,rsi) == C_ERR) {
        errno = error;
        //报存失败进入错误处理流程
        goto werr;
    }

    /* Make sure data will not remain on the OS's output buffers */
    //清空缓冲区，释放资源
    if (fflush(fp) == EOF) goto werr;
    if (fsync(fileno(fp)) == -1) goto werr;
    if (fclose(fp) == EOF) goto werr;

    /* Use RENAME to make sure the DB file is changed atomically only
     * if the generate DB file is ok. */
    //重命名
    if (rename(tmpfile,filename) == -1) {
        //失败则放弃持久化并清除文件
        char *cwdp = getcwd(cwd,MAXPATHLEN);
        serverLog(LL_WARNING,
            "Error moving temp DB file %s on the final "
            "destination %s (in server root dir %s): %s",
            tmpfile,
            filename,
            cwdp ? cwdp : "unknown",
            strerror(errno));
        unlink(tmpfile);
        return C_ERR;
    }
	
    //更新日志
    serverLog(LL_NOTICE,"DB saved on disk");
    server.dirty = 0;  //脏键归零
    server.lastsave = time(NULL);  //更新最近保存时间
    server.lastbgsave_status = C_OK;
    return C_OK;

werr:
    serverLog(LL_WARNING,"Write error saving DB on disk: %s", strerror(errno));
    fclose(fp);  //释放文件资源
    unlink(tmpfile);  //删除文件
    return C_ERR;
}
```

后台执行实现

```c
int rdbSaveBackground(char *filename, rdbSaveInfo *rsi) {
    pid_t childpid;
    long long start;
	
    //确保当前没有进行其他持久化操作
    if (server.aof_child_pid != -1 || server.rdb_child_pid != -1) return C_ERR;

    //备份脏键值，最后一次尝试持久化的时间
    server.dirty_before_bgsave = server.dirty;
    server.lastbgsave_try = time(NULL);
    //打开server中子进程与父进程间的管道
    openChildInfoPipe();

    //记录开始时间
    start = ustime();
    //调用fork函数
    if ((childpid = fork()) == 0) {
        int retval;

        /* Child */
        //以下为子进程执行的代码
        closeListeningSockets(0);  //关闭所有监听的socket
        redisSetProcTitle("redis-rdb-bgsave");  //设置进程标题
        retval = rdbSave(filename,rsi);  //调用rdbsave函数保存
        if (retval == C_OK) {
            //(Linux)获取/proc/$pid/smaps中Private_dirty的值
            //这个值表示(子进程)有修改的私有页大小
            size_t private_dirty = zmalloc_get_private_dirty(-1);

            if (private_dirty) {
                serverLog(LL_NOTICE,
                    "RDB: %zu MB of memory used by copy-on-write",
                    private_dirty/(1024*1024));
            }
            
            //保存并向父进程发送copy-on-write size
            server.child_info_data.cow_size = private_dirty;
            sendChildInfo(CHILD_INFO_TYPE_RDB);
        }
        //子进程结束，向父进程发送信号，成功为0，失败为1
        exitFromChild((retval == C_OK) ? 0 : 1);
    } else {
        /* Parent */
        //以下代码与子进程代码并发执行
        //fork时间(仅包括创建子进程，不包括代码rdb持久化执行)
        server.stat_fork_time = ustime()-start;
        //fork速率，单位为GB/s
        server.stat_fork_rate = (double) zmalloc_used_memory() * 1000000 / server.stat_fork_time / (1024*1024*1024); /* GB per second. */
        //在fork执行时间超过配置中设置的阈值的情况下，将事件存入一个dict，延迟诊断
        latencyAddSampleIfNeeded("fork",server.stat_fork_time/1000);
        //fork失败
        if (childpid == -1) {
            //关闭通信管道
            closeChildInfoPipe();
            server.lastbgsave_status = C_ERR;
            serverLog(LL_WARNING,"Can't save in background: fork: %s",
                strerror(errno));
            return C_ERR;
        }
        //更新日志
        serverLog(LL_NOTICE,"Background saving started by pid %d",childpid);
        server.rdb_save_time_start = time(NULL); //设置rdb开始时间
        server.rdb_child_pid = childpid; //执行rdb的子进程id
        server.rdb_child_type = RDB_CHILD_TYPE_DISK; //BGSAVE类型
        //更新hastableh的resize功能
        //此时rdb_child_pid不为-1，动作为关闭resize
        //只有rdb_child_pid与aof_child_pid都为-1时动作才为开启resize
        //hashtable的resize过程中会出现大量内存页的复制
        updateDictResizePolicy();
        return C_OK;
    }
    return C_OK; /* unreached */
}
```

BGSAVE命令实现

```c
void bgsaveCommand(client *c) {
    int schedule = 0;

    /* The SCHEDULE option changes the behavior of BGSAVE when an AOF rewrite
     * is in progress. Instead of returning an error a BGSAVE gets scheduled. */
    if (c->argc > 1) {
        //设置schedule标志
        if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"schedule")) {
            schedule = 1;
        } else {
            addReply(c,shared.syntaxerr);
            return;
        }
    }

    
    rdbSaveInfo rsi, *rsiptr;
    //根据情况更改rsi->repl_stream_db
    rsiptr = rdbPopulateSaveInfo(&rsi);
	
    //如果后台有执行中的RDB持久化，直接退出
    if (server.rdb_child_pid != -1) {
        addReplyError(c,"Background save already in progress");
    //后台有执行中的AOF持久化
    } else if (server.aof_child_pid != -1) {
        //如果设置了schedule，则将BGSAVE的执行放入预定计划中
        if (schedule) {
            server.rdb_bgsave_scheduled = 1;
            addReplyStatus(c,"Background saving scheduled");
        //没有设置则不能继续执行
        } else {
            addReplyError(c,
                "An AOF log rewriting in progress: can't BGSAVE right now. "
                "Use BGSAVE SCHEDULE in order to schedule a BGSAVE whenever "
                "possible.");
        }
    //尝试后台执行
    } else if (rdbSaveBackground(server.rdb_filename,rsiptr) == C_OK) {
        addReplyStatus(c,"Background saving started");
    //执行失败
    } else {
        addReply(c,shared.err);
    }
}

```

##### 00x06 AOF持久化

---

AOF模式会记录所有执行过的命令，恢复时按照顺序执行aof文件中的命令

记录命令时，不直接写入aof文件中，这样会受制于磁盘读写速度

而是先将命令写入缓冲区，之后再将内容同步到磁盘文件中

缓冲区aof_buf在redisServer结构中，数据类型为sds

**追加记录**

实现追加命令到缓冲区

```c
sds catAppendOnlyGenericCommand(sds dst, int argc, robj **argv) {
    //创建临时buffer
    char buf[32];
    int len, j;
    robj *o;
	
    //添加起始符号
    buf[0] = '*';
    //'*'后跟参数个数(argc)
    len = 1+ll2string(buf+1,sizeof(buf)-1,argc);
    //以\r\n做分隔符
    buf[len++] = '\r';
    buf[len++] = '\n';
    //追加到缓冲区中
    dst = sdscatlen(dst,buf,len);
	
    //处理参数部分
    for (j = 0; j < argc; j++) {
        o = getDecodedObject(argv[j]);
        buf[0] = '$';
        len = 1+ll2string(buf+1,sizeof(buf)-1,sdslen(o->ptr));
        buf[len++] = '\r';
        buf[len++] = '\n';
        //'$'后跟此参数长度
        dst = sdscatlen(dst,buf,len);
        //参数内容
        dst = sdscatlen(dst,o->ptr,sdslen(o->ptr));
        dst = sdscatlen(dst,"\r\n",2);
        decrRefCount(o);
    }
    return dst;
}
```

实现追加过期时间到缓冲区

需要将相对时间转换为绝对时间。在恢复时，通过相对时间无法确定键是否过期

```c
sds catAppendOnlyExpireAtCommand(sds buf, struct redisCommand *cmd, robj *key, robj *seconds) {
    long long when;
    robj *argv[3];

    /* Make sure we can use strtoll */
    //处理并读出过期时间
    seconds = getDecodedObject(seconds);
    when = strtoll(seconds->ptr,NULL,10);
    /* Convert argument into milliseconds for EXPIRE, SETEX, EXPIREAT */
    //确定设置过期时间的命令类型，转换单位为毫秒
    if (cmd->proc == expireCommand || cmd->proc == setexCommand ||
        cmd->proc == expireatCommand)
    {
        when *= 1000;
    }
    /* Convert into absolute time for EXPIRE, PEXPIRE, SETEX, PSETEX */
    //从相对时间转换为绝对时间
    if (cmd->proc == expireCommand || cmd->proc == pexpireCommand ||
        cmd->proc == setexCommand || cmd->proc == psetexCommand)
    {
        when += mstime();
    }
    decrRefCount(seconds);
	
    //修改命令内容
    argv[0] = createStringObject("PEXPIREAT",9);
    argv[1] = key;
    argv[2] = createStringObjectFromLongLong(when);
    //追加命令记录
    buf = catAppendOnlyGenericCommand(buf, 3, argv);
    decrRefCount(argv[0]);
    decrRefCount(argv[2]);
    return buf;
}
```

追加操作，调用以上两个函数

```c
void feedAppendOnlyFile(struct redisCommand *cmd, int dictid, robj **argv, int argc) {
    sds buf = sdsempty();
    robj *tmpargv[3];

    /* The DB this command was targeting is not the same as the last command
     * we appended. To issue a SELECT command is needed. */
    //先保存一个SELECT命令，确保当前数据库指向正确
    if (dictid != server.aof_selected_db) {
        char seldb[64];

        snprintf(seldb,sizeof(seldb),"%d",dictid);
        buf = sdscatprintf(buf,"*2\r\n$6\r\nSELECT\r\n$%lu\r\n%s\r\n",
            (unsigned long)strlen(seldb),seldb);
        server.aof_selected_db = dictid;
    }
	
    //EXPIRE，PEXPIRE，EXPIREAT转PEXPIREAT
    if (cmd->proc == expireCommand || cmd->proc == pexpireCommand ||
        cmd->proc == expireatCommand) {
        /* Translate EXPIRE/PEXPIRE/EXPIREAT into PEXPIREAT */
        //调用过期命令记录追加函数
        buf = catAppendOnlyExpireAtCommand(buf,cmd,argv[1],argv[2]);
    //SETEX，PSETEX转SET，PEXPIREAT
    } else if (cmd->proc == setexCommand || cmd->proc == psetexCommand) {
        /* Translate SETEX/PSETEX to SET and PEXPIREAT */
        tmpargv[0] = createStringObject("SET",3);
        tmpargv[1] = argv[1];
        tmpargv[2] = argv[3];
        //添加set命令
        buf = catAppendOnlyGenericCommand(buf,3,tmpargv);
        decrRefCount(tmpargv[0]);
        //设置过期命令
        buf = catAppendOnlyExpireAtCommand(buf,cmd,argv[1],argv[2]);
    //类似上一个分支，过期设置在set命令的EX，PX选项中
    } else if (cmd->proc == setCommand && argc > 3) {
        int i;
        robj *exarg = NULL, *pxarg = NULL;
        /* Translate SET [EX seconds][PX milliseconds] to SET and PEXPIREAT */
        buf = catAppendOnlyGenericCommand(buf,3,argv);
        for (i = 3; i < argc; i ++) {
            if (!strcasecmp(argv[i]->ptr, "ex")) exarg = argv[i+1];
            if (!strcasecmp(argv[i]->ptr, "px")) pxarg = argv[i+1];
        }
        serverAssert(!(exarg && pxarg));
        if (exarg)
            buf = catAppendOnlyExpireAtCommand(buf,server.expireCommand,argv[1],
                                               exarg);
        if (pxarg)
            buf = catAppendOnlyExpireAtCommand(buf,server.pexpireCommand,argv[1],
                                               pxarg);
    //其他命令可直接转换
    } else {
        /* All the other commands don't need translation or need the
         * same translation already operated in the command vector
         * for the replication itself. */
        buf = catAppendOnlyGenericCommand(buf,argc,argv);
    }

    /* Append to the AOF buffer. This will be flushed on disk just before
     * of re-entering the event loop, so before the client will get a
     * positive reply about the operation performed. */
    //正在进行AOF，记录追加到server缓存中
    if (server.aof_state == AOF_ON)
        server.aof_buf = sdscatlen(server.aof_buf,buf,sdslen(buf));

    /* If a background append only file rewriting is in progress we want to
     * accumulate the differences between the child DB and the current one
     * in a buffer, so that when the child process will do its work we
     * can append the differences to the new append only file. */
    //正在进行记录重写，记录追加到重写缓冲区
    if (server.aof_child_pid != -1)
        aofRewriteBufferAppend((unsigned char*)buf,sdslen(buf));

    sdsfree(buf);
}
```

**同步到磁盘**

缓冲区的内容在同步到磁盘(保存为.aof文件)后才完成持久化

共有三种不同的同步模式可设置，当前选项保存在redisServer结构的aof_fsync中

1. AOF_FSYNC_EVERYSEC 2

   每次将命令记录写入缓冲区，执行write操作

   fsync每秒每秒尝试调用一次

2. AOF_FSYNC_ALWAYS 1

   命令记录写入后调用fsync同步

3. AOF_FSYNC_NO 0

   命令记录写入后执行write操作

   不做fsync同步

```c
#define AOF_WRITE_LOG_ERROR_RATE 30
void flushAppendOnlyFile(int force) {
    ssize_t nwritten;
    int sync_in_progress = 0;
    mstime_t latency;
	
    //缓冲区为空，结束
    if (sdslen(server.aof_buf) == 0) return;

    //选项为每秒同步
    if (server.aof_fsync == AOF_FSYNC_EVERYSEC)
        //检查后台是否由aof同步正在进行
        sync_in_progress = bioPendingJobsOfType(BIO_AOF_FSYNC) != 0;
	
    //每秒同步且非强制
    if (server.aof_fsync == AOF_FSYNC_EVERYSEC && !force) {
        /* With this append fsync policy we do background fsyncing.
         * If the fsync is still in progress we can try to delay
         * the write for a couple of seconds. */
        //已有同步正在执行
        if (sync_in_progress) {
            //延迟flush开始时间为0，表示之前未进行过延迟，结束
            if (server.aof_flush_postponed_start == 0) {
                /* No previous write postponing, remember that we are
                 * postponing the flush and return. */
                //保存延迟开始的时间
                server.aof_flush_postponed_start = server.unixtime;
                return;
            //之前有过延迟，但距现在不到2s，继续延迟，结束
            } else if (server.unixtime - server.aof_flush_postponed_start < 2) {
                /* We were already waiting for fsync to finish, but for less
                 * than two seconds this is still ok. Postpone again. */
                return;
            }
            /* Otherwise fall trough, and go write since we can't wait
             * over two seconds. */
            //flush操作延迟已超两秒
            server.aof_delayed_fsync++;
            serverLog(LL_NOTICE,"Asynchronous AOF fsync is taking too long (disk is busy?). Writing the AOF buffer without waiting for fsync to complete, this may slow down Redis.");
        }
    }
    /* We want to perform a single write. This should be guaranteed atomic
     * at least if the filesystem we are writing is a real physical one.
     * While this will save us against the server being killed I don't think
     * there is much to do about the whole server stopping for power problems
     * or alike */
	
    //开始延迟检测
    latencyStartMonitor(latency);
    //将缓冲区数据写入aof文件
    nwritten = aofWrite(server.aof_fd,server.aof_buf,sdslen(server.aof_buf));
    //检测结束
    latencyEndMonitor(latency);
    /* We want to capture different events for delayed writes:
     * when the delay happens with a pending fsync, or with a saving child
     * active, and when the above two conditions are missing.
     * We also use an additional event name to save all samples which is
     * useful for graphing / monitoring purposes. */
    //记录造成延迟的各种情况
    //后台有正在执行的fsync
    if (sync_in_progress) {
        latencyAddSampleIfNeeded("aof-write-pending-fsync",latency);
    //正在执行AOF或RDB
    } else if (server.aof_child_pid != -1 || server.rdb_child_pid != -1) {
        latencyAddSampleIfNeeded("aof-write-active-child",latency);
    //write部分延迟
    } else {
        latencyAddSampleIfNeeded("aof-write-alone",latency);
    }
    //记录aof写操作延迟样本
    latencyAddSampleIfNeeded("aof-write",latency);

    /* We performed the write so reset the postponed flush sentinel to zero. */
    //执行后清除flush延迟时间
    server.aof_flush_postponed_start = 0;
	
    //写入长度与缓存长度相同，进行错误处理与恢复
    if (nwritten != (ssize_t)sdslen(server.aof_buf)) {
        static time_t last_write_error_log = 0;
        int can_log = 0;

        /* Limit logging rate to 1 line per AOF_WRITE_LOG_ERROR_RATE seconds. */
        //限制日志频率
        if ((server.unixtime - last_write_error_log) > AOF_WRITE_LOG_ERROR_RATE) {
            can_log = 1;
            last_write_error_log = server.unixtime;
        }

        /* Log the AOF write error and record the error code. */
        //未成功写入，记录errno到日志中
        if (nwritten == -1) {
            if (can_log) {
                serverLog(LL_WARNING,"Error writing to the AOF file: %s",
                    strerror(errno));
                server.aof_last_write_errno = errno;
            }
        //写了一部分
        } else {
            if (can_log) {
                serverLog(LL_WARNING,"Short write while writing to "
                                       "the AOF file: (nwritten=%lld, "
                                       "expected=%lld)",
                                       (long long)nwritten,
                                       (long long)sdslen(server.aof_buf));
            }
		   //尝试恢复原内容
            if (ftruncate(server.aof_fd, server.aof_current_size) == -1) {
                //无法恢复，记录错误
                if (can_log) {
                    serverLog(LL_WARNING, "Could not remove short write "
                             "from the append-only file.  Redis may refuse "
                             "to load the AOF the next time it starts.  "
                             "ftruncate: %s", strerror(errno));
                }
            } else {
                /* If the ftruncate() succeeded we can set nwritten to
                 * -1 since there is no longer partial data into the AOF. */
                //恢复成功，将nwritten改为-1，表示不需要恢复aof文件
                nwritten = -1;
            }
            server.aof_last_write_errno = ENOSPC;
        }

        /* Handle the AOF write error. */
        //这种设置下write无法恢复
        if (server.aof_fsync == AOF_FSYNC_ALWAYS) {
            /* We can't recover when the fsync policy is ALWAYS since the
             * reply for the client is already in the output buffers, and we
             * have the contract with the user that on acknowledged write data
             * is synced on disk. */
            serverLog(LL_WARNING,"Can't recover from AOF write error when the AOF fsync policy is 'always'. Exiting...");
            exit(1);
        } else {
            /* Recover from failed write leaving data into the buffer. However
             * set an error to stop accepting writes as long as the error
             * condition is not cleared. */
            server.aof_last_write_status = C_ERR;

            /* Trim the sds buffer if there was a partial write, and there
             * was no way to undo it with ftruncate(2). */
            //之前恢复ftruncate恢复失败的话，nwritten不会被重置为-1
            //这时无法恢复aof文件内容
            if (nwritten > 0) {
                //更新AOF文件大小
                server.aof_current_size += nwritten;
                //删除缓冲区写入的内容
                sdsrange(server.aof_buf,nwritten,-1);
            }
            return; /* We'll try again on the next call... */
        }
    //写入成功
    } else {
        /* Successful write(2). If AOF was in error state, restore the
         * OK state and log the event. */
        if (server.aof_last_write_status == C_ERR) {
            serverLog(LL_WARNING,
                "AOF write error looks solved, Redis can write again.");
            server.aof_last_write_status = C_OK;
        }
    }
    //更新当前aof文件大小
    server.aof_current_size += nwritten;

    /* Re-use AOF buffer when it is small enough. The maximum comes from the
     * arena size of 4k minus some overhead (but is otherwise arbitrary). */
    //当前缓存大小小于4k
    if ((sdslen(server.aof_buf)+sdsavail(server.aof_buf)) < 4000) {
        //清空缓存内容，进行重用
        sdsclear(server.aof_buf);
    } else {
        //释放当前缓存空间，新建缓存
        sdsfree(server.aof_buf);
        server.aof_buf = sdsempty();
    }

    /* Don't fsync if no-appendfsync-on-rewrite is set to yes and there are
     * children doing I/O in the background. */
    //正在进行重写/正在执行BGSAVE/正在执行BGREWRITEAOF，直接结束
    if (server.aof_no_fsync_on_rewrite &&
        (server.aof_child_pid != -1 || server.rdb_child_pid != -1))
            return;

    /* Perform the fsync if needed. */
    //每次写入同步
    if (server.aof_fsync == AOF_FSYNC_ALWAYS) {
        /* aof_fsync is defined as fdatasync() for Linux in order to avoid
         * flushing metadata. */
        latencyStartMonitor(latency);
        aof_fsync(server.aof_fd); /* Let's try to get this data on the disk */
        latencyEndMonitor(latency);
        latencyAddSampleIfNeeded("aof-fsync-always",latency);
        //更新最后一次同步时间
        server.aof_last_fsync = server.unixtime
    //设置了force的每秒同步
    } else if ((server.aof_fsync == AOF_FSYNC_EVERYSEC &&
                server.unixtime > server.aof_last_fsync)) {
        //无视延迟，只要后台没有执行同步，立刻开启线程进行同步
        if (!sync_in_progress) aof_background_fsync(server.aof_fd);
        server.aof_last_fsync = server.unixtime;
    }
}
```

**记录重写**

记录命令的AOF文件比起经过较好压缩的rdb文件要大很多

在反复命令非常多时，这种现象犹为严重

redis采用了重写aof文件的方式减小其所占空间，其思想是简化过程，得到相同的结果

重写策略：

- 超时数据不写入文件
- 无效命令不写入文件
- 命令合并

与rdb类似，重写的触发方式也分文主动与被动

- 主动 BGREWRITEAOF 命令

- 被动 由配置中的两个参数决定是否触发

  - auto-aof-rewrite-percentage 追加数据所占空间与上次重写后AOF文件所占空间的比值

  - auto-aof-rewrite-min-size 触发重写的文件所占空间的最小值

    当同时超过这两个阈值，会自动触发AOF重写

```c
//server.h
#define AOF_AUTOSYNC_BYTES (1024*1024*32)

//aof.c
//重写操作实现
int rewriteAppendOnlyFile(char *filename) {
    rio aof;
    FILE *fp;
    char tmpfile[256];
    char byte;

    /* Note that we have to use a different temp name here compared to the
     * one used by rewriteAppendOnlyFileBackground() function. */
    //创建临时文件
    snprintf(tmpfile,256,"temp-rewriteaof-%d.aof", (int) getpid());
    fp = fopen(tmpfile,"w");
    if (!fp) {
        serverLog(LL_WARNING, "Opening the temp file for AOF rewrite in rewriteAppendOnlyFile(): %s", strerror(errno));
        return C_ERR;
    }
	
    //创建一个server内公共空sds，用于保存累计差异
    server.aof_child_diff = sdsempty();
    rioInitWithFile(&aof,fp);
	
    //如果设置了aof_rewrite_incremental_fsync则开启自动同步
    //每写入 AOF_AUTOSYNC_BYTES(32M) 大小的数据，就进行一次同步
    if (server.aof_rewrite_incremental_fsync)
        rioSetAutoSync(&aof,AOF_AUTOSYNC_BYTES);

    //可选混合持久化，redis4.0后的新特性
    if (server.aof_use_rdb_preamble) {
        int error;
        //在aof文件前直接写入rdb格式数据
        if (rdbSaveRio(&aof,&error,RDB_SAVE_AOF_PREAMBLE,NULL) == C_ERR) {
            errno = error;
            goto werr;
        }
    } else {
        //关闭状态下仍以aof格式写入
        if (rewriteAppendOnlyFileRio(&aof) == C_ERR) goto werr;
    }

    /* Do an initial slow fsync here while the parent is still sending
     * data, in order to make the next final fsync faster. */
    //父进程仍在发送数据时进行一个慢同步，使最终同步更快
    if (fflush(fp) == EOF) goto werr;
    if (fsync(fileno(fp)) == -1) goto werr;

    /* Read again a few times to get more data from the parent.
     * We can't read forever (the server may receive data from clients
     * faster than it is able to send data to the child), so we try to read
     * some more data in a loop as soon as there is a good chance more data
     * will come. If it looks like we are wasting time, we abort (this
     * happens after 20 ms without new data). */
    //从父进程多读几次数据
    int nodata = 0;
    mstime_t start = mstime();
    while(mstime()-start < 1000 && nodata < 20) {
        //1ms内从pipe中读不出数据，则纪录nodata++
        //连续20ms没有数据则结束循环
        if (aeWait(server.aof_pipe_read_data_from_parent, AE_READABLE, 1) <= 0)
        {
            nodata++;
            continue;
        }
        
        //读取到数据重新开始计时
        nodata = 0; /* Start counting from zero, we stop on N *contiguous*
                       timeouts. */
        aofReadDiffFromParent();
    }

    /* Ask the master to stop sending diffs. */
    //通知父进程停止发送累计差异
    if (write(server.aof_pipe_write_ack_to_parent,"!",1) != 1) goto werr;
    //设置从父进程读ack的pipe设置为非阻塞模式
    if (anetNonBlock(NULL,server.aof_pipe_read_ack_from_parent) != ANET_OK)
        goto werr;
    /* We read the ACK from the server using a 10 seconds timeout. Normally
     * it should reply ASAP, but just in case we lose its reply, we are sure
     * the child will eventually get terminated. */
    //逐个取字节到byte中，检查是否为'!'
    if (syncRead(server.aof_pipe_read_ack_from_parent,&byte,1,5000) != 1 ||
        byte != '!') goto werr;
    //收到'!'则发送日志
    serverLog(LL_NOTICE,"Parent agreed to stop sending diffs. Finalizing AOF...");

    /* Read the final diff if any. */
    //读取余下的累计差异
    aofReadDiffFromParent();

    /* Write the received diff to the file. */
    serverLog(LL_NOTICE,
        "Concatenating %.2f MB of AOF diff received from parent.",
        (double) sdslen(server.aof_child_diff) / (1024*1024));
    //将子进程保存的差异写入aof
    if (rioWrite(&aof,server.aof_child_diff,sdslen(server.aof_child_diff)) == 0)
        goto werr;

    /* Make sure data will not remain on the OS's output buffers */
    //清空缓冲区，再次同步
    if (fflush(fp) == EOF) goto werr;
    if (fsync(fileno(fp)) == -1) goto werr;
    if (fclose(fp) == EOF) goto werr;

    /* Use RENAME to make sure the DB file is changed atomically only
     * if the generate DB file is ok. */
    //更改临时文件名
    if (rename(tmpfile,filename) == -1) {
        serverLog(LL_WARNING,"Error moving temp append only file on the final destination: %s", strerror(errno));
        unlink(tmpfile);
        return C_ERR;
    }
    serverLog(LL_NOTICE,"SYNC append only file rewrite performed");
    return C_OK;

//错误处理
werr:
    serverLog(LL_WARNING,"Write error writing append only file on disk: %s", strerror(errno));
    fclose(fp);
    unlink(tmpfile);
    return C_ERR;
}

//后台重写实现
int rewriteAppendOnlyFileBackground(void) {
    pid_t childpid;
    long long start;
	
    //正在执行BGSAVE/BGREWRITEAOF，结束，返回C_ERR
    if (server.aof_child_pid != -1 || server.rdb_child_pid != -1) return C_ERR;
    //尝试创建父进程与子进程间的管道
    if (aofCreatePipes() != C_OK) return C_ERR;
    //打开管道
    openChildInfoPipe();
    //fork开始时间
    start = ustime();
    //调用fork
    if ((childpid = fork()) == 0) {
        char tmpfile[256];

        /* Child */
        //子进程代码段
        closeListeningSockets(0);
        redisSetProcTitle("redis-aof-rewrite");
        snprintf(tmpfile,256,"temp-rewriteaof-bg-%d.aof", (int) getpid());
        //对临时文件重写
        if (rewriteAppendOnlyFile(tmpfile) == C_OK) {
            //同rdb
            //(Linux)获取/proc/$pid/smaps中Private_dirty的值
            //这个值表示(子进程)有修改的私有页大小
            size_t private_dirty = zmalloc_get_private_dirty(-1);

            if (private_dirty) {
                serverLog(LL_NOTICE,
                    "AOF rewrite: %zu MB of memory used by copy-on-write",
                    private_dirty/(1024*1024));
            }

            server.child_info_data.cow_size = private_dirty;
            sendChildInfo(CHILD_INFO_TYPE_AOF);
            exitFromChild(0);
        } else {
            exitFromChild(1);
        }
    } else {
        /* Parent */
        //父进程继续执行的代码段
        //计算fork用时
        server.stat_fork_time = ustime()-start;
        //fork速率
        server.stat_fork_rate = (double) zmalloc_used_memory() * 1000000 / server.stat_fork_time / (1024*1024*1024); /* GB per second. */
        latencyAddSampleIfNeeded("fork",server.stat_fork_time/1000);
        //子进程创建失败
        if (childpid == -1) {
            closeChildInfoPipe();
            serverLog(LL_WARNING,
                "Can't rewrite append only file in background: fork: %s",
                strerror(errno));
            aofClosePipes();
            return C_ERR;
        }
        serverLog(LL_NOTICE,
            "Background append only file rewriting started by pid %d",childpid);
        //清空预定计划
        server.aof_rewrite_scheduled = 0;
        //记录aof重写开始时间
        server.aof_rewrite_time_start = time(NULL);
        //更新server中aof执行子进程的pid
        server.aof_child_pid = childpid;
        updateDictResizePolicy();
        /* We set appendseldb to -1 in order to force the next call to the
         * feedAppendOnlyFile() to issue a SELECT command, so the differences
         * accumulated by the parent into server.aof_rewrite_buf will start
         * with a SELECT statement and it will be safe to merge. */
        //强制让feedAppendOnlyFile开始时执行SELECT
        server.aof_selected_db = -1;
        //清空脚本缓存
        replicationScriptCacheFlush();
        return C_OK;
    }
    return C_OK; /* unreached */
}

//AOF重写命令实现
void bgrewriteaofCommand(client *c) {
    //aof重写正在执行
    if (server.aof_child_pid != -1) {
        addReplyError(c,"Background append only file rewriting already in progress");
    //rdb持久化正在进行
    } else if (server.rdb_child_pid != -1) {
        server.aof_rewrite_scheduled = 1;
        addReplyStatus(c,"Background append only file rewriting scheduled");
    //重写成功
    } else if (rewriteAppendOnlyFileBackground() == C_OK) {
        addReplyStatus(c,"Background append only file rewriting started");
    } else {
        //发送错误到客户端
        addReply(c,shared.err);
    }
}
```