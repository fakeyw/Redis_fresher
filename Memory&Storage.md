# Memory&Storage

#### 内存（内存分配、编码压缩）

**00x01 zmalloc**

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



**00x02 ziplist.c 压缩列表**

---

