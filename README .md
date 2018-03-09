## About Redis 

redis是一种存储结构类似Nosql的数据储存系统。
与mongodb之类不同的是，redis将数据存放于内存，所以读写速度要快上很多倍。
而与memcache的区别是redis也使用磁盘将储存的数据持久化，而且相当于一块能够更新数据的缓存。
但内存仍然是redis能快速查询资源大小的限制条件。

###### redis的特点

---
优点：原子性 速度极快 数据类型丰富 自带多种工具（缓存、消息队列...） cluster的主从模式
缺点：内存开销大
不确定：单线程 去结构化

###### 应用
---
主要应用：

基于redis最突出的特点——速度极快，其大多被用于热点数据的缓存。新浪微博、Pinterest、Viacom等都在使用Redis作为其缓存系统。同时，其种类多样的数据类型起到了很大的作用，如Viacom对hashmap的需求令其放弃MySQL+memcache转而使用redis

其他应用：
基于单线程与操作速度，可用于计数
可使用内建的消息队列，但不如其他成熟消息队列好用

## Install & use Redis

###### 安装
---
一般作为服务器常用ubuntu server/centos等linux系系统

在Ubuntu下，可使用如下命令安装：

```bash
sudo apt-get update
sudo apt-get install redis-server
```

在redis官网上给出了通用的下载与安装命令
```bash
$ wget http://download.redis.io/releases/redis-4.0.8.tar.gz
$ tar xzf redis-4.0.8.tar.gz
$ cd redis-4.0.8
$ make
```

执行make命令前需要事先安装好gcc与make
```bash
$ sudo apt-get install gcc
$ sudo apt-get install make
$ make install #or just make, make install can add redis to /usr/bin
```

如果安装顺利，完成后开启redis服务：
```bash
root@ubuntu:/home/fakeyw/redis-4.0.8# redis-server #make：src/redis-server
4559:C 08 Mar 00:22:48.260 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
4559:C 08 Mar 00:22:48.260 # Redis version=4.0.8, bits=64, commit=00000000, modi fied=0, pid=4559, just started
4559:C 08 Mar 00:22:48.260 # Warning: no config file specified, using the defaul t config. In order to specify a config file use redis-server /path/to/redis.conf
4559:M 08 Mar 00:22:48.261 * Increased maximum number of open files to 10032 (it  was originally set to 1024).
                _._
           _.-``__ ''-._
      _.-``    `.  `_.  ''-._           Redis 4.0.8 (00000000/0) 64 bit
  .-`` .-```.  ```\/    _.,_ ''-._
 (    '      ,       .-`  | `,    )     Running in standalone mode
 |`-._`-...-` __...-.``-._|'` _.-'|     Port: 6379
 |    `-._   `._    /     _.-'    |     PID: 4559
  `-._    `-._  `-./  _.-'    _.-'
 |`-._`-._    `-.__.-'    _.-'_.-'|
 |    `-._`-._        _.-'_.-'    |           http://redis.io
  `-._    `-._`-.__.-'_.-'    _.-'
 |`-._`-._    `-.__.-'    _.-'_.-'|
 |    `-._`-._        _.-'_.-'    |
  `-._    `-._`-.__.-'_.-'    _.-'
      `-._    `-.__.-'    _.-'
          `-._        _.-'
              `-.__.-'

4559:M 08 Mar 00:22:48.265 # WARNING: The TCP backlog setting of 511 cannot be e nforced because /proc/sys/net/core/somaxconn is set to the lower value of 128.
4559:M 08 Mar 00:22:48.265 # Server initialized
4559:M 08 Mar 00:22:48.265 # WARNING overcommit_memory is set to 0! Background s ave may fail under low memory condition. To fix this issue add 'vm.overcommit_me mory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.over commit_memory=1' for this to take effect.
4559:M 08 Mar 00:22:48.265 # WARNING you have Transparent Huge Pages (THP) suppo rt enabled in your kernel. This will create latency and memory usage issues with  Redis. To fix this issue run the command 'echo never > /sys/kernel/mm/transpare nt_hugepage/enabled' as root, and add it to your /etc/rc.local in order to retai n the setting after a reboot. Redis must be restarted after THP is disabled.
4559:M 08 Mar 00:22:48.266 * DB loaded from disk: 0.000 seconds
4559:M 08 Mar 00:22:48.266 * Ready to accept connections

```

redis默认为前台启动，如果想改成后台，需要对目录下redis.conf进行更改：

> 找到 daemonize no 这一条，no改为yes，启动时导入这份配置文件即可

```bash
root@ubuntu:/home/fakeyw/redis-4.0.8# redis-server redis.conf
4565:C 08 Mar 00:23:08.007 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
4565:C 08 Mar 00:23:08.007 # Redis version=4.0.8, bits=64, commit=00000000, modi fied=0, pid=4565, just started
4565:C 08 Mar 00:23:08.007 # Configuration loaded

root@ubuntu:/home/fakeyw/redis-4.0.8# netstat -tunpl|grep redis
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN       4559/redis-server *
tcp6       0      0 :::6379                 :::*                    LISTEN       4559/redis-server *
```

这时redis就在后台运行了

###### 数据结构
---
redis支持的数据结构有五种：string、hash、list、set和zset

> String 字符串
> 最基本数据类型，二进制安全，最大512M，可包含任何类型文件
> 相关命令：SET  GET 等

> Hash 哈希表
> 键值对集合，string类型的field-value映射表，适用与储存对象
> 相关命令：HMSET  HGET 等

> List 列表
> 与一般意义上的列表功能相似，可头插或尾插
> 相关命令：LPUSH  LPOP 等

> Set 集合
> string类型的无序集合，由hashmap实现，基本操作复杂度为O(1)
> 相关命令：SADD  SMEMBERS 等

> Zset 有序集合
> 元素唯一，每个元素关联一个double类型的分数（可重复）用于排序
> 相关命令： ZADD  ZSCAN 等

###### 基本使用

---

最基本测试python代码：

```python
import redis
from datetime import datetime

r_conn = redis.Redis(host='192.168.179.128',port=6379,db=0)
#获取与远程（或本地）redis服务的连接

r_conn.set('time_now',datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
t = r_conn.get('time_now')
print(t)
```

此时...由于目标计算机积极拒绝，无法连接。这里遇到了第一个坑

是因为redis-server默认配置为 bind 127.0.0.1，也就是本地请求

要在配置里改为 0.0.0.0 或直接注释掉，重启服务。

再次运行脚本，然后...

> redis.exceptions.ResponseError: DENIED Redis is running in protected mode because protected mode is enabled, no bind address was specified, no authentication password is requested to clients. In this mode connections are only accepted from the loopback interface. If you want to connect from external computers to Redis you may adopt one of the following solutions: 1) Just disable protected mode sending the command 'CONFIG SET protected-mode no' from the loopback interface by connecting to Redis from the same host the server is running, however MAKE SURE Redis is not publicly accessible from internet if you do so. Use CONFIG REWRITE to make this change permanent. 2) Alternatively you can just disable the protected mode by editing the Redis configuration file, and setting the protected mode option to 'no', and then restarting the server. 3) If you started the server manually just for testing, restart it with the '--protected-mode no' option. 4) Setup a bind address or an authentication password. NOTE: You only need to do one of the above things in order for the server to start accepting connections from the outside.

这么一大段文字作为警报弹出来，写得很明显，还是配置的问题。

1.强行关闭保护模式

2.强行关闭保护模式

3.再次打开时强行关闭保护模式

4.监听某一个ip或设置密码

说得好，我选择4

找到redis.conf中的 #requirepass foobared，去掉注释并把foobared改为密码

在脚本中加上密码

```python
>>> r_conn = redis.Redis(host='192.168.179.128',port=6379,password='111111',db=0)
>>> r_conn.set('time_now',datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
True
```

连接成功。



## Redis Sentinel&Cluster

---

