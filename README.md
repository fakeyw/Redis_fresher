# Redis急速入门日志

[TOC]

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

P.S. ：以下操作为尝试方便，在本地使用了root用户。在使用时最好使用限权用户进行操作。

###### 安装
---
一般作为服务器常用ubuntu server/centos等linux系系统

在Ubuntu下，可使用如下命令安装（不推荐使用）：

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

要在配置里改为 对应ip 或直接注释掉，重启服务。

再次运行脚本，然后...

> redis.exceptions.ResponseError: DENIED Redis is running in protected mode because protected mode is enabled, no bind address was specified, no authentication password is requested to clients. In this mode connections are only accepted from the loopback interface. If you want to connect from external computers to Redis you may adopt one of the following solutions: **1) Just disable protected mode sending the command 'CONFIG SET protected-mode no' from the loopback interface by connecting to Redis from the same host the server is running, however MAKE SURE Redis is not publicly accessible from internet if you do so. Use CONFIG REWRITE to make this change permanent. 2) Alternatively you can just disable the protected mode by editing the Redis configuration file, and setting the protected mode option to 'no', and then restarting the server. 3) If you started the server manually just for testing, restart it with the '--protected-mode no' option. 4) Setup a bind address or an authentication password. NOTE: You only need to do one of the above things in order for the server to start accepting connections from the outside.**

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

###### 开启多个结点

---

redis结点的功能是由.conf配置文件来调整的

可以根据多个配置文件开启多个redis服务结点

而集群正式运作需要至少三个结点，为了体现redis主从结点的复制特点，在三个主结点`master`的基础上最好添加数个从结点`slaver`

1.为每个结点创建一个文件夹

P.S. : 对于每个结点，需要一个相对独立空间。因为每个结点的结点配置文件(与服务配置文件不同)、操作日志aof文件，在同一目录下只能存在一份。而这些文件保存在用户启动服务时，所在的当前文件夹下。

2.复制一份redis主目录给出的redis.conf文件，找到如下条目修改为：

> cluster-enable yes #开启集群功能
>
> cluster-config-file nodes.conf #这就是上面所说的 结点配置文件，为了分辨可以自行命名
>
> cluster-node-timeout 15000 #在确认结点是否正常工作(PING-PONG)时的的等待时间
>
> appendonly yes #可选，在数据库持久化的基础上保存每一条操作日志，牺牲部分性能尽量保证数据完整性

3.将这份配置复制到每个结点的文件夹中，更改.conf中的port，选择结点监听的端口。

4.依次cd到每个文件夹中，运行 `redis-server redis.conf` ，此时文件夹中会自动产生nodes.conf(由配置决定)，如果开启了aof持久化，还会出现appendonly.aof。

5.查看后台进程（我用了六个结点）：

```bash
root@ubuntu:/home/fakeyw/redis-cls-7005# ps -aux|grep redis
root       2108  0.1  1.0  46808 10368 ?        Ssl  04:15   0:00 redis-server *:7000 [cluster]
root       2115  0.0  1.0  46808 10348 ?        Ssl  04:15   0:00 redis-server *:7001 [cluster]
root       2124  0.0  1.0  46808 10392 ?        Ssl  04:16   0:00 redis-server *:7002 [cluster]
root       2131  0.2  1.0  46808 10396 ?        Ssl  04:16   0:00 redis-server *:7003 [cluster]
root       2139  0.3  1.0  46808 10456 ?        Ssl  04:16   0:00 redis-server *:7004 [cluster]
root       2146  0.6  1.0  46808 10356 ?        Ssl  04:16   0:00 redis-server *:7005 [cluster]
root       2151  0.0  0.1  14224  1020 pts/1    S+   04:16   0:00 grep --color=auto redis
```

现在已经成功开启足够的实验结点，可以开始尝试构建集群。

另，关闭结点的命令常用：

>redis-cli -h [ip] -p [port] -a [passwd] shutdown

###### 构建集群

---

在redis主目录 /src下有自带的 redis-trib.rb 是ruby语言的集群构建脚本，需要安装Ruby环境。

详见：[ruby官方安装文档](http://www.ruby-lang.org/en/downloads/)

Ruby环境安装好之后

执行

>ruby redis-trib.rb create --replicas 1 127.0.0.1:7000 127.0.0.1:7001 127.0.0.1:7002 127.0.0.1:7003 127.0.0.1:7004 127.0.0.1:7005

来构建由五个结点构成的集群，
其中 `replicas` 参数为每个主结点的从结点数量。

但在纯净的系统中很可能出现如下报错：

```bash
/usr/lib/ruby/2.3.0/rubygems/core_ext/kernel_require.rb:55:in `require': cannot load such file -- redis (LoadError)
```

意思是无法加载redis，查了一下是指ruby的redis依赖模块。

执行

>gem install redis

如果长时间没有反应，说明网络有问题，大家都懂的

实在没办法连接就直接去官方渠道下载 [Redis包](https://rubygems.org/gems/redis/)

以下为4.0.1版本正常操作与反馈：

```
root@ubuntu:/home/fakeyw/redis-4.0.8# wget https://rubygems.org/downloads/redis-4.0.1.gem
--2018-03-09 07:44:05--  https://rubygems.org/downloads/redis-4.0.1.gem
Resolving rubygems.org (rubygems.org)... 151.101.194.2, 151.101.2.2, 151.101.66.2, ...
Connecting to rubygems.org (rubygems.org)|151.101.194.2|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 91648 (90K) [application/octet-stream]
Saving to: ‘redis-4.0.1.gem’

redis-4.0.1.gem     100%[===================>]  89.50K  71.5KB/s    in 1.3s

2018-03-09 07:44:07 (71.5 KB/s) - ‘redis-4.0.1.gem’ saved [91648/91648]

root@ubuntu:/home/fakeyw/redis-4.0.8# gem install redis-4.0.1.gem
Successfully installed redis-4.0.1
Parsing documentation for redis-4.0.1
Installing ri documentation for redis-4.0.1
Done installing documentation for redis after 1 seconds
1 gem installed
```

再次运行构建命令

然而报错

>[ERR] Sorry, can't connect to node 127.0.0.1:7000

一般来说有两种情况：

1. 未开放ip或端口。因为是本地连接，所以排除
2. 配置中的bind不对。ps查看时为 ‘ * ’，即所有ip，排除

查看了配置文件，最后发现是认证的问题，因为之前在配置中设置了密码。

而ruby集群构建脚本是不能带密码连接的，需要在集群构成后进行设置。

而且对集群设置密码时，requirepass与masterauth都要设置，否则在主从切换时会遇到授权问题。且每个结点要求一致，否则Redirected会失败。（re和ma两个密码是否需要一致有待求证）

取消密码，再次运行脚本，完成集群构建

```bash
127.0.0.1:7000> cluster info
cluster_state:ok
cluster_slots_assigned:16384
cluster_slots_ok:16384
cluster_slots_pfail:0
cluster_slots_fail:0
cluster_known_nodes:6
cluster_size:3
cluster_current_epoch:6
cluster_my_epoch:1
cluster_stats_messages_ping_sent:248
cluster_stats_messages_pong_sent:263
cluster_stats_messages_sent:511
cluster_stats_messages_ping_received:263
cluster_stats_messages_pong_received:248
cluster_stats_messages_received:511
```

虽然说16384个槽位都有所属，集群也正常，但其实构建过程中是有报错的

>[ERR] Sorry, can't connect to node 192.168.179.128:7004
>......
>[ERR] Not all 16384 slots are covered by nodes.

像这样显示实际ip的

排查后发现只有配置为 bind 127.0.0.1 192.168.179.128 时才完全正常。

目前集群时规模为三个结点，三主三从的最小集群。

显示为：

```bash
......
[OK] All nodes agree about slots configuration.
>>> Check for open slots...
>>> Check slots coverage...
[OK] All 16384 slots covered.
```

> P.S. : 在测试时写了三个shell脚本，分别用于启动所有结点、关闭所有结点、完全初始化结点文件。不建议完全手动进行测试，效率太低。

###### 内网分布式集群

---

分布式集群实际上只是将本地结点迁移到其他主机或容器中，仍然是通过更改bind ip来监听与互联。

在这里以将docker容器中一对容器加入本地集群作为例子。

但刚开始似乎遇到了很严重的问题，ubuntu:16.04容器中无法加载配置启动redis

那么试试centos的容器

> 关于Centos，安装ssh服务时要安装openssh-server与openssh-clients 而不是 openssh-client
>
> 另，docker centos镜像没有service命令（不影响集群构建），恢复：
>
> yum install initscripts 

可以正常从配置启动。

远程添加结点：

>```
>ruby redis-trib.rb add-node 172.17.0.3:6397 127.0.0.1:7000
>```

显示是成功的，但几秒后这个结点就从记录中消失了。。

尝试添加本地结点 127.0.0.1:7006

成功添加并分片（命令如下），此结点成为主节点。

```bash
root@ubuntu:/home/fakeyw/redis-cls-7006# ruby ../redis-4.0.8/src/redis-trib.rb add-node 127.0.0.1:7006 127.0.0.1:7000
.......
[OK] All nodes agree about slots configuration.
>>> Check for open slots...
>>> Check slots coverage...
[OK] All 16384 slots covered.
>>> Send CLUSTER MEET to node 127.0.0.1:7006 to make it join the cluster.
[OK] New node added correctly.
root@ubuntu:/home/fakeyw/redis-cls-7006# ruby ../redis-4.0.8/src/redis-trib.rb reshard 127.0.0.1:7000
......
Moving slot 11252 from 127.0.0.1:7002 to 192.168.179.128:7006:
Moving slot 11253 from 127.0.0.1:7002 to 192.168.179.128:7006:
Moving slot 11254 from 127.0.0.1:7002 to 192.168.179.128:7006:
Moving slot 11255 from 127.0.0.1:7002 to 192.168.179.128:7006:
```

说明添加结点没有问题，这时需要解决远程结点添加不成功的问题。

Several hours later...

在一种苛刻条件下，成功构建了包含远程结点的集群:

```bash
root@ubuntu:/home/fakeyw# ruby redis-4.0.8/src/redis-trib.rb create --replicas 1 192.168.179.128:7000 192.168.179.128:7001 192.168.179.128:7002 192.168.179.128:7003 192.168.179.128:7004 192.168.179.128:7005 192.168.179.129:7777
>>> Creating cluster
>>> Performing hash slots allocation on 7 nodes...
Using 3 masters:
192.168.179.128:7000
192.168.179.129:7777
192.168.179.128:7001
......
......
......
S: 7d066691090762d927cffdb065d721bc2754eb43 192.168.179.128:7003
   slots: (0 slots) slave
   replicates a1cf5bff7895650d67d7bf09ed05dbf2947d34a0
[OK] All nodes agree about slots configuration.
>>> Check for open slots...
>>> Check slots coverage...
[OK] All 16384 slots covered.
```

当前条件为：每个节点的配置 bind 不能为127.0.0.1而是内网ip（如果需要映射到公网，之后有一个announce-ip）、安全模式是关闭的。

在ip为192.168.179.129的主机的7778端口再次开放一个除端口外同样配置的redis结点，尝试连接

>ruby redis-4.0.8/src/redis-trib.rb add-node 192.168.179.129:7778 192.168.179.128:7000

仍然显示为

>[OK] New node added correctly.

查看cluster nodes发现成功加入结点。

```bash
root@ubuntu:/home/fakeyw# redis-cli -h 192.168.179.128 -p 7000
192.168.179.128:7000> cluster nodes
6abb1cc5b10e40e831dd0eda9900f60072a3f35d 192.168.179.128:7004@17004 slave 27c35825805895deda38c34ffde65ccf630f035f 0 1520695346426 7 connected
a1cf5bff7895650d67d7bf09ed05dbf2947d34a0 192.168.179.128:7000@17000 myself,master - 0 1520695347000 1 connected 0-5460
663fd8e4c8fd23c6ed937deaf66339dc04b23020 192.168.179.129:7778@17778 master - 0 1520695345000 0 connected #这是动态加入的远程结点
f985284ea6a9d4189d348e7fea454df836a6c3ff 192.168.179.128:7001@17001 master - 0 1520695347449 2 connected 10923-16383
78cd852c36019b8ea17ce4f03c3af90fb3bf3c58 192.168.179.128:7002@17002 slave a1cf5bff7895650d67d7bf09ed05dbf2947d34a0 0 1520695345000 3 connected
27c35825805895deda38c34ffde65ccf630f035f 192.168.179.129:7777@17777 master - 0 1520695345403 7 connected 5461-10922 #这时构建时加入的远程结点
6b7b0ecbd1106c0178fa87b89afaacba78c9d879 192.168.179.128:7005@17005 slave f985284ea6a9d4189d348e7fea454df836a6c3ff 0 1520695348474 6 connected
7d066691090762d927cffdb065d721bc2754eb43 192.168.179.128:7003@17003 slave a1cf5bff7895650d67d7bf09ed05dbf2947d34a0 0 1520695346000 4 connected
```

P.S. ：远程结点所在宿主机不需要安装Ruby解释器，因为脚本起到的作用仅为向redis结点发送信号。

###### 公网结点

---

暂缺，本地（无固定公网ip）结点 - 公网docker内结点 组建集群失败，但可以连接控制台（redis-cli）。

配置：

docker内结点

dockers转发设置为 -p vps ip:vps port:container port (不一定是ssh连接的ip，一般是vps在eth0网络内的ip)

据资料，redis总线端口也需要转发，但操作后仍然没能构建结点

cluster-announce-ip 等设置后（多种组合） 也没能构建结点

bind docker0网络ip 

推测需要两台有相对固定ip的主机进行实验。

###### 哨兵结点（sentinel）

---

sentinel结点与数据结点不同，其功能是对数据结点与其他sentinel结点进行监控。

当发现一个结点不可达时，当前sentinel结点会给出Subjectively Down（简称SDOWN）标识

sentinel结点相互交流后，当多数认为此结点(只能为主结点，其他结点下线不需要协商）SDOWN，则此结点Objectively Down（简称ODOWN）

主节点ODOWN时，开始进行故障迁移。

根据raft算法（之后会讨论），选出一个sentinel来主持主从切换。

再在ODOWN主节点的从结点里选出一个从结点，切换为主节点，换下的主节点属性更改为从结点，再次上线时开始复制新的从结点。

这种自动保持结点完整的特性为redis集群提供了高度可用性。

## Source Code&Algorithm

###### 源码

---

下载：[redis 4.0.8 源文件](http://download.redis.io/releases/redis-4.0.8.tar.gz)

（main函数在server.c中）

源码阅读顺序推荐 （https://www.cnblogs.com/aixiaomei/p/6311633.html）

1. 基本数据结构

   1. 内存分配 zmalloc.c、zmalloc.h *
   2. 动态字符串 sds.h、sds.c
   3. 双端链表 adlist.c、adlist.h
   4. 字典 dict.h、dict.c
   5. 跳跃表 server.h 中的zskiplist、zskiplistNode 结构，t_zset.c中所有zsl开头的函数 *
   6. 日志类型 hyperloglog.c 中的 hllhdr结构、hll开头的函数

2. 内存编码

   1. 整数集合 intset.h、intset.c 
   2. 压缩列表 ziplist.h、ziplist.c *

3. redis数据类型

   1. 对象系统 object.c *
   2. 字串键 t_string.c *
   3. 列表键 t_list.c *
   4. 散列键 hash.c *
   5. 集合键 t_set.c *
   6. 有序集合键 t_zset.c中除 zsl 开头的函数之外的所有函数 *
   7. HyperLogLog键 hyperloglog.c中所有以pf开头的函数

4. 数据库实现

   1. redis.h redisDb结构、db.c *
   2. 通知 notify.c
   3. RDB rdb.c *
   4. AOF aof.c *
   5. 发布-订阅 redis.h - pubsubPattern、pubsub.c
   6. 事务 redis.h - multiState multiCmd、multi.c

5. 双端实现

   1. 事件处理 ae.c/ae_epoll.c/ae_evport.c/ae_kqueue.c/ae_select.c
   2. 网络 anet.c、networking.c *
   3. 服务端 redis.c
   4. 客户端 redis-cli.c
   5. lua脚本 scripting.c
   6. 慢查询 slowlog.c
   7. 监视 monitor.c *

6. 集群功能

   1. 复制 replication.c *
   2. 哨兵 sentinal.c *
   3. 集群 cluster.c *

7. 其他

   暂略

---

以上为`3.2.5`版本的源码基本结构，而且有一些问题，比如并不存在的redis.c

在当前使用的`4.0.8`中，暂时猜测服务端在server.c中，redis.h对应到server.h

源码分析主要探究如下部分：

- 数据类型
- 内存/存储
- 网络
- 集群实现

具体分析都以4.0.8稳定版作为标准

