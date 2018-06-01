# Cluster&Sentinel

[TOC]



#### 基本功能实现

##### 00x01 集群初始化

---

**开启集群模式**

启动服务时，集群开启状态在配置文件中被加载

`main()` -> `loadServerConfig()` -> `loadServerConfigFromString()` 读取配置文件

当函数检查 cluster-enabled 选项为 yes 的时候，会将当前要开启server的cluster_enabled参数设为1

之后，`main()` -> `initServer()` 执行server初始化函数

在 `initServer()` 中检查了server.cluster_enabled

```c
if (server.cluster_enabled) clusterInit();
```

**集群服务初始化**

当前节点状态数据结构

```c
//cluster.h

#define CLUSTER_SLOTS 16384

typedef struct clusterState {
    //代表本节点
    clusterNode *myself;  /* This node */
    //当前纪元
    uint64_t currentEpoch;
    //状态
    int state;            /* CLUSTER_OK, CLUSTER_FAIL, ... */
    //至少负责一个slot的主节点个数
    int size;             /* Num of master nodes with at least one slot */
    //保存集群节点
    dict *nodes;          /* Hash table of name -> clusterNode structures */
    //保证一些节点在一些时间内不可读
    dict *nodes_black_list; /* Nodes we don't re-add for a few seconds. */
    //记录导入slots
    clusterNode *migrating_slots_to[CLUSTER_SLOTS];
    //记录导出slots
    clusterNode *importing_slots_from[CLUSTER_SLOTS];
    //slot映射到节点
    clusterNode *slots[CLUSTER_SLOTS];
    //slot包括的key的数量
    uint64_t slots_keys_count[CLUSTER_SLOTS];
    //slot映射到keys
    rax *slots_to_keys;
    /* The following fields are used to take the slave state on elections. */
    //前一次或下次选举时间
    mstime_t failover_auth_time; /* Time of previous or next election. */
    //当前已获得支持数
    int failover_auth_count;    /* Number of votes received so far. */
    //是否已投票
    int failover_auth_sent;     /* True if we already asked for votes. */
    //当前从节点的排名
    int failover_auth_rank;     /* This slave rank for current auth request. */
    //当前选举纪元
    uint64_t failover_auth_epoch; /* Epoch of the current election. */
    //不能进行故障转移的原因
    int cant_failover_reason;   /* Why a slave is currently not able to
                                   failover. See the CANT_FAILOVER_* macros. */
    /* Manual failover state in common. */
    //手动故障转移状态
    mstime_t mf_end;            /* Manual failover time limit (ms unixtime).
                                   It is zero if there is no MF in progress. */
    /* Manual failover state of master. */
    //执行故障转移的从节点
    clusterNode *mf_slave;      /* Slave performing the manual failover. */
    /* Manual failover state of slave. */
    //从节点开始故障转移时主节点偏移量
    long long mf_master_offset; /* Master offset the slave needs to start MF
                                   or zero if stil not received. */
    //故障转移是否能开始
    int mf_can_start;           /* If non-zero signal that the manual failover
                                   can start requesting masters vote. */
    /* The followign fields are used by masters to take state on elections. */
    //集群最后一次投票的纪元
    uint64_t lastVoteEpoch;     /* Epoch of the last vote granted. */
    //clusterBeforeSleep()执行的内容
    int todo_before_sleep; /* Things to do in clusterBeforeSleep(). */
    /* Messages received and sent by type. */
    //总线发送/接收的字节数
    long long stats_bus_messages_sent[CLUSTERMSG_TYPE_COUNT];
    long long stats_bus_messages_received[CLUSTERMSG_TYPE_COUNT];
    //处在PFAIL状态的节点
    long long stats_pfail_nodes;    /* Number of nodes in PFAIL status,
                                       excluding nodes without address. */
} clusterState;
```

初始化函数

```c
//cluster.c
void clusterInit(void) {
    int saveconf = 0;

    //初始化各种状态
    server.cluster = zmalloc(sizeof(clusterState));
    server.cluster->myself = NULL;
    server.cluster->currentEpoch = 0;
    server.cluster->state = CLUSTER_FAIL;
    server.cluster->size = 1;
    server.cluster->todo_before_sleep = 0;
    server.cluster->nodes = dictCreate(&clusterNodesDictType,NULL);
    server.cluster->nodes_black_list =
        dictCreate(&clusterNodesBlackListDictType,NULL);
    server.cluster->failover_auth_time = 0;
    server.cluster->failover_auth_count = 0;
    server.cluster->failover_auth_rank = 0;
    server.cluster->failover_auth_epoch = 0;
    server.cluster->cant_failover_reason = CLUSTER_CANT_FAILOVER_NONE;
    server.cluster->lastVoteEpoch = 0;
    for (int i = 0; i < CLUSTERMSG_TYPE_COUNT; i++) {
        server.cluster->stats_bus_messages_sent[i] = 0;
        server.cluster->stats_bus_messages_received[i] = 0;
    }
    server.cluster->stats_pfail_nodes = 0;
    memset(server.cluster->slots,0, sizeof(server.cluster->slots));
    clusterCloseAllSlots();

    /* Lock the cluster config file to make sure every node uses
     * its own nodes.conf. */
    //确保配置文件不被重复使用
    if (clusterLockConfig(server.cluster_configfile) == C_ERR)
        exit(1);

    /* Load or create a new nodes configuration. */
    //读取配置文件，如果没有则创建一个配置文件
    if (clusterLoadConfig(server.cluster_configfile) == C_ERR) {
        /* No configuration found. We will just use the random name provided
         * by the createClusterNode() function. */
        myself = server.cluster->myself =
            createClusterNode(NULL,CLUSTER_NODE_MYSELF|CLUSTER_NODE_MASTER);
        serverLog(LL_NOTICE,"No cluster configuration found, I'm %.40s",
            myself->name);
        clusterAddNode(myself);
        saveconf = 1;
    }
    if (saveconf) clusterSaveConfigOrDie(1);

    /* We need a listening TCP port for our cluster messaging needs. */
    server.cfd_count = 0;

    /* Port sanity check II
     * The other handshake port check is triggered too late to stop
     * us from trying to use a too-high cluster port number. */
    //集群总线端口默认为当前服务端口+10000
    //服务端口应设置为小于55535的值
    if (server.port > (65535-CLUSTER_PORT_INCR)) {
        serverLog(LL_WARNING, "Redis port number too high. "
                   "Cluster communication port is 10,000 port "
                   "numbers higher than your Redis port. "
                   "Your Redis port number must be "
                   "lower than 55535.");
        exit(1);
    }

    if (listenToPort(server.port+CLUSTER_PORT_INCR,
        server.cfd,&server.cfd_count) == C_ERR)
    {
        exit(1);
    } else {
        int j;
	
        //为监听的每个端口设置可读事件处理函数
        for (j = 0; j < server.cfd_count; j++) {
            if (aeCreateFileEvent(server.el, server.cfd[j], AE_READABLE,
                clusterAcceptHandler, NULL) == AE_ERR)
                    serverPanic("Unrecoverable error creating Redis Cluster "
                                "file event.");
        }
    }

    /* The slots -> keys map is a radix tree. Initialize it here. */
    //slots -> keys 是一个基数树(广泛用于查找与内存管理)
    server.cluster->slots_to_keys = raxNew();
    memset(server.cluster->slots_keys_count,0,
           sizeof(server.cluster->slots_keys_count));

    /* Set myself->port / cport to my listening ports, we'll just need to
     * discover the IP address via MEET messages. */
    //保存监听的两个端口
    myself->port = server.port;
    myself->cport = server.port+CLUSTER_PORT_INCR;
    if (server.cluster_announce_port)
        myself->port = server.cluster_announce_port;
    if (server.cluster_announce_bus_port)
        myself->cport = server.cluster_announce_bus_port;

    server.cluster->mf_end = 0;
    resetManualFailover();
}
```

**后台事件**

另外，在initServer中开启了一个后台事件，执行 `serverCron()` 函数(每1ms)，处理各种异步事务

```c
//server.c
#define run_with_period(_ms_) if ((_ms_ <= 1000/server.hz) || !(server.cronloops%((_ms_)/(1000/server.hz))))
//...
run_with_period(100) {
    if (server.cluster_enabled) clusterCron();
}
```

设置了每100ms执行一次 `clusterCron()` ，处理集群事务

后面的部分会对clusterCron()函数中比较重要的几块代码进行注释

**数据检查**

初始化结束，从磁盘中读取数据到数据库，在执行`loadDataFromDisk()`后要检查集群节点的数据是否正确

```c
//server.c - main()
loadDataFromDisk();
if (server.cluster_enabled) {
    if (verifyClusterConfigWithData() == C_ERR) {
         serverLog(LL_WARNING,
             "You can't have keys in a DB different than DB 0 when in "
             "Cluster mode. Exiting.");
         exit(1);
    }
}

//cluster.c
int verifyClusterConfigWithData(void) {
    int j;
    int update_config = 0;

    /* If this node is a slave, don't perform the check at all as we
     * completely depend on the replication stream. */
    //当前节点为从节点，不检查
    if (nodeIsSlave(myself)) return C_OK;

    /* Make sure we only have keys in DB0. */
    //只有0号数据库有数据
    for (j = 1; j < server.dbnum; j++) {
        if (dictSize(server.db[j].dict)) return C_ERR;
    }

    /* Check that all the slots we see populated memory have a corresponding
     * entry in the cluster table. Otherwise fix the table. */
    //确认是否所有slot都被覆盖
    for (j = 0; j < CLUSTER_SLOTS; j++) {
        //当前slot没有包含key，跳过
        if (!countKeysInSlot(j)) continue; /* No keys in this slot. */
        /* Check if we are assigned to this slot or if we are importing it.
         * In both cases check the next slot as the configuration makes
         * sense. */
        //跳过当前节点的slot
        //跳过要导入的slot
        if (server.cluster->slots[j] == myself ||
            server.cluster->importing_slots_from[j] != NULL) continue;

        /* If we are here data and cluster config don't agree, and we have
         * slot 'j' populated even if we are not importing it, nor we are
         * assigned to this slot. Fix this condition. */
        //需要更新配置的标志
        update_config++;
        /* Case A: slot is unassigned. Take responsibility for it. */
        //如果这个slot没被覆盖，则直接由当前节点负责
        if (server.cluster->slots[j] == NULL) {
            serverLog(LL_WARNING, "I have keys for unassigned slot %d. "
                                    "Taking responsibility for it.",j);
            clusterAddSlot(myself,j);
        } else {
            //若已被覆盖，则记录在importing_slots_from中
            serverLog(LL_WARNING, "I have keys for slot %d, but the slot is "
                                    "assigned to another node. "
                                    "Setting it to importing state.",j);
            server.cluster->importing_slots_from[j] = server.cluster->slots[j];
        }
    }
    //更新配置
    if (update_config) clusterSaveConfigOrDie(1);
    return C_OK;
}
```

##### 00x02 节点创建

---

创建一个节点实际上是将当前服务与集群节点信息关联，生成一个clusterNode数据结构

```c
//cluster.h
typedef struct clusterNode {
    mstime_t ctime; /* Node object creation time. */
    char name[CLUSTER_NAMELEN]; /* Node name, hex string, sha1-size */
    int flags;      /* CLUSTER_NODE_... */
    uint64_t configEpoch; /* Last configEpoch observed for this node */
    unsigned char slots[CLUSTER_SLOTS/8]; /* slots handled by this node */
    int numslots;   /* Number of slots handled by this node */
    int numslaves;  /* Number of slave nodes, if this is a master */
    struct clusterNode **slaves; /* pointers to slave nodes */
    struct clusterNode *slaveof; /* pointer to the master node. Note that it
                                    may be NULL even if the node is a slave
                                    if we don't have the master node in our
                                    tables. */
    mstime_t ping_sent;      /* Unix time we sent latest ping */
    mstime_t pong_received;  /* Unix time we received the pong */
    mstime_t fail_time;      /* Unix time when FAIL flag was set */
    mstime_t voted_time;     /* Last time we voted for a slave of this master */
    mstime_t repl_offset_time;  /* Unix time we received offset for this node */
    mstime_t orphaned_time;     /* Starting time of orphaned master condition */
    long long repl_offset;      /* Last known repl offset for this node. */
    char ip[NET_IP_STR_LEN];  /* Latest known IP address of this node */
    int port;                   /* Latest known clients port of this node */
    int cport;                  /* Latest known cluster port of this node. */
    clusterLink *link;          /* TCP/IP link with this node */
    list *fail_reports;         /* List of nodes signaling this as failing */
} clusterNode;

//cluster.c
clusterNode *createClusterNode(char *nodename, int flags) {
    clusterNode *node = zmalloc(sizeof(*node));

    if (nodename)
        memcpy(node->name, nodename, CLUSTER_NAMELEN);
    else
        getRandomHexChars(node->name, CLUSTER_NAMELEN);
    node->ctime = mstime();
    node->configEpoch = 0;
    node->flags = flags;
    memset(node->slots,0,sizeof(node->slots));
    node->numslots = 0;
    node->numslaves = 0;
    node->slaves = NULL;
    node->slaveof = NULL;
    node->ping_sent = node->pong_received = 0;
    node->fail_time = 0;
    node->link = NULL;
    memset(node->ip,0,sizeof(node->ip));
    node->port = 0;
    node->cport = 0;
    node->fail_reports = listCreate();
    node->voted_time = 0;
    node->orphaned_time = 0;
    node->repl_offset_time = 0;
    node->repl_offset = 0;
    listSetFreeMethod(node->fail_reports,zfree);
    return node;
}
```

##### 00x03 节点握手

---

clusterNode结构中的link保存的是包含当前结点与另一个结点连接信息的数据结构

server结构中有一个字典cluster，保存当前集群中的节点信息

```c
typedef struct clusterLink {
    mstime_t ctime;             /* Link creation time */
    int fd;                     /* TCP socket file descriptor */
    sds sndbuf;                 /* Packet send buffer */
    sds rcvbuf;                 /* Packet reception buffer */
    //与此连接关联的节点
    struct clusterNode *node;   /* Node related to this link if any, or NULL */
} clusterLink;

//向字典加入节点信息
int clusterAddNode(clusterNode *node) {
    int retval;

    retval = dictAdd(server.cluster->nodes,
            sdsnewlen(node->name,CLUSTER_NAMELEN), node);
    return (retval == DICT_OK) ? C_OK : C_ERR;
}
```

两个节点握手的基本流程：
1. A向B发送MEET消息
2. B接收并处理MEET消息，向A返回PONG消息
3. A接收并处理PONG消息，向B回复PING消息
4. 之后每隔1s就会发送一个PING消息进行故障检测

**准备发送MEET消息**

触发发送MEET消息的方法为执行 `CLUSTER MEET <ip> <port>` 命令

```c
//每个集群节点占用两个端口，客户端通讯端口与集群总线端口
//在默认情况下，集群总线端口编号为通讯端口+10000
//集群总线采用了与通讯端口不同的二进制协议，可以使节点间以更小流量与更短时间来交换信息
//用于节点的失效检测与配置更新等工作

#define CLUSTER_PORT_INCR 10000 /* Cluster port = baseport + PORT_INCR */

void clusterCommand(client *c) {
    if (server.cluster_enabled == 0) {
        addReplyError(c,"This instance has cluster support disabled");
        return;
    }
	
    if (!strcasecmp(c->argv[1]->ptr,"meet") && (c->argc == 4 || c->argc == 5)) {
        /* CLUSTER MEET <ip> <port> [cport] */
        long long port, cport;
		
        //获取通信端口编号
        if (getLongLongFromObject(c->argv[3], &port) != C_OK) {
            addReplyErrorFormat(c,"Invalid TCP base port specified: %s",
                                (char*)c->argv[3]->ptr);
            return;
        }
	    //获取集群总线端口编号(可选参数)
        if (c->argc == 5) {
            if (getLongLongFromObject(c->argv[4], &cport) != C_OK) {
                addReplyErrorFormat(c,"Invalid TCP bus port specified: %s",
                                    (char*)c->argv[4]->ptr);
                return;
            }
        //没有这一参数则默认为通信端口编号+10000
        } else {
            cport = port + CLUSTER_PORT_INCR;
        }
	    //尝试握手
        if (clusterStartHandshake(c->argv[2]->ptr,port,cport) == 0 &&
            errno == EINVAL)
        {
            addReplyErrorFormat(c,"Invalid node address specified: %s:%s",
                            (char*)c->argv[2]->ptr, (char*)c->argv[3]->ptr);
        } else {
            addReply(c,shared.ok);
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"nodes") && c->argc == 2) {
   		//......
    }
    //......
}

//准备开始握手
int clusterStartHandshake(char *ip, int port, int cport) {
    clusterNode *n;
    char norm_ip[NET_IP_STR_LEN];
    struct sockaddr_storage sa;

    /* IP sanity check */
    //ip可用性测试
    if (inet_pton(AF_INET,ip,
            &(((struct sockaddr_in *)&sa)->sin_addr)))
    {
        sa.ss_family = AF_INET;
    } else if (inet_pton(AF_INET6,ip,
            &(((struct sockaddr_in6 *)&sa)->sin6_addr)))
    {
        sa.ss_family = AF_INET6;
    } else {
        errno = EINVAL;
        return 0;
    }

    /* Port sanity check */
    //端口可用性测试
    if (port <= 0 || port > 65535 || cport <= 0 || cport > 65535) {
        errno = EINVAL;
        return 0;
    }

    /* Set norm_ip as the normalized string representation of the node
     * IP address. */
    //设置节点地址的标准字符串
    memset(norm_ip,0,NET_IP_STR_LEN);
    if (sa.ss_family == AF_INET)
        inet_ntop(AF_INET,
            (void*)&(((struct sockaddr_in *)&sa)->sin_addr),
            norm_ip,NET_IP_STR_LEN);
    else
        inet_ntop(AF_INET6,
            (void*)&(((struct sockaddr_in6 *)&sa)->sin6_addr),
            norm_ip,NET_IP_STR_LEN);
	
    //检查这个地址是否正在进行握手
    if (clusterHandshakeInProgress(norm_ip,port,cport)) {
        errno = EAGAIN;
        return 0;
    }

    /* Add the node with a random address (NULL as first argument to
     * createClusterNode()). Everything will be fixed during the
     * handshake. */
    //创建一个名字随机的节点
    n = createClusterNode(NULL,CLUSTER_NODE_HANDSHAKE|CLUSTER_NODE_MEET);
    memcpy(n->ip,norm_ip,sizeof(n->ip));
    n->port = port;
    n->cport = cport;
    //将握手的节点信息保存到当前节点的cluster字典中
    clusterAddNode(n);
    return 1;
}
```

这时MEET消息只是准备好发送，实际上并没有发送

发送MEET消息的动作在clusterCron()函数中周期性执行

```c
void clusterCron(void) {
	//......
	/* The handshake timeout is the time after which a handshake node that was
     * not turned into a normal node is removed from the nodes. Usually it is
     * just the NODE_TIMEOUT value, but when NODE_TIMEOUT is too small we use
     * the value of 1 second. */
    //握手被要求在设置的超时时间内完成，最小为1s
    handshake_timeout = server.cluster_node_timeout;
    if (handshake_timeout < 1000) handshake_timeout = 1000;

    /* Check if we have disconnected nodes and re-establish the connection.
     * Also update a few stats while we are here, that can be used to make
     * better decisions in other part of the code. */
    //检查是否有断开或进行过重连的节点
    di = dictGetSafeIterator(server.cluster->nodes);
    server.cluster->stats_pfail_nodes = 0;
    while((de = dictNext(di)) != NULL) {
        clusterNode *node = dictGetVal(de);

        /* Not interested in reconnecting the link with myself or nodes
         * for which we have no address. */
        //跳过本节点与地址未知的节点
        if (node->flags & (CLUSTER_NODE_MYSELF|CLUSTER_NODE_NOADDR)) continue;
		
        //检查是否为 可能失效状态
        if (node->flags & CLUSTER_NODE_PFAIL)
            server.cluster->stats_pfail_nodes++;

        /* A Node in HANDSHAKE state has a limited lifespan equal to the
         * configured node timeout. */
        //检查握手是否超时
        if (nodeInHandshake(node) && now - node->ctime > handshake_timeout) {
            //超时会被删除，跳过
            clusterDelNode(node);
            continue;
        }
		
        //如果与这个节点连接为空
        if (node->link == NULL) {
            int fd;
            mstime_t old_ping_sent;
            clusterLink *link;
			
            //尝试连接这个节点
            fd = anetTcpNonBlockBindConnect(server.neterr, node->ip,
                node->cport, NET_FIRST_BIND_ADDR);
            //连接失败，跳过
            if (fd == -1) {
                /* We got a synchronous error from connect before
                 * clusterSendPing() had a chance to be called.
                 * If node->ping_sent is zero, failure detection can't work,
                 * so we claim we actually sent a ping now (that will
                 * be really sent as soon as the link is obtained). */
                if (node->ping_sent == 0) node->ping_sent = mstime();
                serverLog(LL_DEBUG, "Unable to connect to "
                    "Cluster Node [%s]:%d -> %s", node->ip,
                    node->cport, server.neterr);
                continue;
            }
            //连接成功，创建连接信息结构
            link = createClusterLink(node);
            link->fd = fd;
            node->link = link;
            //设置可读事件的处理函数
            aeCreateFileEvent(server.el,link->fd,AE_READABLE,
                    clusterReadHandler,link);
            /* Queue a PING in the new connection ASAP: this is crucial
             * to avoid false positives in failure detection.
             *
             * If the node is flagged as MEET, we send a MEET message instead
             * of a PING one, to force the receiver to add us in its node
             * table. */
            //保存原PING命令发送的事件
            old_ping_sent = node->ping_sent;
            //发送一个MEET/PING命令
            clusterSendPing(link, node->flags & CLUSTER_NODE_MEET ?
                    CLUSTERMSG_TYPE_MEET : CLUSTERMSG_TYPE_PING);
            //如果之前发送过PING命令，则要还原
            if (old_ping_sent) {
                /* If there was an active ping before the link was
                 * disconnected, we want to restore the ping time, otherwise
                 * replaced by the clusterSendPing() call. */
                node->ping_sent = old_ping_sent;
            }
            /* We can clear the flag after the first packet is sent.
             * If we'll never receive a PONG, we'll never send new packets
             * to this node. Instead after the PONG is received and we
             * are no longer in meet/handshake status, we want to send
             * normal PING packets. */
            //清除MEET标识
            node->flags &= ~CLUSTER_NODE_MEET;

            serverLog(LL_DEBUG,"Connecting with Node %.40s at %s:%d",
                    node->name, node->ip, node->cport);
        }
    }
    dictReleaseIterator(di);
	//......
}
```

**双方握手消息处理流程**

1. 在clusterCron中，A在发送MEET消息前先用aeCreateFileEvent()将clusterReadHandler()加入事件循环监听与B建立的连接，等待可能返回的PONG消息

   clusterReadHandler()用于处理消息头部并读出完整信息

```c
/* Read data. Try to read the first field of the header first to check the
 * full length of the packet. When a whole packet is in memory this function
 * will call the function to process the packet. And so forth. */
void clusterReadHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    char buf[sizeof(clusterMsg)];
    ssize_t nread;
    clusterMsg *hdr;
    clusterLink *link = (clusterLink*) privdata;
    unsigned int readlen, rcvbuflen;
    UNUSED(el);
    UNUSED(mask);
	
    //从socket中读取数据
    while(1) { /* Read as long as there is data to read. */
        //获取对当前连接的接收缓冲区大小
        rcvbuflen = sdslen(link->rcvbuf);
        //长度小于8，无法从一次读出的信息中获取消息总长
        if (rcvbuflen < 8) {
            /* First, obtain the first 8 bytes to get the full message
             * length. */
            //需要再读的信息长度
            readlen = 8 - rcvbuflen;
        } else {
            /* Finally read the full message. */
            hdr = (clusterMsg*) link->rcvbuf;
            if (rcvbuflen == 8) {
                /* Perform some sanity check on the message signature
                 * and length. */
                //前四字节要为RCmb，否则释放该连接
                if (memcmp(hdr->sig,"RCmb",4) != 0 ||
                    ntohl(hdr->totlen) < CLUSTERMSG_MIN_LEN)
                {
                    serverLog(LL_WARNING,
                        "Bad message length or signature received "
                        "from Cluster bus.");
                    handleLinkIOError(link);
                    return;
                }
            }
            //已读入的内容长度
            readlen = ntohl(hdr->totlen) - rcvbuflen;
            if (readlen > sizeof(buf)) readlen = sizeof(buf);
        }

        //从socket中读数据
        nread = read(fd,buf,readlen);
        //空读
        if (nread == -1 && errno == EAGAIN) return; /* No more data ready. */
        //读取出错
        if (nread <= 0) {
            /* I/O error... */
            serverLog(LL_DEBUG,"I/O error reading from node link: %s",
                (nread == 0) ? "connection closed" : strerror(errno));
            handleLinkIOError(link);
            return;
        } else {
            //读取成功，追加到接收缓冲区中
            /* Read data and recast the pointer to the new buffer. */
            link->rcvbuf = sdscatlen(link->rcvbuf,buf,nread);
            hdr = (clusterMsg*) link->rcvbuf;
            rcvbuflen += nread;
        }

        /* Total length obtained? Process this packet. */
        //检查数据完整性
        if (rcvbuflen >= 8 && rcvbuflen == ntohl(hdr->totlen)) {
            if (clusterProcessPacket(link)) {
                sdsfree(link->rcvbuf);
                link->rcvbuf = sdsempty();
            } else {
                return; /* Link no longer valid. */
            }
        }
    }
}
```

2. A与B建立连接时会触发B的clusterAcceptHandler()函数，类似socket的accept()，创建了link信息并对可读socket(fd 文件描述符)设置clusterReadHandler()

   收到一条消息后，clusterReadHandler()将socket的数据读到clusterLink的rcvbuf(接收缓冲区)并判断消息是否读取完整

   完成接收，调用通用函数clusterProcessPacket()处理各种类型的消息

   此时为处理MEET并调用clusterSendPing()发送PONG消息

```c
int clusterProcessPacket(clusterLink *link) {
    //......
    /* Check if the sender is a known node. */
    //从集群中查找sender节点
    sender = clusterLookupNode(hdr->sender);
    //如果存在并且其未处于握手状态
    if (sender && !nodeInHandshake(sender)) {
        /* Update our curretEpoch if we see a newer epoch in the cluster. */
        //更新集群纪元
        senderCurrentEpoch = ntohu64(hdr->currentEpoch);
        senderConfigEpoch = ntohu64(hdr->configEpoch);
        //更新集群当前纪元
        if (senderCurrentEpoch > server.cluster->currentEpoch)
            server.cluster->currentEpoch = senderCurrentEpoch;
        /* Update the sender configEpoch if it is publishing a newer one. */
        //更新sender信息中的配置纪元
        if (senderConfigEpoch > sender->configEpoch) {
            sender->configEpoch = senderConfigEpoch;
            //设置要更新配置和状态的标志
            clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                 CLUSTER_TODO_FSYNC_CONFIG);
        }
        /* Update the replication offset info for this node. */
        //更新复制偏移量与更新复制偏移量的时间
        sender->repl_offset = ntohu64(hdr->offset);
        sender->repl_offset_time = mstime();
        /* If we are a slave performing a manual failover and our master
         * sent its offset while already paused, populate the MF state. */
        //如果当前节点时正在进行手动故障转移的从节点
        //sender节点为当前节点的主节点
        //并且主节点发送复制偏移量时，已经暂停手动故障转移的动作
        if (server.cluster->mf_end &&
            nodeIsSlave(myself) &&
            myself->slaveof == sender &&
            hdr->mflags[0] & CLUSTERMSG_FLAG0_PAUSED &&
            server.cluster->mf_master_offset == 0)
        {
            //设置从节点已复制的偏移量
            server.cluster->mf_master_offset = sender->repl_offset;
            serverLog(LL_WARNING,
                "Received replication offset for paused "
                "master manual failover: %lld",
                server.cluster->mf_master_offset);
        }
    }
    
    /* Initial processing of PING and MEET requests replying with a PONG. */
    //处理MEET与PING，并用PONG回复
    if (type == CLUSTERMSG_TYPE_PING || type == CLUSTERMSG_TYPE_MEET) {
        serverLog(LL_DEBUG,"Ping packet received: %p", (void*)link->node);

        /* We use incoming MEET messages in order to set the address
         * for 'myself', since only other cluster nodes will send us
         * MEET messages on handshakes, when the cluster joins, or
         * later if we changed address, and those nodes will use our
         * official address to connect to us. So by obtaining this address
         * from the socket is a simple way to discover / update our own
         * address in the cluster without it being hardcoded in the config.
         *
         * However if we don't have an address at all, we update the address
         * even with a normal PING packet. If it's wrong it will be fixed
         * by MEET later. */
        
        //如果是MEET消息，或者是其他消息但当前集群节点的ip记录为空
        if ((type == CLUSTERMSG_TYPE_MEET || myself->ip[0] == '\0') &&
            server.cluster_announce_ip == NULL)
        {
            char ip[NET_IP_STR_LEN];
            //根据socket获取自己的ip，并更新myself信息
            if (anetSockName(link->fd,ip,sizeof(ip),NULL) != -1 &&
                strcmp(ip,myself->ip))
            {
                memcpy(myself->ip,ip,NET_IP_STR_LEN);
                serverLog(LL_WARNING,"IP address for this node updated to %s",
                    myself->ip);
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG);
            }
        }

        /* Add this node if it is new for us and the msg type is MEET.
         * In this stage we don't try to add the node with the right
         * flags, slaveof pointer, and so forth, as this details will be
         * resolved when we'll receive PONGs from the node. */
        //如果没有sender，即这个消息来自未知的节点，且消息类型未MEET
        if (!sender && type == CLUSTERMSG_TYPE_MEET) {
            clusterNode *node;
            //创建一个处于握手状态的节点
            node = createClusterNode(NULL,CLUSTER_NODE_HANDSHAKE);
            nodeIp2String(node->ip,link,hdr->myip);
            node->port = ntohs(hdr->port);
            node->cport = ntohs(hdr->cport);
            //添加到集群中
            clusterAddNode(node);
            clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG);
        }

        /* If this is a MEET packet from an unknown node, we still process
         * the gossip section here since we have to trust the sender because
         * of the message type. */
        //未知节点MEET，处理gossip协议信息
        if (!sender && type == CLUSTERMSG_TYPE_MEET)
            clusterProcessGossipSection(hdr,link);

        /* Anyway reply with a PONG */
        //回复一个PONG
        clusterSendPing(link,CLUSTERMSG_TYPE_PONG);
    }
```

3. 之后A同样通过clusterProcessPacket()处理PONG消息

```c
//接上一块代码
	/* PING, PONG, MEET: process config information. */
	//处理配置信息
    if (type == CLUSTERMSG_TYPE_PING || type == CLUSTERMSG_TYPE_PONG ||
        type == CLUSTERMSG_TYPE_MEET)
    {
        serverLog(LL_DEBUG,"%s packet received: %p",
            type == CLUSTERMSG_TYPE_PING ? "ping" : "pong",
            (void*)link->node);
        //该连接的节点存在
        if (link->node) {
            //并且该节点处于握手状态
            if (nodeInHandshake(link->node)) {
                /* If we already have this node, try to change the
                 * IP/port of the node with the new one. */
                //sender节点在集群信息中存在
                if (sender) {
                    serverLog(LL_VERBOSE,
                        "Handshake: we already know node %.40s, "
                        "updating the address if needed.", sender->name);
                    //在必要的情况下更新地址
                    if (nodeUpdateAddressIfNeeded(sender,link,hdr))
                    {
                        clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                             CLUSTER_TODO_UPDATE_STATE);
                    }
                    /* Free this node as we already have it. This will
                     * cause the link to be freed as well. */
                    //释放连接信息中的节点
                    clusterDelNode(link->node);
                    return 0;
                }

                /* First thing to do is replacing the random name with the
                 * right node name if this was a handshake stage. */
                //将连接关联的节点重命名为sender的名字
                clusterRenameNode(link->node, hdr->sender);
                serverLog(LL_DEBUG,"Handshake with node %.40s completed.",
                    link->node->name);
                //取消握手状态，设置节点是主节点还是从节点
                link->node->flags &= ~CLUSTER_NODE_HANDSHAKE;
                link->node->flags |= flags&(CLUSTER_NODE_MASTER|CLUSTER_NODE_SLAVE);
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG);
            //两节点不相同
            } else if (memcmp(link->node->name,hdr->sender,
                        CLUSTER_NAMELEN) != 0)
            {
                /* If the reply has a non matching node ID we
                 * disconnect this node and set it as not having an associated
                 * address. */
                serverLog(LL_DEBUG,"PONG contains mismatching sender ID. About node %.40s added %d ms ago, having flags %d",
                    link->node->name,
                    (int)(mstime()-(link->node->ctime)),
                    link->node->flags);
                //设置NOADDR标志
                link->node->flags |= CLUSTER_NODE_NOADDR;
                //清除关联节点地址信息
                link->node->ip[0] = '\0';
                link->node->port = 0;
                link->node->cport = 0;
                //释放连接
                freeClusterLink(link);
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG);
                return 0;
            }
        }

        /* Update the node address if it changed. */
        //对于PING消息，可尝试更新连接地址
        if (sender && type == CLUSTERMSG_TYPE_PING &&
            !nodeInHandshake(sender) &&
            nodeUpdateAddressIfNeeded(sender,link,hdr))
        {
            clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                 CLUSTER_TODO_UPDATE_STATE);
        }
        
        /* Update our info about the node */
        //link关联节点存在，并发来PONG消息
        if (link->node && type == CLUSTERMSG_TYPE_PONG) {
            //更新最近一次接收到PONG消息的时间
            link->node->pong_received = mstime();
            //清空最近一次发送PING消息的时间
            link->node->ping_sent = 0;

            /* The PFAIL condition can be reversed without external
             * help if it is momentary (that is, if it does not
             * turn into a FAIL state).
             *
             * The FAIL condition is also reversible under specific
             * conditions detected by clearNodeFailureIfNeeded(). */
            //可取消PFAIL标识
            if (nodeTimedOut(link->node)) {
                link->node->flags &= ~CLUSTER_NODE_PFAIL;
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                     CLUSTER_TODO_UPDATE_STATE);
            //如果这个节点已经下线了
            } else if (nodeFailed(link->node)) {
                //尝试取消下线标识
                clearNodeFailureIfNeeded(link->node);
            }
        }
        //......
    }
	//......
}
```

与B处理MEET消息不同的是，A处理PONG后不会直接发送PING消息，而是清除上次发送的时间戳，以触发clusterCron()中的事件

```c
while((de = dictNext(di)) != NULL) {
    clusterNode *node = dictGetVal(de);
    now = mstime(); /* Use an updated time at every iteration. */
    mstime_t delay;
    //......
    if (node->link &&
        node->ping_sent == 0 &&
        (now - node->pong_received) > server.cluster_node_timeout/2)
    {
        clusterSendPing(node->link, CLUSTERMSG_TYPE_PING);
        continue;
    }
    //......
}
dictReleaseIterator(di);
```

##### 00x04 Gossip协议

---

每次将新节点纳入集群，仅会进行两个节点间的通信

刚刚纳入新节点时，集群节点的信息会处于不统一的状态

更改配置，运行状态变更(节点失效)也会导致类似的状况

redis的节点间使用gossip协议进行工作，使用这种带冗余的容错算法保持集群节点的最终一致性

gossip在节点间传递三种类型的消息，MEET，PING，PONG

同另外三种redis消息UPDATE，PUBLISH与FAIL一样被抽象为clusterMsgData结构

```c
union clusterMsgData {
    /* PING, MEET and PONG */
    struct {
        /* Array of N clusterMsgDataGossip structures */
        clusterMsgDataGossip gossip[1];
    } ping;

    /* FAIL */
    struct {
        clusterMsgDataFail about;
    } fail;

    /* PUBLISH */
    struct {
        clusterMsgDataPublish msg;
    } publish;

    /* UPDATE */
    struct {
        clusterMsgDataUpdate nodecfg;
    } update;
};
```

很明显可以看出，gossip所使用的消息进一步细化为clusterMsgDataGossip结构

并且，在clusterMsgDataGossip中被声明为数组，可存放多个节点的信息

```c
typedef struct {
    char nodename[CLUSTER_NAMELEN];
    uint32_t ping_sent;
    uint32_t pong_received;
    char ip[NET_IP_STR_LEN];  /* IP address last time it was seen */
    uint16_t port;              /* base port last time it was seen */
    uint16_t cport;             /* cluster port last time it was seen */
    uint16_t flags;             /* node->flags copy */
    uint32_t notused1;
} clusterMsgDataGossip;
```

**Gossip系消息实现**

发送PING或PONG消息(实际上发送MEET消息也使用这个函数)

执行中会随机选取当前节点已存在的节点信息放入消息以支持Gossip协议

```c
/* Send a PING or PONG packet to the specified node, making sure to add enough
 * gossip informations. */
void clusterSendPing(clusterLink *link, int type) {
    unsigned char *buf;
    clusterMsg *hdr;
    int gossipcount = 0; /* Number of gossip sections added so far. */
    int wanted; /* Number of gossip sections we want to append if possible. */
    int totlen; /* Total packet length. */
    /* freshnodes is the max number of nodes we can hope to append at all:
     * nodes available minus two (ourself and the node we are sending the
     * message to). However practically there may be less valid nodes since
     * nodes in handshake state, disconnected, are not considered. */
    int freshnodes = dictSize(server.cluster->nodes)-2;

    /* How many gossip sections we want to add? 1/10 of the number of nodes
     * and anyway at least 3. Why 1/10?
     *
     * If we have N masters, with N/10 entries, and we consider that in
     * node_timeout we exchange with each other node at least 4 packets
     * (we ping in the worst case in node_timeout/2 time, and we also
     * receive two pings from the host), we have a total of 8 packets
     * in the node_timeout*2 falure reports validity time. So we have
     * that, for a single PFAIL node, we can expect to receive the following
     * number of failure reports (in the specified window of time):
     *
     * PROB * GOSSIP_ENTRIES_PER_PACKET * TOTAL_PACKETS:
     *
     * PROB = probability of being featured in a single gossip entry,
     *        which is 1 / NUM_OF_NODES.
     * ENTRIES = 10.
     * TOTAL_PACKETS = 2 * 4 * NUM_OF_MASTERS.
     *
     * If we assume we have just masters (so num of nodes and num of masters
     * is the same), with 1/10 we always get over the majority, and specifically
     * 80% of the number of nodes, to account for many masters failing at the
     * same time.
     *
     * Since we have non-voting slaves that lower the probability of an entry
     * to feature our node, we set the number of entires per packet as
     * 10% of the total nodes we have. */
    wanted = floor(dictSize(server.cluster->nodes)/10);
    if (wanted < 3) wanted = 3;
    if (wanted > freshnodes) wanted = freshnodes;

    /* Include all the nodes in PFAIL state, so that failure reports are
     * faster to propagate to go from PFAIL to FAIL state. */
    int pfail_wanted = server.cluster->stats_pfail_nodes;

    /* Compute the maxium totlen to allocate our buffer. We'll fix the totlen
     * later according to the number of gossip sections we really were able
     * to put inside the packet. */
    totlen = sizeof(clusterMsg)-sizeof(union clusterMsgData);
    totlen += (sizeof(clusterMsgDataGossip)*(wanted+pfail_wanted));
    /* Note: clusterBuildMessageHdr() expects the buffer to be always at least
     * sizeof(clusterMsg) or more. */
    if (totlen < (int)sizeof(clusterMsg)) totlen = sizeof(clusterMsg);
    buf = zcalloc(totlen);
    hdr = (clusterMsg*) buf;

    /* Populate the header. */
    if (link->node && type == CLUSTERMSG_TYPE_PING)
        link->node->ping_sent = mstime();
    clusterBuildMessageHdr(hdr,type);

    /* Populate the gossip fields */
    int maxiterations = wanted*3;
    while(freshnodes > 0 && gossipcount < wanted && maxiterations--) {
        dictEntry *de = dictGetRandomKey(server.cluster->nodes);
        clusterNode *this = dictGetVal(de);

        /* Don't include this node: the whole packet header is about us
         * already, so we just gossip about other nodes. */
        if (this == myself) continue;

        /* PFAIL nodes will be added later. */
        if (this->flags & CLUSTER_NODE_PFAIL) continue;

        /* In the gossip section don't include:
         * 1) Nodes in HANDSHAKE state.
         * 3) Nodes with the NOADDR flag set.
         * 4) Disconnected nodes if they don't have configured slots.
         */
        if (this->flags & (CLUSTER_NODE_HANDSHAKE|CLUSTER_NODE_NOADDR) ||
            (this->link == NULL && this->numslots == 0))
        {
            freshnodes--; /* Tecnically not correct, but saves CPU. */
            continue;
        }

        /* Do not add a node we already have. */
        if (clusterNodeIsInGossipSection(hdr,gossipcount,this)) continue;

        /* Add it */
        clusterSetGossipEntry(hdr,gossipcount,this);
        freshnodes--;
        gossipcount++;
    }

    /* If there are PFAIL nodes, add them at the end. */
    if (pfail_wanted) {
        dictIterator *di;
        dictEntry *de;

        di = dictGetSafeIterator(server.cluster->nodes);
        while((de = dictNext(di)) != NULL && pfail_wanted > 0) {
            clusterNode *node = dictGetVal(de);
            if (node->flags & CLUSTER_NODE_HANDSHAKE) continue;
            if (node->flags & CLUSTER_NODE_NOADDR) continue;
            if (!(node->flags & CLUSTER_NODE_PFAIL)) continue;
            clusterSetGossipEntry(hdr,gossipcount,node);
            freshnodes--;
            gossipcount++;
            /* We take the count of the slots we allocated, since the
             * PFAIL stats may not match perfectly with the current number
             * of PFAIL nodes. */
            pfail_wanted--;
        }
        dictReleaseIterator(di);
    }

    /* Ready to send... fix the totlen fiend and queue the message in the
     * output buffer. */
    totlen = sizeof(clusterMsg)-sizeof(union clusterMsgData);
    totlen += (sizeof(clusterMsgDataGossip)*gossipcount);
    hdr->count = htons(gossipcount);
    hdr->totlen = htonl(totlen);
    clusterSendMessage(link,buf,totlen);
    zfree(buf);
}
```

**节点信息的选取**

1. 不包括当前节点，因为在消息头中会包含当前节点信息
2. 

#### 数据分布

##### 00x05 slot分配

---

`CLUSTER ADDSLOTS` 命令用于向当(client连入的)节点分配指定slots

从节点的角度看

- clusterNode中的slots数组记录节点分配的slot，对应位置值为1，其余为0
- numslots则记录此节点负责的slot总数

从整个集群的视角来看

- clusterState中slots数组长度为16384，即总slot数，数据类型为clusterNode，记录slot与集群中所有**主节点**的映射关系
- slots_to_keys数据类型为skiplist，用于实现 `CLUSTER GETKEYSINSLOT` 命令，效果为获取属于同一slot的多个键
- 在重新分片时，migrating_slots_to与importing_slots_to这两个数据类型为clusterNode，同样长为16384的数组，分别用于记录slots从节点导出与导入的情况

`CLUSTER ADDSLOTS/DELSLOTS` 命令在clusterCommand()函数中实现

```c
void clusterCommand(client *c) {
    //......
    //slot操作部分
    } else if ((!strcasecmp(c->argv[1]->ptr,"addslots") ||
               !strcasecmp(c->argv[1]->ptr,"delslots")) && c->argc >= 3)
    {
        /* CLUSTER ADDSLOTS <slot> [slot] ... */
        /* CLUSTER DELSLOTS <slot> [slot] ... */
        int j, slot;
        unsigned char *slots = zmalloc(CLUSTER_SLOTS);
    	//DELSLOTS命令
        int del = !strcasecmp(c->argv[1]->ptr,"delslots");

        memset(slots,0,CLUSTER_SLOTS);
        /* Check that all the arguments are parseable and that all the
         * slots are not already busy. */
    	//遍历参数中指定的slot，排除三种不能处理的情况
        for (j = 2; j < c->argc; j++) {
            if ((slot = getSlotOrReply(c,c->argv[j])) == -1) {
                zfree(slots);
                return;
            }
            //要删除，但slot无所属节点
            if (del && server.cluster->slots[slot] == NULL) {
                addReplyErrorFormat(c,"Slot %d is already unassigned", slot);
                zfree(slots);
                return;
            //要添加，但slot已有所属节点
            } else if (!del && server.cluster->slots[slot]) {
                addReplyErrorFormat(c,"Slot %d is already busy", slot);
                zfree(slots);
                return;
            }
            //slot在参数中出现多次
            if (slots[slot]++ == 1) {
                addReplyErrorFormat(c,"Slot %d specified multiple times",
                    (int)slot);
                zfree(slots);
                return;
            }
        }
    	//再次遍历，进行槽位操作
        for (j = 0; j < CLUSTER_SLOTS; j++) {
            if (slots[j]) {
                int retval;

                /* If this slot was set as importing we can clear this
                 * state as now we are the real owner of the slot. */
                //清除导入状态，让这个slot归属于当前节点
                if (server.cluster->importing_slots_from[j])
                    server.cluster->importing_slots_from[j] = NULL;
                //执行操作
                retval = del ? clusterDelSlot(j) :
                               clusterAddSlot(myself,j);
                serverAssertWithInfo(c,NULL,retval == C_OK);
            }
        }
        zfree(slots);
    	//保存状态与配置
        clusterDoBeforeSleep(CLUSTER_TODO_UPDATE_STATE|CLUSTER_TODO_SAVE_CONFIG);
        addReply(c,shared.ok);
	} //......
	//......
}

//跟进add操作
int clusterAddSlot(clusterNode *n, int slot) {
    //与刚才的检查重复了
    if (server.cluster->slots[slot]) return C_ERR;
    //设置slot的归属
    clusterNodeSetSlotBit(n,slot);
    //设置负责该slot的节点
    server.cluster->slots[slot] = n;
    return C_OK;
}

//分配槽位底层实现
int clusterNodeSetSlotBit(clusterNode *n, int slot) {
    //好像又重复了，检查slot是否已被设置
    int old = bitmapTestBit(n->slots,slot);
    //slot设置为1，下方有详细注释
    bitmapSetBit(n->slots,slot);
    if (!old) {
        //更新节点负责的slot的数目
        n->numslots++;
        /* When a master gets its first slot, even if it has no slaves,
         * it gets flagged with MIGRATE_TO, that is, the master is a valid
         * target for replicas migration, if and only if at least one of
         * the other masters has slaves right now.
         *
         * Normally masters are valid targerts of replica migration if:
         * 1. The used to have slaves (but no longer have).
         * 2. They are slaves failing over a master that used to have slaves.
         *
         * However new masters with slots assigned are considered valid
         * migration tagets if the rest of the cluster is not a slave-less.
         *
         * See https://github.com/antirez/redis/issues/3043 for more info. */
        //如果是第一次被分配slot，且没有从节点，则设置可迁移标志
        if (n->numslots == 1 && clusterMastersHaveSlaves())
            n->flags |= CLUSTER_NODE_MIGRATE_TO;
    }
    return old;
}

```

##### 00x06 分布存储

---

要将数据正确地存到所属slot对应的节点，需要事先获知其他主节点负责的slots

这种信息同步由发送消息实现，可能包括slot信息的消息有MEET，PONG，PING和UPDATE

**消息发送**

clusterBuildMessageHdr()函数用于构建消息头，其中会包括节点的槽位信息

clusterProcessPacket()处理消息时会检测并尝试读取槽位信息(代码注释见*握手-消息处理流程*)

```c
void clusterBuildMessageHdr(clusterMsg *hdr, int type) {
    int totlen = 0;
    uint64_t offset;
    clusterNode *master;

    /* If this node is a master, we send its slots bitmap and configEpoch.
     * If this node is a slave we send the master's information instead (the
     * node is flagged as slave so the receiver knows that it is NOT really
     * in charge for this slots. */
    //当前节点为主节点，发送slot bitmap与配置纪元
    //当前节点为从节点，发送其所属主节点的slot bitmap与配置纪元
    master = (nodeIsSlave(myself) && myself->slaveof) ?
              myself->slaveof : myself;

    memset(hdr,0,sizeof(*hdr));
    //消息在头部加入签名，没有签名会被断开连接
    hdr->ver = htons(CLUSTER_PROTO_VER);
    hdr->sig[0] = 'R';
    hdr->sig[1] = 'C';
    hdr->sig[2] = 'm';
    hdr->sig[3] = 'b';
    //设置消息类型
    hdr->type = htons(type);
    //加入当前节点的名称
    memcpy(hdr->sender,myself->name,CLUSTER_NAMELEN);

    /* If cluster-announce-ip option is enabled, force the receivers of our
     * packets to use the specified address for this node. Otherwise if the
     * first byte is zero, they'll do auto discovery. */
    //清空ip信息
    memset(hdr->myip,0,NET_IP_STR_LEN);
    //将设置在集群节点间使用的本节点ip地址写入hdr->myip
    if (server.cluster_announce_ip) {
        strncpy(hdr->myip,server.cluster_announce_ip,NET_IP_STR_LEN);
        hdr->myip[NET_IP_STR_LEN-1] = '\0';
    }

    /* Handle cluster-announce-port as well. */
    //确定服务与集群总线端口
    int announced_port = server.cluster_announce_port ?
                         server.cluster_announce_port : server.port;
    int announced_cport = server.cluster_announce_bus_port ?
                          server.cluster_announce_bus_port :
                          (server.port + CLUSTER_PORT_INCR);
	
    //向消息头中加入slot信息
    memcpy(hdr->myslots,master->slots,sizeof(hdr->myslots));
    //如果当前节点为从节点，设置主节点名称
    memset(hdr->slaveof,0,CLUSTER_NAMELEN);
    if (myself->slaveof != NULL)
        memcpy(hdr->slaveof,myself->slaveof->name, CLUSTER_NAMELEN);
    //设置端口，节点类型，集群状态
    hdr->port = htons(announced_port);
    hdr->cport = htons(announced_cport);
    hdr->flags = htons(myself->flags);
    hdr->state = server.cluster->state;

    /* Set the currentEpoch and configEpochs. */
    //设置当前纪元与配置纪元
    hdr->currentEpoch = htonu64(server.cluster->currentEpoch);
    hdr->configEpoch = htonu64(master->configEpoch);

    /* Set the replication offset. */
    //如果当前节点为从节点，设置复制偏移量
    //为主节点，设置主节点的复制偏移量
    if (nodeIsSlave(myself))
        offset = replicationGetSlaveOffset();
    else
        offset = server.master_repl_offset;
    hdr->offset = htonu64(offset);

    /* Set the message flags. */
    //设置信息标志
    if (nodeIsMaster(myself) && server.cluster->mf_end)
        hdr->mflags[0] |= CLUSTERMSG_FLAG0_PAUSED;

    /* Compute the message length for certain messages. For other messages
     * this is up to the caller. */
    //如果为FAIL/UPDATE消息，计算消息总长度
    if (type == CLUSTERMSG_TYPE_FAIL) {
        totlen = sizeof(clusterMsg)-sizeof(union clusterMsgData);
        totlen += sizeof(clusterMsgDataFail);
    } else if (type == CLUSTERMSG_TYPE_UPDATE) {
        totlen = sizeof(clusterMsg)-sizeof(union clusterMsgData);
        totlen += sizeof(clusterMsgDataUpdate);
    }
    //设置总长
    hdr->totlen = htonl(totlen);
    /* For PING, PONG, and MEET, fixing the totlen field is up to the caller. */
}
```

**记录更新**

clusterProcessPacket() 中确认消息来自一主节点，并且有slot信息需要更新，则会调用clusterUpdateSlotsConfigWith() 函数对当前节点的记录进行更新

```c
int clusterProcessPacket(clusterLink *link) {
    //......
    if (type == CLUSTERMSG_TYPE_PING || type == CLUSTERMSG_TYPE_PONG ||
        type == CLUSTERMSG_TYPE_MEET)
    {
        //......
		/* Update our info about served slots.
         *
         * Note: this MUST happen after we update the master/slave state
         * so that CLUSTER_NODE_MASTER flag will be set. */

        /* Many checks are only needed if the set of served slots this
         * instance claims is different compared to the set of slots we have
         * for it. Check this ASAP to avoid other computational expansive
         * checks later. */
        //更新当前节点负责slot的信息
        //与握手第三步，主动节点处理PONG消息的代码处于同一if块内
        //两者中间隔的部分是检测主从切换与更新信息的代码
        //而且下面的操作不行在更新主从状态后进行，因为需要CLUSTER_NODE_MASTER标志
        clusterNode *sender_master = NULL; /* Sender or its master if slave. */
        int dirty_slots = 0; /* Sender claimed slots don't match my view? */

        if (sender) {
            //如果sender是主节点，直接获取其信息
            //如果是从节点，则获取其所属主节点的信息
            sender_master = nodeIsMaster(sender) ? sender : sender->slaveof;
            if (sender_master) {
                //对比从对方那里获取的信息与当前节点视角下保存的集群slot信息
                //dirty_slots不为0表示有差异
                dirty_slots = memcmp(sender_master->slots,
                        hdr->myslots,sizeof(hdr->myslots)) != 0;
            }
        }

        /* 1) If the sender of the message is a master, and we detected that
         *    the set of slots it claims changed, scan the slots to see if we
         *    need to update our configuration. */
        //1.sender是一个主节点，但slot信息不匹配
        if (sender && nodeIsMaster(sender) && dirty_slots)
            //更新当前节点视角下sender的信息
            clusterUpdateSlotsConfigWith(sender,senderConfigEpoch,hdr->myslots);

        /* 2) We also check for the reverse condition, that is, the sender
         *    claims to serve slots we know are served by a master with a
         *    greater configEpoch. If this happens we inform the sender.
         *
         * This is useful because sometimes after a partition heals, a
         * reappearing master may be the last one to claim a given set of
         * hash slots, but with a configuration that other instances know to
         * be deprecated. Example:
         *
         * A and B are master and slave for slots 1,2,3.
         * A is partitioned away, B gets promoted.
         * B is partitioned away, and A returns available.
         *
         * Usually B would PING A publishing its set of served slots and its
         * configEpoch, but because of the partition B can't inform A of the
         * new configuration, so other nodes that have an updated table must
         * do it. In this way A will stop to act as a master (or can try to
         * failover if there are the conditions to win the election). */
        //2.检测与1相反的条件，sender发送的槽位信息比当前节点已知槽位信息的配置纪元低 这时要通知对方
        //一个重新连入集群的主节点很可能携带过时的信息，经常导致这种情况的发生
        //如：
        //A负责slot 1，2，3 B是A的从节点
        //A断连，B晋升为主节点
        //B断连，A恢复连接但已不应负责slot 1，2，3
        //两者强行切换，没有进行平时该有的通知转移，A仍认为自己负责slot 1，2，3
        if (sender && dirty_slots) {
            int j;
            //遍历全部slot(当前节点保存的信息)
            for (j = 0; j < CLUSTER_SLOTS; j++) {
                //检测当前slot是否在消息的bitmap中被覆盖
                if (bitmapTestBit(hdr->myslots,j)) {
                    //若当前slot由sender负责或未被覆盖，则跳过
                    if (server.cluster->slots[j] == sender ||
                        server.cluster->slots[j] == NULL) continue;
                    //如果当前slot的配置纪元大于sender的配置纪元
                    if (server.cluster->slots[j]->configEpoch >
                        senderConfigEpoch)
                    {
                        serverLog(LL_VERBOSE,
                            "Node %.40s has old slots configuration, sending "
                            "an UPDATE message about %.40s",
                                sender->name, server.cluster->slots[j]->name);
                        //向sender发送UPDATE消息，当前更新的slot信息
                        clusterSendUpdate(sender->link,
                            server.cluster->slots[j]);

                        /* TODO: instead of exiting the loop send every other
                         * UPDATE packet for other nodes that are the new owner
                         * of sender's slots. */
                        break;
                    }
                }
            }
        }

        /* If our config epoch collides with the sender's try to fix
         * the problem. */
        //如果双方都是主节点，配置纪元相同但信息不统一
        if (sender &&
            nodeIsMaster(myself) && nodeIsMaster(sender) &&
            senderConfigEpoch == myself->configEpoch)
        {
            //处理配置纪元冲突
            clusterHandleConfigEpochCollision(sender);
        }

        /* Get info from the gossip section */
        //处理gossip协议的PING，PONG消息
        if (sender) clusterProcessGossipSection(hdr,link);
    } else if (type == CLUSTERMSG_TYPE_FAIL) {
       //......
    } else if (type == CLUSTERMSG_TYPE_PUBLISH) {
       //......
    } else if (type == CLUSTERMSG_TYPE_FAILOVER_AUTH_REQUEST) {
       //......
    } else if (type == CLUSTERMSG_TYPE_FAILOVER_AUTH_ACK) {
       //......
    } else if (type == CLUSTERMSG_TYPE_MFSTART) {
       //......
    } else if (type == CLUSTERMSG_TYPE_UPDATE) {
        //处理第二种情况发送的UPDATE消息
        clusterNode *n; /* The node the update is about. */
        //消息种节点的配置纪元
        uint64_t reportedConfigEpoch =
                    ntohu64(hdr->data.update.nodecfg.configEpoch);

        if (!sender) return 1;  /* We don't know the sender. */
        //查找需要更新的节点
        n = clusterLookupNode(hdr->data.update.nodecfg.nodename);
        if (!n) return 1;   /* We don't know the reported node. */
        //需要更新的节点的信息配置纪元较高，返回
        //这种情况发生在先后接收两个UPDATE，接收的后一个的时候
        if (n->configEpoch >= reportedConfigEpoch) return 1; /* Nothing new. */

        /* If in our current config the node is a slave, set it as a master. */
        //如果需要更新的节点是从节点，更改其属性为主节点
        if (nodeIsSlave(n)) clusterSetNodeAsMaster(n);

        /* Update the node's configEpoch. */
        //更新配置纪元
        n->configEpoch = reportedConfigEpoch;
        clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                             CLUSTER_TODO_FSYNC_CONFIG);

        /* Check the bitmap of served slots and update our
         * config accordingly. */
        //更新这个节点的slot信息
        clusterUpdateSlotsConfigWith(n,reportedConfigEpoch,
            hdr->data.update.nodecfg.slots);
    } else {
        serverLog(LL_WARNING,"Received unknown packet type: %d", type);
    }
    return 1;
}

//更新节点的slot信息
void clusterUpdateSlotsConfigWith(clusterNode *sender, uint64_t senderConfigEpoch, unsigned char *slots) {
    int j;
    clusterNode *curmaster, *newmaster = NULL;
    /* The dirty slots list is a list of slots for which we lose the ownership
     * while having still keys inside. This usually happens after a failover
     * or after a manual cluster reconfiguration operated by the admin.
     *
     * If the update message is not able to demote a master to slave (in this
     * case we'll resync with the master updating the whole key space), we
     * need to delete all the keys in the slots we lost ownership. */
    uint16_t dirty_slots[CLUSTER_SLOTS];
    int dirty_slots_count = 0;

    /* Here we set curmaster to this node or the node this node
     * replicates to if it's a slave. In the for loop we are
     * interested to check if slots are taken away from curmaster. */
    //获取当前主节点或当前从节点从属主节点的信息
    curmaster = nodeIsMaster(myself) ? myself : myself->slaveof;

    //发送这条消息的不能是自己
    if (sender == myself) {
        serverLog(LL_WARNING,"Discarding UPDATE message about myself.");
        return;
    }

    //遍历所有slot(当前节点保存的集群信息)
    for (j = 0; j < CLUSTER_SLOTS; j++) {
        //如果当前slot在消息的bitmap中已被覆盖
        if (bitmapTestBit(slots,j)) {
            /* The slot is already bound to the sender of this message. */
            //并且由sender负责，跳过
            if (server.cluster->slots[j] == sender) continue;

            /* The slot is in importing state, it should be modified only
             * manually via redis-trib (example: a resharding is in progress
             * and the migrating side slot was already closed and is advertising
             * a new config. We still want the slot to be closed manually). */
            //处于导入状态，应只能通过redis-trib修改，跳过
            if (server.cluster->importing_slots_from[j]) continue;

            /* We rebind the slot to the new node claiming it if:
             * 1) The slot was unassigned or the new node claims it with a
             *    greater configEpoch.
             * 2) We are not currently importing the slot. */
            //1. slot在当前节点的记录中未被覆盖/消息来源节点配置纪元更大
            //2. 当前未导入这个slot
            if (server.cluster->slots[j] == NULL ||
                server.cluster->slots[j]->configEpoch < senderConfigEpoch)
            {
                /* Was this slot mine, and still contains keys? Mark it as
                 * a dirty slot. */
                //如果这个slot由自己负责，且其中有数据，则属于发生冲突的slot
                if (server.cluster->slots[j] == myself &&
                    countKeysInSlot(j) &&
                    sender != myself)
                {
                    dirty_slots[dirty_slots_count] = j;
                    dirty_slots_count++;
                }
                
                //如果这个slot属于当前节点的主节点，则表示发生了故障转移
                if (server.cluster->slots[j] == curmaster)
                    newmaster = sender;
                //删除这个slot
                clusterDelSlot(j);
                //将其分配给消息来源节点
                clusterAddSlot(sender,j);
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                     CLUSTER_TODO_UPDATE_STATE|
                                     CLUSTER_TODO_FSYNC_CONFIG);
            }
        }
    }

    /* If at least one slot was reassigned from a node to another node
     * with a greater configEpoch, it is possible that:
     * 1) We are a master left without slots. This means that we were
     *    failed over and we should turn into a replica of the new
     *    master.
     * 2) We are a slave and our master is left without slots. We need
     *    to replicate to the new slots owner. */
    //如果至少有一个slot从一个节点被重新分配到另一个配置纪元更大的节点，有两种情况
    //1.当前节点是不再处理任何slot的主节点，应作为新主节点的从节点
    //2.当前节点是从节点，当前节点的主节点不再处理任何slot，也应作为新主节点的从节点
    if (newmaster && curmaster->numslots == 0) {
        serverLog(LL_WARNING,
            "Configuration change detected. Reconfiguring myself "
            "as a replica of %.40s", sender->name);
        //将sender设为当前节点的主节点
        clusterSetMaster(sender);
        clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                             CLUSTER_TODO_UPDATE_STATE|
                             CLUSTER_TODO_FSYNC_CONFIG);
    } else if (dirty_slots_count) {
        /* If we are here, we received an update message which removed
         * ownership for certain slots we still have keys about, but still
         * we are serving some slots, so this master node was not demoted to
         * a slave.
         *
         * In order to maintain a consistent state between keys and slots
         * we need to remove all the keys from the slots we lost. */
        //进行到这里，如果接收到一个要求删除由当前节点负责且仍存有信息的slot的UPDATE消息，但同时当前节点仍负责一些slot，此时主节点不能直接被降为从节点
        //为保持slot与key的关系，需要将slot中的key先删除
        for (j = 0; j < dirty_slots_count; j++)
            delKeysInSlot(dirty_slots[j]);
    }
}
```

**存储**

向某一节点发送数据变更的命令时，服务将跟据key找到对应的slot，再存入slot所属节点的数据库

```c
//db.c
void dbAdd(redisDb *db, robj *key, robj *val) {
    sds copy = sdsdup(key->ptr);
    int retval = dictAdd(db->dict, copy, val);

    serverAssertWithInfo(NULL,key,retval == DICT_OK);
    if (val->type == OBJ_LIST) signalListAsReady(db, key);
    //这一步将开始寻找对影slot与其所属主节点
    if (server.cluster_enabled) slotToKeyAdd(key);
 }

void slotToKeyAdd(robj *key) {
    slotToKeyUpdateKey(key,1);
}

void slotToKeyUpdateKey(robj *key, int add) {
    unsigned int hashslot = keyHashSlot(key->ptr,sdslen(key->ptr));
    unsigned char buf[64];
    unsigned char *indexed = buf;
    size_t keylen = sdslen(key->ptr);

    server.cluster->slots_keys_count[hashslot] += add ? 1 : -1;
    if (keylen+2 > 64) indexed = zmalloc(keylen+2);
    indexed[0] = (hashslot >> 8) & 0xff;
    indexed[1] = hashslot & 0xff;
    memcpy(indexed+2,key->ptr,keylen);
    if (add) {
        raxInsert(server.cluster->slots_to_keys,indexed,keylen+2,NULL,NULL);
    } else {
        raxRemove(server.cluster->slots_to_keys,indexed,keylen+2,NULL);
    }
    if (indexed != buf) zfree(indexed);
}
```

#### 高级特性

##### 00x07 主从节点

---

`SLAVEOF <host> <port>` 命令用于建立主从关系

`SLAVEOF NO ONE` 用于断开主从关系，并且使当前节点成为主节点

其实现定义在replication.c中

```c
void slaveofCommand(client *c) {
    /* SLAVEOF is not allowed in cluster mode as replication is automatically
     * configured using the current address of the master node. */
    //当前正处于集群模式时，不允许再手动建立主从关系
    if (server.cluster_enabled) {
        addReplyError(c,"SLAVEOF not allowed in cluster mode.");
        return;
    }

    /* The special host/port combination "NO" "ONE" turns the instance
     * into a master. Otherwise the new master address is set. */
    //SLAVEOF NO ONE
    //使从节点恢复为主节点，不丢弃已同步到的数据
    if (!strcasecmp(c->argv[1]->ptr,"no") &&
        !strcasecmp(c->argv[2]->ptr,"one")) {
        //如果有主节点IP
        if (server.masterhost) {
            //取消复制，设置当前节点为主节点
            replicationUnsetMaster();
            //以sds形式获取client信息，写入日志
            sds client = catClientInfoString(sdsempty(),c);
            serverLog(LL_NOTICE,"MASTER MODE enabled (user request from '%s')",
                client);
            sdsfree(client);
        }
    //SLAVEOF <host> <port>
    } else {
        long port;
        //端口号
        if ((getLongFromObjectOrReply(c, c->argv[2], &port, NULL) != C_OK))
            return;
        
        /* Check if we are already attached to the specified slave */
        //检测是否已将其作为主节点
        if (server.masterhost && !strcasecmp(server.masterhost,c->argv[1]->ptr)
            && server.masterport == port) {
            serverLog(LL_NOTICE,"SLAVE OF would result into synchronization with the master we are already connected with. No operation performed.");
            addReplySds(c,sdsnew("+OK Already connected to specified master\r\n"));
            return;
        }
        /* There was no previous master or the user specified a different one,
         * we can continue. */
        //设置主节点
        replicationSetMaster(c->argv[1]->ptr, port);
        //将client信息写入日志
        sds client = catClientInfoString(sdsempty(),c);
        serverLog(LL_NOTICE,"SLAVE OF %s:%d enabled (user request from '%s')",
            server.masterhost, server.masterport, client);
        sdsfree(client);
    }
    addReply(c,shared.ok);
}
```

建立主从关系

```c
void replicationSetMaster(char *ip, int port) {
    int was_master = server.masterhost == NULL;
    //清除原主节点ip
    sdsfree(server.masterhost);
    //设置新的host port
    server.masterhost = sdsnew(ip);
    server.masterport = port;
    //释放之前的主节点
    if (server.master) {
        freeClient(server.master);
    }
    //block.c unblockClient操作
    //解除所有client的阻塞状态
    disconnectAllBlockedClients(); /* Clients blocked in master, now slave. */

    /* Force our slaves to resync with us as well. They may hopefully be able
     * to partially resync with us, but we can notify the replid change. */
    //networking.c freeClient操作
    disconnectSlaves();
    //在非阻塞状况下关闭主从同步socket
    cancelReplicationHandshake();
    /* Before destroying our master state, create a cached master using
     * our own parameters, to later PSYNC with the new master. */
    //先用自己的参数做一次缓存，可能会在在同步时做快速恢复
    if (was_master) replicationCacheMasterUsingMyself();
    //复制状态改为待连接
    server.repl_state = REPL_STATE_CONNECT;
    server.repl_down_since = 0;
}
```

断开主从关系，设置当前节点为主节点

```c
void replicationUnsetMaster(void) {
    if (server.masterhost == NULL) return; /* Nothing to do. */
    //释放主节点ip
    sdsfree(server.masterhost);
    server.masterhost = NULL;
    /* When a slave is turned into a master, the current replication ID
     * (that was inherited from the master at synchronization time) is
     * used as secondary ID up to the current offset, and a new replication
     * ID is created to continue with a new replication history. */
    //切换复制id
    shiftReplicationId();
    //释放客户端
    if (server.master) freeClient(server.master);
    //释放缓存，不再使用
    replicationDiscardCachedMaster();
    //取消复制
    cancelReplicationHandshake();
    /* Disconnecting all the slaves is required: we need to inform slaves
     * of the replication ID change (see shiftReplicationId() call). However
     * the slaves will be able to partially resync with us, so it will be
     * a very fast reconnection. */
    //与其他从节点断开连接
    disconnectSlaves();
    server.repl_state = REPL_STATE_NONE;

    /* We need to make sure the new master will start the replication stream
     * with a SELECT statement. This is forced after a full resync, but
     * with PSYNC version 2, there is no need for full resync after a
     * master switch. */
    //强制触发全量同步
    server.slaveseldb = -1;

    /* Once we turn from slave to master, we consider the starting time without
     * slaves (that is used to count the replication backlog time to live) as
     * starting from now. Otherwise the backlog will be freed after a
     * failover if slaves do not connect immediately. */
    //设置无从节点状态开始的时间
    server.repl_no_slaves_since = server.unixtime;
}
```

##### 00x08 replicate节点复制

---

主从关系建立后，从节点的server.repl_state值被设为REPL_STATE_CONNECT，表示现在已有主节点，且需要连接主节点

这个动作定义在replicationCron()函数中

serverCron()中每1000ms调用一次replicationCron()

在周期函数中，复制状态由一系列标志表示

复制的操作在函数中是连续定义的，但在每次循环中以状态标志决定要进入哪一步操作的分支

以此实现复制操作的有序执行

期间，命令的发送与回复的接收都由sendSynchronousCommand()进行，根据传入的flag，收发可连续进行也可分开进行

```c
	/* Replication cron function -- used to reconnect to master,
     * detect transfer failures, start background RDB transfers and so forth. */
    run_with_period(1000) replicationCron();
```

检查状态，尝试与主节点建立连接

```c
void replicationCron(void) {
    static long long replication_cron_loops = 0;
    //......
    /* Check if we should connect to a MASTER */
    if (server.repl_state == REPL_STATE_CONNECT) {
        serverLog(LL_NOTICE,"Connecting to MASTER %s:%d",
            server.masterhost, server.masterport);
        if (connectWithMaster() == C_OK) {
            serverLog(LL_NOTICE,"MASTER <-> SLAVE sync started");
        }
    }
	//......
}

//连接动作实现
int connectWithMaster(void) {
    int fd;

    fd = anetTcpNonBlockBestEffortBindConnect(NULL,
        server.masterhost,server.masterport,NET_FIRST_BIND_ADDR);
    if (fd == -1) {
        serverLog(LL_WARNING,"Unable to connect to MASTER: %s",
            strerror(errno));
        return C_ERR;
    }
	
    //连接后设置可读写事件的处理函数为syncWithMaster()
    if (aeCreateFileEvent(server.el,fd,AE_READABLE|AE_WRITABLE,syncWithMaster,NULL) ==
            AE_ERR)
    {
        close(fd);
        serverLog(LL_WARNING,"Can't create readable event for SYNC");
        return C_ERR;
    }

    server.repl_transfer_lastio = server.unixtime;
    server.repl_transfer_s = fd;
    //更改状态为正在连接
    server.repl_state = REPL_STATE_CONNECTING;
    return C_OK;
}
```

当前节点与主节点建立连接后，设置了synvWitherMaster()函数来处理socket的可读写事件

此时复制状态repl_state为REPL_STATE_CONNECTING

```c
void syncWithMaster(aeEventLoop *el, int fd, void *privdata, int mask) {
    char tmpfile[256], *err = NULL;
    int dfd = -1, maxtries = 5;
    int sockerr = 0, psync_result;
    socklen_t errlen = sizeof(sockerr);
    UNUSED(el);
    UNUSED(privdata);
    UNUSED(mask);

    /* If this event fired after the user turned the instance into a master
     * with SLAVEOF NO ONE we must just return ASAP. */
    //若复制状态为无复制(执行了SLAVEOF NO ONE)，则关闭socket
    if (server.repl_state == REPL_STATE_NONE) {
        close(fd);
        return;
    }

    /* Check for errors in the socket: after a non blocking connect() we
     * may find that the socket is in error state. */
    //检查socket状态
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &errlen) == -1)
        sockerr = errno;
    if (sockerr) {
        serverLog(LL_WARNING,"Error condition on socket for SYNC: %s",
            strerror(sockerr));
        goto error;
    }

    /* Send a PING to check the master is able to reply without errors. */
    //socket刚连接完成，向主节点发送一个PING命令
    //检测网络是否用，主节点是否可接受命令
    if (server.repl_state == REPL_STATE_CONNECTING) {
        serverLog(LL_NOTICE,"Non blocking connect for SYNC fired the event.");
        /* Delete the writable event so that the readable event remains
         * registered and we can wait for the PONG reply. */
        //收到PONG消息前暂时取消可写事件，等待可读事件
        aeDeleteFileEvent(server.el,fd,AE_WRITABLE);
        //更改复制状态为等待PONG命令
        server.repl_state = REPL_STATE_RECEIVE_PONG;
        /* Send the PING, don't check for errors at all, we have the timeout
         * that will take care about this. */
        //通过fd向主节点发送PING命令
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"PING",NULL);
        if (err) goto write_error;
        return;
    }
```

主节点会从socket中读取到PING命令，调用processCommand() - pingCommand() - addReply(c,shared.pong) 返回PONG回复

> 当前判断主节点将从节点当作一个类似客户端的实体来对待，所以从节点向主节点的消息会被作为命令处理，主节点向从节点发送的消息相当于对客户端的回复

接下来是从节点对PONG的处理

```c
    //接上一块syncWithMaster()
	/* Receive the PONG command. */
    if (server.repl_state == REPL_STATE_RECEIVE_PONG) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);

        /* We accept only two replies as valid, a positive +PONG reply
         * (we just check for "+") or an authentication error.
         * Note that older versions of Redis replied with "operation not
         * permitted" instead of using a proper error code, so we test
         * both. */
        //解析命令
        if (err[0] != '+' &&
            strncmp(err,"-NOAUTH",7) != 0 &&
            strncmp(err,"-ERR operation not permitted",28) != 0)
        {
            serverLog(LL_WARNING,"Error reply to PING from master: '%s'",err);
            sdsfree(err);
            goto error;
        } else {
            serverLog(LL_NOTICE,
                "Master replied to PING, replication can continue...");
        }
        sdsfree(err);
        //变更状态为REPL_STATE_SEND_AUTH
        server.repl_state = REPL_STATE_SEND_AUTH;
    }
```

如果从节点服务器有密码保护(主节点的密码，即主节点服务器配置中的requirepass)，则会先将密码以AUTH命令的方式发送到主节点进行验证

而没有密码保护时则跳过，进入REPL_STATE_SEND_PORT状态

```c
//接上一块syncWithMaster()
    /* AUTH with the master if required. */
    if (server.repl_state == REPL_STATE_SEND_AUTH) {
        //如果在配置中设置了验证，向服务端发送AUTH命令
        if (server.masterauth) {
            err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"AUTH",server.masterauth,NULL);
            if (err) goto write_error;
            server.repl_state = REPL_STATE_RECEIVE_AUTH;
            return;
        } else {
            //未设置验证，跳过验证阶段
            server.repl_state = REPL_STATE_SEND_PORT;
        }
    }

    /* Receive AUTH reply. */
	//验证第二阶段，接收验证结果
    if (server.repl_state == REPL_STATE_RECEIVE_AUTH) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        if (err[0] == '-') {
            serverLog(LL_WARNING,"Unable to AUTH to MASTER: %s",err);
            sdsfree(err);
            goto error;
        }
        sdsfree(err);
        //更改状态为发送端口
        server.repl_state = REPL_STATE_SEND_PORT;
    }
```

从节点的端口号将以 `REPLCONF listening-port <port>` 的形式写入socket

主节点读出这一命令后，调用replconfCommand()处理，将端口号保存于c->slave_listening_port，并向socket中写入 `+OK\r\n` 回复

```c
//接上一块syncWithMaster()
	/* Set the slave port, so that Master's INFO command can list the
     * slave listening port correctly. */
    if (server.repl_state == REPL_STATE_SEND_PORT) {
        //以sds标准格式获取端口
        sds port = sdsfromlonglong(server.slave_announce_port ?
            server.slave_announce_port : server.port);
        //发送REPLCONF命令
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"REPLCONF",
                "listening-port",port, NULL);
        sdsfree(port);
        if (err) goto write_error;
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_PORT;
        return;
    }

    /* Receive REPLCONF listening-port reply. */
	//与AUTH类似，端口发送第二阶段
    if (server.repl_state == REPL_STATE_RECEIVE_PORT) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF listening-port. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                "REPLCONF listening-port: %s", err);
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_SEND_IP;
    }
```

与发送PORT的流程基本相同，从节点发送 `REPLCONF ip-address <ip>` 

主节点将其保存于c->slave_ip

```c
//接上一块syncWithMaster()
    /* Skip REPLCONF ip-address if there is no slave-announce-ip option set. */
    if (server.repl_state == REPL_STATE_SEND_IP &&
        server.slave_announce_ip == NULL)
    {
        //没有设置则跳过ip发送
        server.repl_state = REPL_STATE_SEND_CAPA;
    }
    
    /* Set the slave ip, so that Master's INFO command can list the
     * slave IP address port correctly in case of port forwarding or NAT. */
    if (server.repl_state == REPL_STATE_SEND_IP) {
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"REPLCONF",
                "ip-address",server.slave_announce_ip, NULL);
        if (err) goto write_error;
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_IP;
        return;
    }

    /* Receive REPLCONF ip-address reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_IP) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF listening-port. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                "REPLCONF ip-address: %s", err);
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_SEND_CAPA;
    }
```

同样地，从节点发送 `REPLCONF capa eof` 

目前这条命令只有eof与psync2两个可选项

主节点将其保存在c->slave_capa中

```c
//接上一块syncWithMaster()
    /* Inform the master of our (slave) capabilities.
     *
     * EOF: supports EOF-style RDB transfer for diskless replication.
     * PSYNC2: supports PSYNC v2, so understands +CONTINUE <new repl ID>.
     *
     * The master will ignore capabilities it does not understand. */
    if (server.repl_state == REPL_STATE_SEND_CAPA) {
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"REPLCONF",
                "capa","eof","capa","psync2",NULL);
        if (err) goto write_error;
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_CAPA;
        return;
    }

    /* Receive CAPA reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_CAPA) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        /* Ignore the error if any, not all the Redis versions support
         * REPLCONF capa. */
        if (err[0] == '-') {
            serverLog(LL_NOTICE,"(Non critical) Master does not understand "
                                  "REPLCONF capa: %s", err);
        }
        sdsfree(err);
        server.repl_state = REPL_STATE_SEND_PSYNC;
    }
```

REPLCONF命令实现

```c
void replconfCommand(client *c) {
    int j;

    if ((c->argc % 2) == 0) {
        //参数必须为2的倍数
        /* Number of arguments must be odd to make sure that every
         * option has a corresponding value. */
        addReply(c,shared.syntaxerr);
        return;
    }

    /* Process every option-value pair. */
    for (j = 1; j < c->argc; j+=2) {
        //处理port
        if (!strcasecmp(c->argv[j]->ptr,"listening-port")) {
            long port;

            if ((getLongFromObjectOrReply(c,c->argv[j+1],
                    &port,NULL) != C_OK))
                return;
            c->slave_listening_port = port;
        //处理ip
        } else if (!strcasecmp(c->argv[j]->ptr,"ip-address")) {
            sds ip = c->argv[j+1]->ptr;
            if (sdslen(ip) < sizeof(c->slave_ip)) {
                memcpy(c->slave_ip,ip,sdslen(ip)+1);
            } else {
                //发送的ip字符串过长，格式不对
                addReplyErrorFormat(c,"REPLCONF ip-address provided by "
                    "slave instance is too long: %zd bytes", sdslen(ip));
                return;
            }
        //处理capability
        } else if (!strcasecmp(c->argv[j]->ptr,"capa")) {
            /* Ignore capabilities not understood by this master. */
            //设置标志
            if (!strcasecmp(c->argv[j+1]->ptr,"eof"))
                c->slave_capa |= SLAVE_CAPA_EOF;
            else if (!strcasecmp(c->argv[j+1]->ptr,"psync2"))
                c->slave_capa |= SLAVE_CAPA_PSYNC2;
        //REPLCONF ack 仅用于从节点告知主节点已执行复制流的总数
        } else if (!strcasecmp(c->argv[j]->ptr,"ack")) {
            /* REPLCONF ACK is used by slave to inform the master the amount
             * of replication stream that it processed so far. It is an
             * internal only command that normal clients should never use. */
            long long offset;

            if (!(c->flags & CLIENT_SLAVE)) return;
            if ((getLongLongFromObject(c->argv[j+1], &offset) != C_OK))
                return;
            if (offset > c->repl_ack_off)
                c->repl_ack_off = offset;
            c->repl_ack_time = server.unixtime;
            /* If this was a diskless replication, we need to really put
             * the slave online when the first ACK is received (which
             * confirms slave is online and ready to get more data). */
            if (c->repl_put_online_on_ack && c->replstate == SLAVE_STATE_ONLINE)
                putSlaveOnline(c);
            /* Note: this command does not reply anything! */
            return;
        //用于要求从节点立刻发送一个REPLCONF ack命令
        } else if (!strcasecmp(c->argv[j]->ptr,"getack")) {
            /* REPLCONF GETACK is used in order to request an ACK ASAP
             * to the slave. */
            if (server.masterhost && server.master) replicationSendAck();
            return;
        } else {
            //无法识别REPLCONF的参数
            addReplyErrorFormat(c,"Unrecognized REPLCONF option: %s",
                (char*)c->argv[j]->ptr);
            return;
        }
    }
    addReply(c,shared.ok);
}
```

此时基本信息发送完毕，按照流程开始进行第一次同步

因为是第一次进行同步，将进行全量同步以获取所有数据与之后部分同步所需的信息

```c
//接上一块syncWithMaster()
    /* Try a partial resynchonization. If we don't have a cached master
     * slaveTryPartialResynchronization() will at least try to use PSYNC
     * to start a full resynchronization so that we get the master run id
     * and the global offset, to try a partial resync at the next
     * reconnection attempt. */
    //尝试与主节点进行部分重同步
    //在尚未进行同步的状况下，至少会与主节点进行一次全量同步
    //以获取主节点的run id与全局偏移量，以便下一次尝试部分重同步
    if (server.repl_state == REPL_STATE_SEND_PSYNC) {
        //向主节点发送PSYNC命令
        if (slaveTryPartialResynchronization(fd,0) == PSYNC_WRITE_ERROR) {
            err = sdsnew("Write error sending the PSYNC command.");
            goto write_error;
        }
        //复制状态设置为等待PSYNC回复
        server.repl_state = REPL_STATE_RECEIVE_PSYNC;
        return;
    }
```

修改复制状态后，调用slaveTryPartialResynchronization()进行同步

跟据参数read_reply，分为读与写两种操作，先分析写部分，向socket写入命令

```c
#define PSYNC_WRITE_ERROR 0
#define PSYNC_WAIT_REPLY 1
#define PSYNC_CONTINUE 2
#define PSYNC_FULLRESYNC 3
#define PSYNC_NOT_SUPPORTED 4
#define PSYNC_TRY_LATER 5
int slaveTryPartialResynchronization(int fd, int read_reply) {
    char *psync_replid;
    char psync_offset[32];
    sds reply;

    /* Writing half */
    //写部分
    //read_reply为0时，向socket写入PSYNC命令
    if (!read_reply) {
        /* Initially set master_initial_offset to -1 to mark the current
         * master run_id and offset as not valid. Later if we'll be able to do
         * a FULL resync using the PSYNC command we'll set the offset at the
         * right value, so that this information will be propagated to the
         * client structure representing the master into server.master. */
        //这个值为-1时，代表当前主节点的replid与全局复制偏移量无效
        //当执行全量同步后，偏移量将被修正
        server.master_initial_offset = -1;

        //检查主节点缓存，判断是进行全量同步还是部分同步
        if (server.cached_master) {
            //有缓存，向主节点发送"PSYNC <replid> <repl_offset>"，进行部分同步
            psync_replid = server.cached_master->replid;
            //获取已复制偏移量
            snprintf(psync_offset,sizeof(psync_offset),"%lld", server.cached_master->reploff+1);
            serverLog(LL_NOTICE,"Trying a partial resynchronization (request %s:%s).", psync_replid, psync_offset);
        } else {
            //无缓存，向主节点发送"PSYNC ? -1"，进行全同步
            serverLog(LL_NOTICE,"Partial resynchronization not possible (no cached master)");
            psync_replid = "?";
            memcpy(psync_offset,"-1",3);
        }

        /* Issue the PSYNC command */
        //组装完整PSYNC命令
        reply = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"PSYNC",psync_replid,psync_offset,NULL);
        if (reply != NULL) {
            //命令发送失败，写入日志，删除可读事件并返回错误
            serverLog(LL_WARNING,"Unable to send PSYNC to master: %s",reply);
            sdsfree(reply);
            aeDeleteFileEvent(server.el,fd,AE_READABLE);
            return PSYNC_WRITE_ERROR;
        }
        return PSYNC_WAIT_REPLY;
    }
```

从节点成功向socket写入命令，轮到主节点处理PSYNC命令

PSYNC命令与SYNC命令一样，由syncCommand()实现

首先判断当前命令是PSYNC还是SYNC(版本兼容命令)

对于PSYNC命令，将首先调用masterTryPartialResynchronization() 

在这个函数中，将判断PSYNC的参数是否符合部分重同步的要求(replid,psync_offset)

符合要求则为部分重同步作准备并向从节点发送"+CONTINUE"告知其将要进行部分重同步，然后直接结束syncCommand()

不符合要求则返回C_ERR进入另一个分支，继续在syncCommand()中执行全量同步

在这里主要关注第一次同步，即全量同步的实现过程

```c
void syncCommand(client *c) {
    /* ignore SYNC if already slave or in monitor mode */
    //如果客户端已经被标识为从节点或monitor，则不执行命令
    //执行这个命令时将要做全量同步或部分重同步
    //主从连接总是第一次建立或重新建立，客户端还未被标志为从节点
    if (c->flags & CLIENT_SLAVE) return;

    /* Refuse SYNC requests if we are a slave but the link with our master
     * is not ok... */
    //这里是从节点处理用户输入的SYNC类命令时做的判断
    //如果未与主节点连接，则无法执行此命令
    if (server.masterhost && server.repl_state != REPL_STATE_CONNECTED) {
        addReplySds(c,sdsnew("-NOMASTERLINK Can't SYNC while not connected with my master\r\n"));
        return;
    }

    /* SYNC can't be issued when the server has pending data to send to
     * the client about already issued commands. We need a fresh reply
     * buffer registering the differences between the BGSAVE and the current
     * dataset, so that we can copy to other slaves if needed. */
    //client的回复缓冲区中还有数据，则无法执行
    if (clientHasPendingReplies(c)) {
        addReplyError(c,"SYNC and PSYNC are invalid with pending output");
        return;
    }

    serverLog(LL_NOTICE,"Slave %s asks for synchronization",
        replicationGetSlaveName(c));

    /* Try a partial resynchronization if this is a PSYNC command.
     * If it fails, we continue with usual full resynchronization, however
     * when this happens masterTryPartialResynchronization() already
     * replied with:
     *
     * +FULLRESYNC <replid> <offset>
     *
     * So the slave knows the new replid and offset to try a PSYNC later
     * if the connection with the master is lost. */
    //如果是PSYNC命令
    if (!strcasecmp(c->argv[0]->ptr,"psync")) {
        //尝试进行部分重同步
        if (masterTryPartialResynchronization(c) == C_OK) {
            server.stat_sync_partial_ok++;
            //执行成功则不需要进行全量同步，直接返回
            return; /* No full resync needed, return. */
        } else {
            char *master_replid = c->argv[1]->ptr;

            /* Increment stats for failed PSYNCs, but only if the
             * replid is not "?", as this is used by slaves to force a full
             * resync on purpose when they are not albe to partially
             * resync. */
            //如果有强制进行全量同步的标志，则不能进行部分重同步，并增加PSYNC命令失败次数
            if (master_replid[0] != '?') server.stat_sync_partial_err++;
        }
    } else {
    //如果是SYNC命令
        /* If a slave uses SYNC, we are dealing with an old implementation
         * of the replication protocol (like redis-cli --slave). Flag the client
         * so that we don't expect to receive REPLCONF ACK feedbacks. */
        //client的版本较低
        //设置标志，不期望能接受到它的REPLCONF ack命令
        c->flags |= CLIENT_PRE_PSYNC;
    }

    /* Full resynchronization. */
    //全量同步次数+1
    server.stat_sync_full++;

    /* Setup the slave as one waiting for BGSAVE to start. The following code
     * paths will change the state if we handle the slave differently. */
    //设置主节点视角下从节点client的复制状态，等待BGSAVE开始
    c->replstate = SLAVE_STATE_WAIT_BGSAVE_START;
    //如果设置中要求关闭连接无延迟(立即响应)模式，则启用TCP的Nagle算法
    if (server.repl_disable_tcp_nodelay)
        anetDisableTcpNoDelay(NULL, c->fd); /* Non critical if it fails. */
    //初始化复制用socket
    c->repldbfd = -1;
    //标志client为一个从节点
    c->flags |= CLIENT_SLAVE;
    //将client加入从节点链表
    listAddNodeTail(server.slaves,c);

    /* Create the replication backlog if needed. */
    //创建积压记录
    if (listLength(server.slaves) == 1 && server.repl_backlog == NULL) {
        /* When we create the backlog from scratch, we always use a new
         * replication ID and clear the ID2, since there is no valid
         * past history. */
        changeReplicationId();
        clearReplicationId2();
        createReplicationBacklog();
    }

    /* CASE 1: BGSAVE is in progress, with disk target. */
    //BGSAVE已在执行，并且是向磁盘保存
    if (server.rdb_child_pid != -1 &&
        server.rdb_child_type == RDB_CHILD_TYPE_DISK)
    {
        /* Ok a background save is in progress. Let's check if it is a good
         * one for replication, i.e. if there is another slave that is
         * registering differences since the server forked to save. */
        client *slave;
        listNode *ln;
        listIter li;

        listRewind(server.slaves,&li);
        //遍历所有从节点
        while((ln = listNext(&li))) {
            slave = ln->value;
            //找到已经在等待BGSAVE完成的从节点
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) break;
        }
        /* To attach this slave, we check that it has at least all the
         * capabilities of the slave that triggered the current BGSAVE. */
        //检查当前从节点是否能重用这个节点的同步信息
        if (ln && ((c->slave_capa & slave->slave_capa) == slave->slave_capa)) {
            /* Perfect, the server is already registering differences for
             * another slave. Set the right state, and copy the buffer. */
            //复制输出缓冲区
            copyClientOutputBuffer(c,slave);
            //这个函数对从节点设置了全量同步偏移量，并向其发送了进行全量同步的回复
            replicationSetupSlaveForFullResync(c,slave->psync_initial_offset);
            serverLog(LL_NOTICE,"Waiting for end of BGSAVE for SYNC");
        } else {
            /* No way, we need to wait for the next BGSAVE in order to
             * register differences. */
            serverLog(LL_NOTICE,"Can't attach the slave to the current BGSAVE. Waiting for next BGSAVE for SYNC");
        }

    /* CASE 2: BGSAVE is in progress, with socket target. */
    //已有BGSAVE在进行，但目标是一个socket
    //这种情况下，只能让发出请求的从节点等待下一个BGSAVE的机会
    } else if (server.rdb_child_pid != -1 &&
               server.rdb_child_type == RDB_CHILD_TYPE_SOCKET)
    {
        /* There is an RDB child process but it is writing directly to
         * children sockets. We need to wait for the next BGSAVE
         * in order to synchronize. */
        serverLog(LL_NOTICE,"Current BGSAVE has socket target. Waiting for next BGSAVE for SYNC");

    /* CASE 3: There is no BGSAVE is progress. */
    //当前没有BGSAVE在运行
    } else {
        //主节点支持无盘同步
        if (server.repl_diskless_sync && (c->slave_capa & SLAVE_CAPA_EOF)) {
            /* Diskless replication RDB child is created inside
             * replicationCron() since we want to delay its start a
             * few seconds to wait for more slaves to arrive. */
            if (server.repl_diskless_sync_delay)
                serverLog(LL_NOTICE,"Delay next BGSAVE for diskless SYNC");
        //不支持无盘同步
        } else {
            /* Target is disk (or the slave is not capable of supporting
             * diskless replication) and we don't have a BGSAVE in progress,
             * let's start one. */
            //且没有进行AOF重写
            if (server.aof_child_pid == -1) 
                //开始BGSAVE
                startBgsaveForReplication(c->slave_capa);
            } else {
                serverLog(LL_NOTICE,
                    "No BGSAVE in progress, but an AOF rewrite is active. "
                    "BGSAVE for replication delayed");
            }
        }
    }
    return;
}
```

在分情况执行前，先将从节点状态设置为SLAVE_STATE_WAIT_BGSAVE_START

执行全量同步时，根据主节点状态，情况分为三种：

1. 主节点在执行BGSAVE，目标是磁盘

   如果当前对某一从节点正在进行rdb操作，且这一节点的capa是当前节点的子集，则可重用其输出缓冲区内容

   这调用replicationSetupSlaveForFullResync()设置全量同步的偏移量，并向从节点回复"+FULLRSYNC"，告知从节点要进行全量同步

   然后当前从节点等待主节点发送准备好的rdb文件即可

2. 主节点在执行BGSAVE，是无盘同步，目标是socket

   只能等待下一次BGSAVE

3. 没有子进程在执行BGSAVE

   - 如果服务器支持无盘同步，则暂时不进行操作，保持SLAVE_STATE_WAIT_BGSAVE_START状态，等待更多从节点的连接到来
   - 如果不支持无盘同步，且当前没有进行AOF持久化，则不用等待replicationCron()事件循环，立即调用startBgsaveForReplication()为同步做准备，执行BGSAVE命令，在磁盘上产生一个rdb文件

在此步骤中进入等待状态的从节点由周期事件处理

可能涉及的节点包括：

- 情况1中不能重用任何缓冲区内容的从节点
- 情况2中等待下一次BGSAVE的节点与
- 情况3中需要进行无盘同步的节点

在周期执行的repilcationCron()中，统计所有处于此状态的从节点，之后会调用startBgsaveForReplication()为全量同步作准备

startBgsaveForReplication()中调用了replicationSetupSlaveForFullResync()，同上面情况1相同，告知从节点准备进行全量同步

```c
//全量同步预处理
//被syncCommand()及replicationCron()调用
int startBgsaveForReplication(int mincapa) {
    int retval;
    //是否启用无盘同步，写入socket
    int socket_target = server.repl_diskless_sync && (mincapa & SLAVE_CAPA_EOF);
    listIter li;
    listNode *ln;

    serverLog(LL_NOTICE,"Starting BGSAVE for SYNC with target: %s",
        socket_target ? "slaves sockets" : "disk");

    rdbSaveInfo rsi, *rsiptr;
    rsiptr = rdbPopulateSaveInfo(&rsi);
    /* Only do rdbSave* when rsiptr is not NULL,
     * otherwise slave will miss repl-stream-db. */
    //选择同步方式，进行传输前的处理
    if (rsiptr) {
        if (socket_target)
            retval = rdbSaveToSlavesSockets(rsiptr);
        else
            retval = rdbSaveBackground(server.rdb_filename,rsiptr);
    } else {
        serverLog(LL_WARNING,"BGSAVE for replication: replication information not available, can't generate the RDB file right now. Try later.");
        retval = C_ERR;
    }

    /* If we failed to BGSAVE, remove the slaves waiting for a full
     * resynchorinization from the list of salves, inform them with
     * an error about what happened, close the connection ASAP. */
    //BGSAVE执行失败，断开等待全量同步的从节点
    if (retval == C_ERR) {
        serverLog(LL_WARNING,"BGSAVE for replication failed");
        listRewind(server.slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                slave->flags &= ~CLIENT_SLAVE;
                listDelNode(server.slaves,ln);
                addReplyError(slave,
                    "BGSAVE failed, replication can't continue");
                slave->flags |= CLIENT_CLOSE_AFTER_REPLY;
            }
        }
        return retval;
    }

    /* If the target is socket, rdbSaveToSlavesSockets() already setup
     * the salves for a full resync. Otherwise for disk target do it now.*/
    if (!socket_target) {
        listRewind(server.slaves,&li);
        //遍历从节点链表
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            //找出等待进行全量同步的节点
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
                	//发送通知
                    replicationSetupSlaveForFullResync(slave,
                            getPsyncInitialOffset());
            }
        }
    }

    /* Flush the script cache, since we need that slave differences are
     * accumulated without requiring slaves to match our cached scripts. */
    if (retval == C_OK) replicationScriptCacheFlush();
    return retval;
}

//告知从节点将要进行全量同步的实现
//同时发送了主节点的replid及全局复制偏移量master_repl_offset
int replicationSetupSlaveForFullResync(client *slave, long long offset) {
    char buf[128];
    int buflen;

    slave->psync_initial_offset = offset;
    slave->replstate = SLAVE_STATE_WAIT_BGSAVE_END;
    /* We are going to accumulate the incremental changes for this
     * slave as well. Set slaveseldb to -1 in order to force to re-emit
     * a SELECT statement in the replication stream. */
    server.slaveseldb = -1;

    /* Don't send this reply to slaves that approached us with
     * the old SYNC command. */
    //告知从节点，即将进行全量同步
    //但不发送给旧版本的节点
    if (!(slave->flags & CLIENT_PRE_PSYNC)) {
        buflen = snprintf(buf,sizeof(buf),"+FULLRESYNC %s %lld\r\n",
                          server.replid,offset);
        if (write(slave->fd,buf,buflen) != buflen) {
            freeClientAsync(slave);
            return C_ERR;
        }
    }
    return C_OK;
}
```

被当作客户端的从节点收到进行全量同步的通知

(或者部分重同步的通知，又或者代表出现问题的"-NOMASTERLINK"，"-LOADING"与"-ERR")

因为在从节点视角中，复制状态仍为REPL_STATE_RECEIVE_SYNC，触发可读事件后进入syncWithMaster()再次执行slaveTryPartialResynchronization()，但这次第二个参数为1，进入读部分

```c
//接上一块syncWithMaster()
    /* If reached this point, we should be in REPL_STATE_RECEIVE_PSYNC. */
	//检查状态
    if (server.repl_state != REPL_STATE_RECEIVE_PSYNC) {
        serverLog(LL_WARNING,"syncWithMaster(): state machine error, "
                             "state should be RECEIVE_PSYNC but is %d",
                             server.repl_state);
        goto error;
    }

    psync_result = slaveTryPartialResynchronization(fd,1);

//接slaveTryPartialResynchronization()写部分，这里是读部分
    /* Reading half */
	//接收回复
    reply = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
    if (sdslen(reply) == 0) {
        /* The master may send empty newlines after it receives PSYNC
         * and before to reply, just to keep the connection alive. */
        sdsfree(reply);
        return PSYNC_WAIT_REPLY;
    }
	
	//暂时删除可读事件
    aeDeleteFileEvent(server.el,fd,AE_READABLE);

	//检测到+FULLSYNC回复，读取偏移量，id等信息，准备进行全量同步
    if (!strncmp(reply,"+FULLRESYNC",11)) {
        char *replid = NULL, *offset = NULL;

        /* FULL RESYNC, parse the reply in order to extract the run id
         * and the replication offset. */
        replid = strchr(reply,' ');
        if (replid) {
            replid++;
            offset = strchr(replid,' ');
            if (offset) offset++;
        }
        if (!replid || !offset || (offset-replid-1) != CONFIG_RUN_ID_SIZE) {
            serverLog(LL_WARNING,
                "Master replied with wrong +FULLRESYNC syntax.");
            /* This is an unexpected condition, actually the +FULLRESYNC
             * reply means that the master supports PSYNC, but the reply
             * format seems wrong. To stay safe we blank the master
             * replid to make sure next PSYNCs will fail. */
            memset(server.master_replid,0,CONFIG_RUN_ID_SIZE+1);
        } else {
            memcpy(server.master_replid, replid, offset-replid-1);
            server.master_replid[CONFIG_RUN_ID_SIZE] = '\0';
            server.master_initial_offset = strtoll(offset,NULL,10);
            serverLog(LL_NOTICE,"Full resync from master: %s:%lld",
                server.master_replid,
                server.master_initial_offset);
        }
        /* We are going to full resync, discard the cached master structure. */
        //丢弃之前同步到的信息
        replicationDiscardCachedMaster();
        sdsfree(reply);
        return PSYNC_FULLRESYNC;
    }

	//+CONTINUE表示进行部分重同步
    if (!strncmp(reply,"+CONTINUE",9)) {
        /* Partial resync was accepted. */
        serverLog(LL_NOTICE,
            "Successful partial resynchronization with master.");

        /* Check the new replication ID advertised by the master. If it
         * changed, we need to set the new ID as primary ID, and set or
         * secondary ID as the old master ID up to the current offset, so
         * that our sub-slaves will be able to PSYNC with us after a
         * disconnection. */
        //更新主节点复制id
        char *start = reply+10;
        char *end = reply+9;
        while(end[0] != '\r' && end[0] != '\n' && end[0] != '\0') end++;
        if (end-start == CONFIG_RUN_ID_SIZE) {
            char new[CONFIG_RUN_ID_SIZE+1];
            memcpy(new,start,CONFIG_RUN_ID_SIZE);
            new[CONFIG_RUN_ID_SIZE] = '\0';

            if (strcmp(new,server.cached_master->replid)) {
                /* Master ID changed. */
                serverLog(LL_WARNING,"Master replication ID changed to %s",new);

                /* Set the old ID as our ID2, up to the current offset+1. */
                //将原id1视为id2，添加修正偏移量
                memcpy(server.replid2,server.cached_master->replid,
                    sizeof(server.replid2));
                server.second_replid_offset = server.master_repl_offset+1;

                /* Update the cached master ID and our own primary ID to the
                 * new one. */
                //更新id
                memcpy(server.replid,new,sizeof(server.replid));
                memcpy(server.cached_master->replid,new,sizeof(server.replid));

                /* Disconnect all the sub-slaves: they need to be notified. */
                disconnectSlaves();
            }
        }

        /* Setup the replication to continue. */
        sdsfree(reply);
        //设被同步的主节点未当前主节点
        replicationResurrectCachedMaster(fd);

        /* If this instance was restarted and we read the metadata to
         * PSYNC from the persistence file, our replication backlog could
         * be still not initialized. Create it. */
        //创建积压记录
        if (server.repl_backlog == NULL) createReplicationBacklog();
        return PSYNC_CONTINUE;
    }

    /* If we reach this point we received either an error (since the master does
     * not understand PSYNC or because it is in a special state and cannot
     * serve our request), or an unexpected reply from the master.
     *
     * Return PSYNC_NOT_SUPPORTED on errors we don't understand, otherwise
     * return PSYNC_TRY_LATER if we believe this is a transient error. */

	//错误处理
	//1.接到SYNC命令的从节点未与主节点连接
	//2.正在加载数据
	//3.1从节点无法识别
	//3.2主节点不支持PSYNC命令
    if (!strncmp(reply,"-NOMASTERLINK",13) ||
        !strncmp(reply,"-LOADING",8))
    {
        serverLog(LL_NOTICE,
            "Master is currently unable to PSYNC "
            "but should be in the future: %s", reply);
        sdsfree(reply);
        return PSYNC_TRY_LATER;
    }

    if (strncmp(reply,"-ERR",4)) {
        /* If it's not an error, log the unexpected event. */
        serverLog(LL_WARNING,
            "Unexpected reply to PSYNC from master: %s", reply);
    } else {
        serverLog(LL_NOTICE,
            "Master does not support PSYNC or is in "
            "error state (reply: %s)", reply);
    }
    sdsfree(reply);
    replicationDiscardCachedMaster();
    return PSYNC_NOT_SUPPORTED;
}
```

slaveTryPartialResynchronization()返回请求同步的结果，回到syncWithMaster()中

在两种情况下可准备开始接受rdb文件

1. slaveTryPartialResynchronization()返回PSYNC_FULLRESYNC，进行全量同步
2. slaveTryPartialResynchronization()返回PSYNC_NOT_SUPPORTED，PSYNC命令不支持

其他情况下syncWithMaster()会转入错误处理或直接返回

```c
//接上一块syncWithMaster()
    if (psync_result == PSYNC_WAIT_REPLY) return; /* Try again later... */

    /* If the master is in an transient error, we should try to PSYNC
     * from scratch later, so go to the error path. This happens when
     * the server is loading the dataset or is not connected with its
     * master and so forth. */
    if (psync_result == PSYNC_TRY_LATER) goto error;

    /* Note: if PSYNC does not return WAIT_REPLY, it will take care of
     * uninstalling the read handler from the file descriptor. */

    if (psync_result == PSYNC_CONTINUE) {
        serverLog(LL_NOTICE, "MASTER <-> SLAVE sync: Master accepted a Partial Resynchronization.");
        return;
    }

    /* PSYNC failed or is not supported: we want our slaves to resync with us
     * as well, if we have any sub-slaves. The master may transfer us an
     * entirely different data set and we have no way to incrementally feed
     * our slaves after that. */
    disconnectSlaves(); /* Force our slaves to resync with us as well. */
    freeReplicationBacklog(); /* Don't allow our chained slaves to PSYNC. */

    /* Fall back to SYNC if needed. Otherwise psync_result == PSYNC_FULLRESYNC
     * and the server.master_replid and master_initial_offset are
     * already populated. */
	//主节点版本不兼容PSYNC命令，则使用SYNC命令
    if (psync_result == PSYNC_NOT_SUPPORTED) {
        serverLog(LL_NOTICE,"Retrying with SYNC...");
        //尝试向主节点发送SYNC命令
        if (syncWrite(fd,"SYNC\r\n",6,server.repl_syncio_timeout*1000) == -1) {
            serverLog(LL_WARNING,"I/O error writing to MASTER: %s",
                strerror(errno));
            goto error;
        }
    }

    /* Prepare a suitable temp file for bulk transfer */
	//准备接收数据的文件

    while(maxtries--) {
        snprintf(tmpfile,256,
            "temp-%d.%ld.rdb",(int)server.unixtime,(long int)getpid());
        //O_CREAT：文件不存在则创建，要有第三个表示文件访问权限的参数
        //O_WRONLY：只写
        //O_EXCL：设置了O_CREAT时，如果文件存在则出错
        dfd = open(tmpfile,O_CREAT|O_WRONLY|O_EXCL,0644);
        if (dfd != -1) break;
        sleep(1);
    }
    if (dfd == -1) {
        serverLog(LL_WARNING,"Opening the temp file needed for MASTER <-> SLAVE synchronization: %s",strerror(errno));
        goto error;
    }

    /* Setup the non blocking download of the bulk file. */
	//设置读事件的处理函数
    if (aeCreateFileEvent(server.el,fd, AE_READABLE,readSyncBulkPayload,NULL)
            == AE_ERR)
    {
        serverLog(LL_WARNING,
            "Can't create readable event for SYNC: %s (fd=%d)",
            strerror(errno),fd);
        goto error;
    }

	//更改一些列状态
    server.repl_state = REPL_STATE_TRANSFER;
    server.repl_transfer_size = -1;
    server.repl_transfer_read = 0;
    server.repl_transfer_last_fsync_off = 0;
    server.repl_transfer_fd = dfd;
    server.repl_transfer_lastio = server.unixtime;
    server.repl_transfer_tmpfile = zstrdup(tmpfile);  //保存临时文件名
    return;

error:
	//取消所有事件监听
    aeDeleteFileEvent(server.el,fd,AE_READABLE|AE_WRITABLE);
	//关闭文件和socket
    if (dfd != -1) close(dfd);
    close(fd);
    server.repl_transfer_s = -1;
	//要从新开始连接主节点
    server.repl_state = REPL_STATE_CONNECT;
    return;

write_error: /* Handle sendSynchronousCommand(SYNC_CMD_WRITE) errors. */
    serverLog(LL_WARNING,"Sending command to master in replication handshake: %s", err);
    sdsfree(err);
    goto error;
}
```

从节点将打开一个临时文件等待写入，并更改状态为REPL_STATE_TRANSFER

这时从节点已做好接收rdb文件的准备

主节点中，rdb文件的发送不是主动执行，而是放在循环事件serverCron()中

serverCron() -> backgroundSaveHandler() -> backgroundSaveDoneHandlerDisk() -> updateSlavesWaitingBgsave() -> sendBulkToSlave()

```c
//主节点
void updateSlavesWaitingBgsave(int bgsaveerr, int type) {
    listNode *ln;
    int startbgsave = 0;
    int mincapa = -1;
    listIter li;

    listRewind(server.slaves,&li);
    //遍历所有从节点
    while((ln = listNext(&li))) {
        client *slave = ln->value;
        //检查复制状态
        //如果是等待开始，则还未进行通知
        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
            //设置bgsave开始标志
            startbgsave = 1;
            mincapa = (mincapa == -1) ? slave->slave_capa :
                                        (mincapa & slave->slave_capa);
        //等待结束，即通知完毕可进行rdb文件传输
        } else if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) {
            struct redis_stat buf;

            /* If this was an RDB on disk save, we have to prepare to send
             * the RDB from disk to the slave socket. Otherwise if this was
             * already an RDB -> Slaves socket transfer, used in the case of
             * diskless replication, our work is trivial, we can just put
             * the slave online. */
            //无盘同步
            if (type == RDB_CHILD_TYPE_SOCKET) {
                serverLog(LL_NOTICE,
                    "Streamed RDB transfer with slave %s succeeded (socket). Waiting for REPLCONF ACK from slave to enable streaming",
                        replicationGetSlaveName(slave));
                /* Note: we wait for a REPLCONF ACK message from slave in
                 * order to really put it online (install the write handler
                 * so that the accumulated data can be transfered). However
                 * we change the replication state ASAP, since our slave
                 * is technically online now. */
                //只需要更改状态
                slave->replstate = SLAVE_STATE_ONLINE;
                slave->repl_put_online_on_ack = 1;
                slave->repl_ack_time = server.unixtime; /* Timeout otherwise. */
            //如果不是无盘同步
            } else {
                //检查BGSAVE执行情况
                if (bgsaveerr != C_OK) {
                    freeClient(slave);
                    serverLog(LL_WARNING,"SYNC failed. BGSAVE child returned an error");
                    continue;
                }
                //以只读方式打开临时的rdb文件
                if ((slave->repldbfd = open(server.rdb_filename,O_RDONLY)) == -1 ||
                    redis_fstat(slave->repldbfd,&buf) == -1) {
                    freeClient(slave);
                    serverLog(LL_WARNING,"SYNC failed. Can't open/stat DB after BGSAVE: %s", strerror(errno));
                    continue;
                }
                slave->repldboff = 0;
                slave->repldbsize = buf.st_size;
                slave->replstate = SLAVE_STATE_SEND_BULK;
                slave->replpreamble = sdscatprintf(sdsempty(),"$%lld\r\n",
                    (unsigned long long) slave->repldbsize);
			   //先删除原有的处理函数
                aeDeleteFileEvent(server.el,slave->fd,AE_WRITABLE);
                //再将sendBulkToSlave设置为与从节点连接可写事件的处理函数
                if (aeCreateFileEvent(server.el, slave->fd, AE_WRITABLE, sendBulkToSlave, slave) == AE_ERR) {
                    freeClient(slave);
                    continue;
                }
            }
        }
    }
    if (startbgsave) startBgsaveForReplication(mincapa);
}
```

sendBulkToSlave()函数将rdb文件写入socket后，再次删除socket的可写事件

调用putSlaveOnline()，在主节点视角设置此从节点状态为SLAVE_STATE_ONLINE，表示已进行过全量同步，从节点处于在线可用状态

在putSlaveOnline()中还将可写事件与sendReplyToClient()绑定，此时同时触发第一次可写事件

这次可写事件会将从节点客户端的输出缓冲区的数据发送出去

至此，在第一次全量同步后，主从服务器状态达到一致

**关于从节点的输出缓冲区**

用于主节点执行命令后，从节点内容的更新

执行命令的主体在call()中

当call()检测到数据修改时会调用 propagate() -> replicationFeedSlaves() 传播变更记录

将修改记录写入积压记录(server.repl_backlog)与所有从节点

保留积压记录是为了在与从节点的连接出现问题时，让断开连接的从节点下次连接后能够获得更新的数(部分重同步)

```c
void replicationFeedSlaves(list *slaves, int dictid, robj **argv, int argc) {
    listNode *ln;
    listIter li;
    int j, len;
    char llstr[LONG_STR_SIZE];

    /* If the instance is not a top level master, return ASAP: we'll just proxy
     * the stream of data we receive from our master instead, in order to
     * propagate *identical* replication stream. In this way this slave can
     * advertise the same replication ID as the master (since it shares the
     * master replication history and has the same backlog and offsets). */
    //没有连接的主节点
    if (server.masterhost != NULL) return;

    /* If there aren't slaves, and there is no backlog buffer to populate,
     * we can return ASAP. */
    //没有已创建的积压记录，也没有从节点记录
    if (server.repl_backlog == NULL && listLength(slaves) == 0) return;

    /* We can't have slaves attached and no backlog. */
    serverAssert(!(listLength(slaves) != 0 && server.repl_backlog == NULL));

    /* Send SELECT command to every slave if needed. */
    //当前从节点选择的数据库不是目标数据库
    if (server.slaveseldb != dictid) {
        robj *selectcmd;

        /* For a few DBs we have pre-computed SELECT command. */
        //使用共享的SELECT命令对象
        if (dictid >= 0 && dictid < PROTO_SHARED_SELECT_CMDS) {
            selectcmd = shared.select[dictid];
        //没有只能创建一个新命令对象
        } else {
            int dictid_len;

            dictid_len = ll2string(llstr,sizeof(llstr),dictid);
            selectcmd = createObject(OBJ_STRING,
                sdscatprintf(sdsempty(),
                "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n",
                dictid_len, llstr));
        }

        /* Add the SELECT command into the backlog. */
        //将命令加入积压记录中
        if (server.repl_backlog) feedReplicationBacklogWithObject(selectcmd);

        /* Send it to slaves. */
        listRewind(slaves,&li);
        //遍历所有从节点
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            //跳过等待开始的节点，这些节点还没有准备好接收
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) continue;
            addReply(slave,selectcmd);
        }

        if (dictid < 0 || dictid >= PROTO_SHARED_SELECT_CMDS)
            decrRefCount(selectcmd);
    }
    //设置当前使用的数据库id
    server.slaveseldb = dictid;

    /* Write the command to the replication backlog if any. */
    //将命令写入积压记录
    if (server.repl_backlog) {
        char aux[LONG_STR_SIZE+3];

        /* Add the multi bulk reply length. */
        aux[0] = '*';
        len = ll2string(aux+1,sizeof(aux)-1,argc);
        aux[len+1] = '\r';
        aux[len+2] = '\n';
        feedReplicationBacklog(aux,len+3);
		
        //遍历所有参数
        for (j = 0; j < argc; j++) {
            long objlen = stringObjectLen(argv[j]);

            /* We need to feed the buffer with the object as a bulk reply
             * not just as a plain string, so create the $..CRLF payload len
             * and add the final CRLF */
            aux[0] = '$';
            len = ll2string(aux+1,sizeof(aux)-1,objlen);
            aux[len+1] = '\r';
            aux[len+2] = '\n';
            feedReplicationBacklog(aux,len+3);
            feedReplicationBacklogWithObject(argv[j]);
            feedReplicationBacklog(aux+len+1,2);
        }
    }

    /* Write the command to every slave. */
    listRewind(slaves,&li);
    //遍历从节点
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        /* Don't feed slaves that are still waiting for BGSAVE to start */
        //跳过等待开始的节点，这些节点并没有完成同步
        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) continue;

        /* Feed slaves that are waiting for the initial SYNC (so these commands
         * are queued in the output buffer until the initial SYNC completes),
         * or are already in sync with the master. */

        /* Add the multi bulk length. */
        //将命令写入缓冲区
        addReplyMultiBulkLen(slave,argc);

        /* Finally any additional argument that was not stored inside the
         * static buffer if any (from j to argc). */
        //将参数写入缓冲区
        for (j = 0; j < argc; j++)
            addReplyBulk(slave,argv[j]);
    }
}
```

##### 00x09 部分重同步机制

---

从节点与主节点短时断连后，需要进行数据同步

2.8版本前会进行全量同步，开销非常大

之后加入了部分重同步

需要注意的是，断连时间过长会导致必须进行全量同步，详见backlog复制部分

在连接时，因为缓存不为空，从节点尝试请求部分同步，成功时主节点回复"+CONTINUE"

**断连发现**

之前推断过主节点将从节点当作一个特殊的客户端来对待

实际上主节点与从节点都将对方当作自己的客户端，并彼此发送心跳命令

动作定义在replicationCron()中

- 主节点

  依照配置中的 repl-ping-slave-period 作为间隔时间向从节点发送PING命令 (默认为10s)

  ```c
  void replicationCron(void){
      //......
  	if ((replication_cron_loops % server.repl_ping_slave_period) == 0 &&
              listLength(server.slaves))
     	    {
          	//创建PING命令
              ping_argv[0] = createStringObject("PING",4);
          	//发送PING命令
              replicationFeedSlaves(server.slaves, server.slaveseldb,
                  ping_argv, 1);
          	//清除临时命令对象
              decrRefCount(ping_argv[0]);
          }
      //......
  }
  ```

- 从节点

  每隔1秒向主节点发送一个 `REPLCONF ACK <offset>` 命令，offset为当前复制偏移量

  ```c
  void replicationCron(void){
      //......
      if (server.masterhost && server.master &&
      !(server.master->flags & CLIENT_PRE_PSYNC))
      replicationSendAck();
      //......
  }
  
  void replicationSendAck(void) {
      client *c = server.master;
  
      if (c != NULL) {
          c->flags |= CLIENT_MASTER_FORCE_REPLY;
          addReplyMultiBulkLen(c,3);
          addReplyBulkCString(c,"REPLCONF");
          addReplyBulkCString(c,"ACK");
          addReplyBulkLongLong(c,c->reploff);
          c->flags &= ~CLIENT_MASTER_FORCE_REPLY;
      }
  }
  ```

当repilcationCron()中检查到连接超时，会调用cancelReplicationHandshake()取消两者的连接，等待网络恢复时重新进行建立连接的操作

**backlog复制**

backlog时一个大小仅有1M的循环队列

如果断开连接的时间内，主节点数据有超过1M的变更，就需要从节点进行全量同步

```c
//部分重同步实现
int masterTryPartialResynchronization(client *c) {
    long long psync_offset, psync_len;
    char *master_replid = c->argv[1]->ptr;
    char buf[128];
    int buflen;

    /* Parse the replication offset asked by the slave. Go to full sync
     * on parse error: this should never happen but we try to handle
     * it in a robust way compared to aborting. */
    //检查发来命令的从节点是否只能进行全量同步
    if (getLongLongFromObjectOrReply(c,c->argv[2],&psync_offset,NULL) !=
       C_OK) goto need_full_resync;

    /* Is the replication ID of this master the same advertised by the wannabe
     * slave via PSYNC? If the replication ID changed this master has a
     * different replication history, and there is no way to continue.
     *
     * Note that there are two potentially valid replication IDs: the ID1
     * and the ID2. The ID2 however is only valid up to a specific offset. */
    if (strcasecmp(master_replid, server.replid) &&
        (strcasecmp(master_replid, server.replid2) ||
         psync_offset > server.second_replid_offset))
    {
        /* Run id "?" is used by slaves that want to force a full resync. */
        //如果传来的id为？，则表示从节点要强制进行全量同步
        if (master_replid[0] != '?') {
            if (strcasecmp(master_replid, server.replid) &&
                strcasecmp(master_replid, server.replid2))
            {
                serverLog(LL_NOTICE,"Partial resynchronization not accepted: "
                    "Replication ID mismatch (Slave asked for '%s', my "
                    "replication IDs are '%s' and '%s')",
                    master_replid, server.replid, server.replid2);
            } else {
                serverLog(LL_NOTICE,"Partial resynchronization not accepted: "
                    "Requested offset for second ID was %lld, but I can reply "
                    "up to %lld", psync_offset, server.second_replid_offset);
            }
        } else {
            serverLog(LL_NOTICE,"Full resync requested by slave %s",
                replicationGetSlaveName(c));
        }
        goto need_full_resync;
    }

    /* We still have the data our slave is asking for? */
    //1.未创建积压记录
    //2.psync_offset < server.repl_backlog_off backlog数据太新，与从节点数据有断层
    //3.psync_offset > (server.repl_backlog_off + server.repl_backlog_histlen)
    //  backlog数据不全
    //都需要进行全量同步
    if (!server.repl_backlog ||
        psync_offset < server.repl_backlog_off ||
        psync_offset > (server.repl_backlog_off + server.repl_backlog_histlen))
    {
        serverLog(LL_NOTICE,
            "Unable to partial resync with slave %s for lack of backlog (Slave request was: %lld).", replicationGetSlaveName(c), psync_offset);
        if (psync_offset > server.master_repl_offset) {
            serverLog(LL_WARNING,
                "Warning: slave %s tried to PSYNC with an offset that is greater than the master replication offset.", replicationGetSlaveName(c));
        }
        goto need_full_resync;
    }

    /* If we reached this point, we are able to perform a partial resync:
     * 1) Set client state to make it a slave.
     * 2) Inform the client we can continue with +CONTINUE
     * 3) Send the backlog data (from the offset to the end) to the slave. */
    //进行到这里表示从节点可以进行部分重同步
    //设置client为从节点
    c->flags |= CLIENT_SLAVE;
    //上线
    c->replstate = SLAVE_STATE_ONLINE;
    c->repl_ack_time = server.unixtime;
    c->repl_put_online_on_ack = 0;
    listAddNodeTail(server.slaves,c);
    /* We can't use the connection buffers since they are used to accumulate
     * new commands at this stage. But we are sure the socket send buffer is
     * empty so this write will never fail actually. */
    //根据capacity发送不同回复
    if (c->slave_capa & SLAVE_CAPA_PSYNC2) {
        buflen = snprintf(buf,sizeof(buf),"+CONTINUE %s\r\n", server.replid);
    } else {
        buflen = snprintf(buf,sizeof(buf),"+CONTINUE\r\n");
    }
    if (write(c->fd,buf,buflen) != buflen) {
        freeClientAsync(c);
        return C_OK;
    }
    //发送回复
    psync_len = addReplyReplicationBacklog(c,psync_offset);
    serverLog(LL_NOTICE,
        "Partial resynchronization request from %s accepted. Sending %lld bytes of backlog starting from offset %lld.",
            replicationGetSlaveName(c),
            psync_len, psync_offset);
    /* Note that we don't need to set the selected DB at server.slaveseldb
     * to -1 to force the master to emit SELECT, since the slave already
     * has this state from the previous connection with the master. */
    //计算延迟小于min-slaves-max-lag的从节点个数
    refreshGoodSlavesCount();
    return C_OK; /* The caller can return, no full resync needed. */

need_full_resync:
    /* We need a full resync for some reason... Note that we can't
     * reply to PSYNC right now if a full SYNC is needed. The reply
     * must include the master offset at the time the RDB file we transfer
     * is generated, so we need to delay the reply to that moment. */
    return C_ERR;
}
```

**PSYNC2**

4.0版本后，为了在从节点重连，主从切换后也能使用部分重同步，redis新上线了PSYNC2作为PSYNC的升级版

在PSYNC2中，除master_replid外又新增了master_replid2用于存储前一次连接的主节点replid1

如果一个从节点所属的主节点未发生过变化，那其记录的replid2仍为初始值0

##### 00x10 集群伸缩

---



#### 哨兵节点

##### 00x11 开启sentinel

---

sentinel实际上也是一个redis服务，特殊模式下运行的节点

sentinel模式与cluster模式互斥

哨兵节点开启的一系列操作都在main()中执行

```c
int main(int argc, char **argv) {
    //......
    //检查命令行中是否选择开启sentinal模式
    server.sentinel_mode = checkForSentinelMode(argc,argv); 
    //......
    /* We need to init sentinel right now as parsing the configuration file
     * in sentinel mode will have the effect of populating the sentinel
     * data structures with master nodes to monitor. */
    //初始化
    if (server.sentinel_mode) {
        initSentinelConfig();
        initSentinel();
    }
    //......
    if (argc >= 2) {
        //......
        //载入配置
        loadServerConfig(configfile,options);
        //......
    }
    //.......
    if (!server.sentinel_mode) {
        //......
    } else {
        //更改服务状态
        sentinelIsRunning();
    }
    //......
}
```

**检查是否开启哨兵模式**

1. redis-sentinel example.conf
2. redis-server --sentinel example.conf 

```c
int checkForSentinelMode(int argc, char **argv) {
    int j;

    if (strstr(argv[0],"redis-sentinel") != NULL) return 1;
    for (j = 1; j < argc; j++)
        if (!strcmp(argv[j],"--sentinel")) return 1;
    return 0;
}
```

**初始化**

```c
//初始化配置
void initSentinelConfig(void) {
    server.port = REDIS_SENTINEL_PORT;
}

//初始化sentinel状态
void initSentinel(void) {
    unsigned int j;

    /* Remove usual Redis commands from the command table, then just add
     * the SENTINEL command. */
    dictEmpty(server.commands,NULL);
    //用SENTINEL系列命令代替原命令表
    for (j = 0; j < sizeof(sentinelcmds)/sizeof(sentinelcmds[0]); j++) {
        int retval;
        struct redisCommand *cmd = sentinelcmds+j;

        retval = dictAdd(server.commands, sdsnew(cmd->name), cmd);
        serverAssert(retval == DICT_OK);
    }

    /* Initialize various data structures. */
    sentinel.current_epoch = 0;
    sentinel.masters = dictCreate(&instancesDictType,NULL);
    sentinel.tilt = 0;
    sentinel.tilt_start_time = 0;
    sentinel.previous_time = mstime();
    sentinel.running_scripts = 0;
    sentinel.scripts_queue = listCreate();
    sentinel.announce_ip = NULL;
    sentinel.announce_port = 0;
    sentinel.simfailure_flags = SENTINEL_SIMFAILURE_NONE;
    memset(sentinel.myid,0,sizeof(sentinel.myid));
}
```

**sentinel相关配置**

loadServerConfig() -> loadServerConfigFromString() -> sentinelHandleConfiguration()

```c
char *sentinelHandleConfiguration(char **argv, int argc) {
    sentinelRedisInstance *ri;
	
    //sentinel monitor <name> <host> <port> <quorum>
    //设置当前sentinel监控的主节点
    if (!strcasecmp(argv[0],"monitor") && argc == 5) {
        /* monitor <name> <host> <port> <quorum> */
        //判断主节点失效需要sentinel同意的个数，参数中至少为1
        int quorum = atoi(argv[4]);

        if (quorum <= 0) return "Quorum must be 1 or greater.";
        //创建主节点实例，存入sentinel.masters
        if (createSentinelRedisInstance(argv[1],SRI_MASTER,argv[2],
                                        atoi(argv[3]),quorum,NULL) == NULL)
        {
            switch(errno) {
            case EBUSY: return "Duplicated master name.";
            case ENOENT: return "Can't resolve master instance hostname.";
            case EINVAL: return "Invalid port number";
            }
        }
    //sentinel down-after-milliseconds <name> <milliseconds> 
    //设置多少毫秒无应答后，判断主节点或数据节点不可达
    } else if (!strcasecmp(argv[0],"down-after-milliseconds") && argc == 3) {
        /* down-after-milliseconds <name> <milliseconds> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->down_after_period = atoi(argv[2]);
        if (ri->down_after_period <= 0)
            return "negative or zero time parameter.";
        sentinelPropagateDownAfterPeriod(ri);
    //故障转移超时时间
    } else if (!strcasecmp(argv[0],"failover-timeout") && argc == 3) {
        /* failover-timeout <name> <milliseconds> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->failover_timeout = atoi(argv[2]);
        if (ri->failover_timeout <= 0)
            return "negative or zero time parameter.";
   //故障转移过程中，同时有几个从节点向新的主节点发起复制
   } else if (!strcasecmp(argv[0],"parallel-syncs") && argc == 3) {
        /* parallel-syncs <name> <milliseconds> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->parallel_syncs = atoi(argv[2]);
   //出现警告级事件时触发的脚本
   } else if (!strcasecmp(argv[0],"notification-script") && argc == 3) {
        /* notification-script <name> <path> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        if (access(argv[2],X_OK) == -1)
            return "Notification script seems non existing or non executable.";
        ri->notification_script = sdsnew(argv[2]);
   //设置发生主从切换时触发的脚本
   } else if (!strcasecmp(argv[0],"client-reconfig-script") && argc == 3) {
        /* client-reconfig-script <name> <path> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        if (access(argv[2],X_OK) == -1)
            return "Client reconfiguration script seems non existing or "
                   "non executable.";
        ri->client_reconfig_script = sdsnew(argv[2]);
   //连接当前sentinel的密码，因其连接时的传递性，应与主节点相同
   } else if (!strcasecmp(argv[0],"auth-pass") && argc == 3) {
        /* auth-pass <name> <password> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->auth_pass = sdsnew(argv[2]);
    //当前纪元，再启动恢复状态时读取，不可随意更改
    } else if (!strcasecmp(argv[0],"current-epoch") && argc == 2) {
        /* current-epoch <epoch> */
        unsigned long long current_epoch = strtoull(argv[1],NULL,10);
        if (current_epoch > sentinel.current_epoch)
            sentinel.current_epoch = current_epoch;
    //sentinel id
    } else if (!strcasecmp(argv[0],"myid") && argc == 2) {
        if (strlen(argv[1]) != CONFIG_RUN_ID_SIZE)
            return "Malformed Sentinel id in myid option.";
        memcpy(sentinel.myid,argv[1],CONFIG_RUN_ID_SIZE);
    //配置纪元
    } else if (!strcasecmp(argv[0],"config-epoch") && argc == 3) {
        /* config-epoch <name> <epoch> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->config_epoch = strtoull(argv[2],NULL,10);
        /* The following update of current_epoch is not really useful as
         * now the current epoch is persisted on the config file, but
         * we leave this check here for redundancy. */
        if (ri->config_epoch > sentinel.current_epoch)
            sentinel.current_epoch = ri->config_epoch;
    //leader字段纪元
    } else if (!strcasecmp(argv[0],"leader-epoch") && argc == 3) {
        /* leader-epoch <name> <epoch> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        ri->leader_epoch = strtoull(argv[2],NULL,10);
    //已知的从节点
    } else if (!strcasecmp(argv[0],"known-slave") && argc == 4) {
        sentinelRedisInstance *slave;

        /* known-slave <name> <ip> <port> */
        ri = sentinelGetMasterByName(argv[1]);
        if (!ri) return "No such master with specified name.";
        if ((slave = createSentinelRedisInstance(NULL,SRI_SLAVE,argv[2],
                    atoi(argv[3]), ri->quorum, ri)) == NULL)
        {
            return "Wrong hostname or port for slave.";
        }
    //已知哨兵节点
    } else if (!strcasecmp(argv[0],"known-sentinel") &&
               (argc == 4 || argc == 5)) {
        sentinelRedisInstance *si;

        if (argc == 5) { /* Ignore the old form without runid. */
            /* known-sentinel <name> <ip> <port> [runid] */
            ri = sentinelGetMasterByName(argv[1]);
            if (!ri) return "No such master with specified name.";
            if ((si = createSentinelRedisInstance(argv[4],SRI_SENTINEL,argv[2],
                        atoi(argv[3]), ri->quorum, ri)) == NULL)
            {
                return "Wrong hostname or port for sentinel.";
            }
            si->runid = sdsnew(argv[4]);
            sentinelTryConnectionSharing(si);
        }
    } else if (!strcasecmp(argv[0],"announce-ip") && argc == 2) {
        /* announce-ip <ip-address> */
        if (strlen(argv[1]))
            sentinel.announce_ip = sdsnew(argv[1]);
    } else if (!strcasecmp(argv[0],"announce-port") && argc == 2) {
        /* announce-port <port> */
        sentinel.announce_port = atoi(argv[1]);
    } else {
        return "Unrecognized sentinel configuration statement.";
    }
    return NULL;
}
```

其中比较重要的两个函数

- createSentinelRedisInstance() 创建节点实例

  参数中flags部分用来标识节点类型

  SRI_MASTER，实例会被加入sentinel.masters

  SRI_SLAVE/SRI_SENTINEL，并且masters非空，实例会被分别加入master->slaves/sentinels与主节点关联

  ​	这种情况下别名无效，会被设置为host:port

  ```c
  #define SRI_MASTER  (1<<0)
  #define SRI_SLAVE   (1<<1)
  #define SRI_SENTINEL (1<<2)
  
  //实例数据结构
  typedef struct sentinelRedisInstance {
      int flags;      /* See SRI_... defines */
      char *name;     /* Master name from the point of view of this sentinel. */
      char *runid;    /* Run ID of this instance, or unique ID if is a Sentinel.*/
      uint64_t config_epoch;  /* Configuration epoch. */
      sentinelAddr *addr; /* Master host. */
      instanceLink *link; /* Link to the instance, may be shared for Sentinels. */
      mstime_t last_pub_time;   /* Last time we sent hello via Pub/Sub. */
      mstime_t last_hello_time; /* Only used if SRI_SENTINEL is set. Last time
                                   we received a hello from this Sentinel
                                   via Pub/Sub. */
      mstime_t last_master_down_reply_time; /* Time of last reply to
                                               SENTINEL is-master-down command. */
      mstime_t s_down_since_time; /* Subjectively down since time. */
      mstime_t o_down_since_time; /* Objectively down since time. */
      mstime_t down_after_period; /* Consider it down after that period. */
      mstime_t info_refresh;  /* Time at which we received INFO output from it. */
  
      /* Role and the first time we observed it.
       * This is useful in order to delay replacing what the instance reports
       * with our own configuration. We need to always wait some time in order
       * to give a chance to the leader to report the new configuration before
       * we do silly things. */
      int role_reported;
      mstime_t role_reported_time;
      mstime_t slave_conf_change_time; /* Last time slave master addr changed. */
  
      /* Master specific. */
      dict *sentinels;    /* Other sentinels monitoring the same master. */
      dict *slaves;       /* Slaves for this master instance. */
      unsigned int quorum;/* Number of sentinels that need to agree on failure. */
      int parallel_syncs; /* How many slaves to reconfigure at same time. */
      char *auth_pass;    /* Password to use for AUTH against master & slaves. */
  
      /* Slave specific. */
      mstime_t master_link_down_time; /* Slave replication link down time. */
      int slave_priority; /* Slave priority according to its INFO output. */
      mstime_t slave_reconf_sent_time; /* Time at which we sent SLAVE OF <new> */
      struct sentinelRedisInstance *master; /* Master instance if it's slave. */
      char *slave_master_host;    /* Master host as reported by INFO */
      int slave_master_port;      /* Master port as reported by INFO */
      int slave_master_link_status; /* Master link status as reported by INFO */
      unsigned long long slave_repl_offset; /* Slave replication offset. */
      /* Failover */
      char *leader;       /* If this is a master instance, this is the runid of
                             the Sentinel that should perform the failover. If
                             this is a Sentinel, this is the runid of the Sentinel
                             that this Sentinel voted as leader. */
      uint64_t leader_epoch; /* Epoch of the 'leader' field. */
      uint64_t failover_epoch; /* Epoch of the currently started failover. */
      int failover_state; /* See SENTINEL_FAILOVER_STATE_* defines. */
      mstime_t failover_state_change_time;
      mstime_t failover_start_time;   /* Last failover attempt start time. */
      mstime_t failover_timeout;      /* Max time to refresh failover state. */
      mstime_t failover_delay_logged; /* For what failover_start_time value we
                                         logged the failover delay. */
      struct sentinelRedisInstance *promoted_slave; /* Promoted slave instance. */
      /* Scripts executed to notify admin or reconfigure clients: when they
       * are set to NULL no script is executed. */
      char *notification_script;
      char *client_reconfig_script;
      sds info; /* cached INFO output */
  } sentinelRedisInstance;
  
  sentinelRedisInstance *createSentinelRedisInstance(char *name, int flags, char *hostname, int port, int quorum, sentinelRedisInstance *master) {
      sentinelRedisInstance *ri;
      sentinelAddr *addr;
      dict *table = NULL;
      char slavename[NET_PEER_ID_LEN], *sdsname;
  
      serverAssert(flags & (SRI_MASTER|SRI_SLAVE|SRI_SENTINEL));
      serverAssert((flags & SRI_MASTER) || master != NULL);
  
      /* Check address validity. */
      addr = createSentinelAddr(hostname,port);
      if (addr == NULL) return NULL;
  
      /* For slaves use ip:port as name. */
      if (flags & SRI_SLAVE) {
          anetFormatAddr(slavename, sizeof(slavename), hostname, port);
          name = slavename;
      }
  
      /* Make sure the entry is not duplicated. This may happen when the same
       * name for a master is used multiple times inside the configuration or
       * if we try to add multiple times a slave or sentinel with same ip/port
       * to a master. */
      if (flags & SRI_MASTER) table = sentinel.masters;
      else if (flags & SRI_SLAVE) table = master->slaves;
      else if (flags & SRI_SENTINEL) table = master->sentinels;
      sdsname = sdsnew(name);
      if (dictFind(table,sdsname)) {
          releaseSentinelAddr(addr);
          sdsfree(sdsname);
          errno = EBUSY;
          return NULL;
      }
  
      /* Create the instance object. */
      ri = zmalloc(sizeof(*ri));
      /* Note that all the instances are started in the disconnected state,
       * the event loop will take care of connecting them. */
      ri->flags = flags;
      ri->name = sdsname;
      ri->runid = NULL;
      ri->config_epoch = 0;
      ri->addr = addr;
      ri->link = createInstanceLink();
      ri->last_pub_time = mstime();
      ri->last_hello_time = mstime();
      ri->last_master_down_reply_time = mstime();
      ri->s_down_since_time = 0;
      ri->o_down_since_time = 0;
      ri->down_after_period = master ? master->down_after_period :
                              SENTINEL_DEFAULT_DOWN_AFTER;
      ri->master_link_down_time = 0;
      ri->auth_pass = NULL;
      ri->slave_priority = SENTINEL_DEFAULT_SLAVE_PRIORITY;
      ri->slave_reconf_sent_time = 0;
      ri->slave_master_host = NULL;
      ri->slave_master_port = 0;
      ri->slave_master_link_status = SENTINEL_MASTER_LINK_STATUS_DOWN;
      ri->slave_repl_offset = 0;
      ri->sentinels = dictCreate(&instancesDictType,NULL);
      ri->quorum = quorum;
      ri->parallel_syncs = SENTINEL_DEFAULT_PARALLEL_SYNCS;
      ri->master = master;
      ri->slaves = dictCreate(&instancesDictType,NULL);
      ri->info_refresh = 0;
  
      /* Failover state. */
      ri->leader = NULL;
      ri->leader_epoch = 0;
      ri->failover_epoch = 0;
      ri->failover_state = SENTINEL_FAILOVER_STATE_NONE;
      ri->failover_state_change_time = 0;
      ri->failover_start_time = 0;
      ri->failover_timeout = SENTINEL_DEFAULT_FAILOVER_TIMEOUT;
      ri->failover_delay_logged = 0;
      ri->promoted_slave = NULL;
      ri->notification_script = NULL;
      ri->client_reconfig_script = NULL;
      ri->info = NULL;
  
      /* Role */
      ri->role_reported = ri->flags & (SRI_MASTER|SRI_SLAVE);
      ri->role_reported_time = mstime();
      ri->slave_conf_change_time = mstime();
  
      /* Add into the right table. */
      dictAdd(table, ri->name, ri);
      return ri;
  }
  ```

- sentinelGetMasterByName() 通过别名获取主节点实例

  ```c
  sentinelRedisInstance *sentinelGetMasterByName(char *name) {
      sentinelRedisInstance *ri;
      sds sdsname = sdsnew(name);
  
      ri = dictFetchValue(sentinel.masters,sdsname);
      sdsfree(sdsname);
      return ri;
  }
  ```

**启动sentinel**

调用sentinelIsRunning()，重写配置文件并最终启动服务

```c
void sentinelIsRunning(void) {
    int j;

    //没有设置配置文件，结束
    if (server.configfile == NULL) {
        serverLog(LL_WARNING,
            "Sentinel started without a config file. Exiting...");
        exit(1);
    //有配置文件但没有写权限，退出
    } else if (access(server.configfile,W_OK) == -1) {
        serverLog(LL_WARNING,
            "Sentinel config file %s is not writable: %s. Exiting...",
            server.configfile,strerror(errno));
        exit(1);
    }

    /* If this Sentinel has yet no ID set in the configuration file, we
     * pick a random one and persist the config on disk. From now on this
     * will be this Sentinel ID across restarts. */
    //找到没有设置id的sentinel
    for (j = 0; j < CONFIG_RUN_ID_SIZE; j++)
        if (sentinel.myid[j] != 0) break;

    //随机生成一个id，写入配置文件
    if (j == CONFIG_RUN_ID_SIZE) {
        /* Pick ID and presist the config. */
        getRandomHexChars(sentinel.myid,CONFIG_RUN_ID_SIZE);
        sentinelFlushConfig();
    }

    /* Log its ID to make debugging of issues simpler. */
    serverLog(LL_WARNING,"Sentinel ID is %s", sentinel.myid);

    /* We want to generate a +monitor event for every configured master
     * at startup. */
    //在启动时生成+monitor事件
    sentinelGenerateInitialMonitorEvents();
}
```

##### 00x12 sentinel周期任务

---

sentinel的相关操作都根据时间事件循环执行

在sentinel模式下，serverCron()每100ms调用一次sentinelTimer()来执行状态检测，脚本触发等操作

大致结构如下

> serverCorn<br>
> 	|<br>
> ​	+sentinelTimer (per 100ms)<br>
>  		|<br>
> 		+sentinelCheckTiltCondition<br>
>  		|<br>
> 		+sentinelHandleDictOfRedisInstances<br>
> 		|<br>
> 		+sentinelHandleDictOfRedisInstances (递归) <br>
> 		|		|<br>
> 		|		+sentinelHandleRedisInstances  <br>
> 		|		|<br>
> 		|		+sentinelReconnectInstance<br>
> 		|		|<br>
> 		|		+sentinelSendPeriodicCommands<br>
> 		|			|<br>
> 		|			+sentinelCheckSubjectivelyDown<br>
> 		|			|<br>
> 		|			+sentinelCheckObjectivelyDown<br>
> 		|<br>
> 		+sentinelRunPendingScripts<br>
> 		|<br>
> 		+sentinelCollectTerminatedScripts<br>
> 		|<br>
> 		+sentinelKillTimedoutScripts<br>
>

##### 00x13 Tilt模式

---

sentinel会检测自身状态，在出现问题时进入TILE模式以保护集群

进入TILT模式后sentinel会继续进行监控，但不会做其他任何动作

当系统恢复正常持续30s，sentinel将退出TILE模式，继续进行任务

```c
#define SENTINEL_TILT_TRIGGER 2000
void sentinelCheckTiltCondition(void) {
    //计算离最后一次执行sentinel事件循环相差多久
    mstime_t now = mstime();
    mstime_t delta = now - sentinel.previous_time;
	
    //差为负或大于2s，sentinel会进入TILT模式
    if (delta < 0 || delta > SENTINEL_TILT_TRIGGER) {
        sentinel.tilt = 1;
        //设置/重置TILT模式的开始时间
        sentinel.tilt_start_time = mstime();
        sentinelEvent(LL_WARNING,"+tilt",NULL,"#tilt mode entered");
    }
    //将当前时间点设为最后一次执行事件循环时间
    sentinel.previous_time = mstime();
}
```

在初始化与执行sentinelCheckTiltCondition()时都会更新previous_time

而Check是每次调用sentinelTimer()时都会执行

当与上次执行时间间隔不正常(为负或超过2000ms)时，将标志位sentinel.tilt设为1，并记录开始时间

TILT模式的解除在sentinelHandleRedisInstance()中进行

```c
#define SENTINEL_PING_PERIOD 1000
#define SENTINEL_TILT_PERIOD (SENTINEL_PING_PERIOD*30)
void sentinelHandleRedisInstance(sentinelRedisInstance *ri) {
    //......
    if (sentinel.tilt) {
        //检查sentinel恢复正常的时间是否超过30s
        if (mstime()-sentinel.tilt_start_time < SENTINEL_TILT_PERIOD) return;
        //如果未到安全时间则不继续进行故障检测
        //已超过30s则解除TILT模式
        sentinel.tilt = 0;
        sentinelEvent(LL_WARNING,"-tilt",NULL,"#tilt mode exited");
    }
    //......
}
```

##### 00x14 脚本

---

sentinel在周期中要执行的脚本放在sentinel.scripts_queue中，等待执行

**将脚本加入队列**

在配置中可以看到，脚本分为两种类型

- notification_script，LL_WARNING级事件会触发sentinelEvent()，将脚本加入队列
- client_reconfig_script，主从切换会触发sentinelCallClientReconfScript()，将脚本加入队列

加入脚本队列的底层实现

```c
//被sentinelEvent()与sentinelCallClientReconfScript()调用
#define SENTINEL_SCRIPT_MAX_ARGS 16
void sentinelScheduleScriptExecution(char *path, ...) {
    va_list ap;
    char *argv[SENTINEL_SCRIPT_MAX_ARGS+1];
    int argc = 1;
    sentinelScriptJob *sj;

    va_start(ap, path);
    while(argc < SENTINEL_SCRIPT_MAX_ARGS) {
        argv[argc] = va_arg(ap,char*);
        if (!argv[argc]) break;
        argv[argc] = sdsnew(argv[argc]); /* Copy the string. */
        argc++;
    }
    va_end(ap);
    argv[0] = sdsnew(path);

    sj = zmalloc(sizeof(*sj));
    sj->flags = SENTINEL_SCRIPT_NONE;
    sj->retry_num = 0;
    sj->argv = zmalloc(sizeof(char*)*(argc+1));
    sj->start_time = 0;
    sj->pid = 0;
    memcpy(sj->argv,argv,sizeof(char*)*(argc+1));

    listAddNodeTail(sentinel.scripts_queue,sj);

    /* Remove the oldest non running script if we already hit the limit. */
    if (listLength(sentinel.scripts_queue) > SENTINEL_SCRIPT_MAX_QUEUE) {
        listNode *ln;
        listIter li;

        listRewind(sentinel.scripts_queue,&li);
        while ((ln = listNext(&li)) != NULL) {
            sj = ln->value;

            if (sj->flags & SENTINEL_SCRIPT_RUNNING) continue;
            /* The first node is the oldest as we add on tail. */
            listDelNode(sentinel.scripts_queue,ln);
            sentinelReleaseScriptJob(sj);
            break;
        }
        serverAssert(listLength(sentinel.scripts_queue) <=
                    SENTINEL_SCRIPT_MAX_QUEUE);
    }
}
```

**执行脚本**

每次轮到sentinelTimer()执行时，都会调用sentinelRunPendingScripts()执行脚本队列中等待的脚本

```c
void sentinelRunPendingScripts(void) {
    listNode *ln;
    listIter li;
    mstime_t now = mstime();

    /* Find jobs that are not running and run them, from the top to the
     * tail of the queue, so we run older jobs first. */
    //遍历队列中的脚本
    listRewind(sentinel.scripts_queue,&li);
    while (sentinel.running_scripts < SENTINEL_SCRIPT_MAX_RUNNING &&
           (ln = listNext(&li)) != NULL)
    {
        sentinelScriptJob *sj = ln->value;
        pid_t pid;

        /* Skip if already running. */
        if (sj->flags & SENTINEL_SCRIPT_RUNNING) continue;

        /* Skip if it's a retry, but not enough time has elapsed. */
        if (sj->start_time && sj->start_time > now) continue;

        sj->flags |= SENTINEL_SCRIPT_RUNNING;
        sj->start_time = mstime();
        sj->retry_num++;
        pid = fork();

        if (pid == -1) {
            /* Parent (fork error).
             * We report fork errors as signal 99, in order to unify the
             * reporting with other kind of errors. */
            sentinelEvent(LL_WARNING,"-script-error",NULL,
                          "%s %d %d", sj->argv[0], 99, 0);
            sj->flags &= ~SENTINEL_SCRIPT_RUNNING;
            sj->pid = 0;
        //函数从这里开始分叉为两个环境
        //pid为0 代表处于子进程环境
        } else if (pid == 0) {
            /* Child */
            execve(sj->argv[0],sj->argv,environ);
            /* If we are here an error occurred. */
            _exit(2); /* Don't retry execution. */
        //pid为子进程id，处于父进程环境
        } else {
            //更改状态
            sentinel.running_scripts++;
            sj->pid = pid;
            sentinelEvent(LL_DEBUG,"+script-child",NULL,"%ld",(long)pid);
        }
    }
}
```

**脚本清理**

Redis的做法是，子进程仅负责执行脚本，父进程则要维护脚本的状态

所以在子进程退出(正常或非正常)后，需要父进程对脚本进行清理

```c
void sentinelCollectTerminatedScripts(void) {
    int statloc;
    pid_t pid;

    while ((pid = wait3(&statloc,WNOHANG,NULL)) > 0) {
        int exitcode = WEXITSTATUS(statloc);
        int bysignal = 0;
        listNode *ln;
        sentinelScriptJob *sj;

        if (WIFSIGNALED(statloc)) bysignal = WTERMSIG(statloc);
        sentinelEvent(LL_DEBUG,"-script-child",NULL,"%ld %d %d",
            (long)pid, exitcode, bysignal);

        ln = sentinelGetScriptListNodeByPid(pid);
        if (ln == NULL) {
            serverLog(LL_WARNING,"wait3() returned a pid (%ld) we can't find in our scripts execution queue!", (long)pid);
            continue;
        }
        sj = ln->value;

        /* If the script was terminated by a signal or returns an
         * exit code of "1" (that means: please retry), we reschedule it
         * if the max number of retries is not already reached. */
        if ((bysignal || exitcode == 1) &&
            sj->retry_num != SENTINEL_SCRIPT_MAX_RETRY)
        {
            sj->flags &= ~SENTINEL_SCRIPT_RUNNING;
            sj->pid = 0;
            sj->start_time = mstime() +
                             sentinelScriptRetryDelay(sj->retry_num);
        } else {
            /* Otherwise let's remove the script, but log the event if the
             * execution did not terminated in the best of the ways. */
            if (bysignal || exitcode != 0) {
                sentinelEvent(LL_WARNING,"-script-error",NULL,
                              "%s %d %d", sj->argv[0], bysignal, exitcode);
            }
            listDelNode(sentinel.scripts_queue,ln);
            sentinelReleaseScriptJob(sj);
            sentinel.running_scripts--;
        }
    }
}
```

**脚本超时**

一个脚本最多被允许执行60s，超时则会被强制中断

```c
#define SENTINEL_SCRIPT_MAX_RUNTIME 60000 /* 60 seconds max exec time. */

void sentinelKillTimedoutScripts(void) {
    listNode *ln;
    listIter li;
    mstime_t now = mstime();

    listRewind(sentinel.scripts_queue,&li);
    while ((ln = listNext(&li)) != NULL) {
        sentinelScriptJob *sj = ln->value;

        if (sj->flags & SENTINEL_SCRIPT_RUNNING &&
            (now - sj->start_time) > SENTINEL_SCRIPT_MAX_RUNTIME)
        {
            sentinelEvent(LL_WARNING,"-script-timeout",NULL,"%s %ld",
                sj->argv[0], (long)sj->pid);
            kill(sj->pid,SIGKILL);
        }
    }
}
```

##### 00x15 节点监控

---

**周期任务**

```c
//递归遍历主节点及其从节点以及监控它的哨兵节点
void sentinelHandleDictOfRedisInstances(dict *instances) {
    dictIterator *di;
    dictEntry *de;
    sentinelRedisInstance *switch_to_promoted = NULL;

    /* There are a number of things we need to perform against every master. */
    di = dictGetIterator(instances);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);

        sentinelHandleRedisInstance(ri);
        if (ri->flags & SRI_MASTER) {
            sentinelHandleDictOfRedisInstances(ri->slaves);
            sentinelHandleDictOfRedisInstances(ri->sentinels);
            if (ri->failover_state == SENTINEL_FAILOVER_STATE_UPDATE_CONFIG) {
                switch_to_promoted = ri;
            }
        }
    }
    if (switch_to_promoted)
        sentinelFailoverSwitchToPromotedSlave(switch_to_promoted);
    dictReleaseIterator(di);
}

//对访问到的每个节点的监控流程
void sentinelHandleRedisInstance(sentinelRedisInstance *ri) {
    /* ========== MONITORING HALF ============ */
    /* Every kind of instance */
    sentinelReconnectInstance(ri);
    sentinelSendPeriodicCommands(ri);

    /* ============== ACTING HALF ============= */
    /* We don't proceed with the acting half if we are in TILT mode.
     * TILT happens when we find something odd with the time, like a
     * sudden change in the clock. */
    if (sentinel.tilt) {
        if (mstime()-sentinel.tilt_start_time < SENTINEL_TILT_PERIOD) return;
        sentinel.tilt = 0;
        sentinelEvent(LL_WARNING,"-tilt",NULL,"#tilt mode exited");
    }

    /* Every kind of instance */
    sentinelCheckSubjectivelyDown(ri);

    /* Masters and slaves */
    if (ri->flags & (SRI_MASTER|SRI_SLAVE)) {
        /* Nothing so far. */
    }

    /* Only masters */
    if (ri->flags & SRI_MASTER) {
        sentinelCheckObjectivelyDown(ri);
        if (sentinelStartFailoverIfNeeded(ri))
            sentinelAskMasterStateToOtherSentinels(ri,SENTINEL_ASK_FORCED);
        sentinelFailoverStateMachine(ri);
        sentinelAskMasterStateToOtherSentinels(ri,SENTINEL_NO_FLAGS);
    }
}
```

**建立连接**

在对节点进行周期检测时，首先要做的就是建立连接

与主从关系的连接不同的是

从节点连接时调用的是anet库中的anetTcpNonBlockBestEffortBindConnect()，并且要在周期事件中执行

而sentinel与其他节点连接时，则直接调用hiredis库中的redisAsyncConnectBind()，是异步执行

但相同的是，连接时都模拟为一个特殊客户端以便发送命令

```c
void sentinelReconnectInstance(sentinelRedisInstance *ri) {
    if (ri->link->disconnected == 0) return;
    if (ri->addr->port == 0) return; /* port == 0 means invalid address. */
    instanceLink *link = ri->link;
    mstime_t now = mstime();

    if (now - ri->link->last_reconn_time < SENTINEL_PING_PERIOD) return;
    ri->link->last_reconn_time = now;

    /* Commands connection. */
    if (link->cc == NULL) {
        link->cc = redisAsyncConnectBind(ri->addr->ip,ri->addr->port,NET_FIRST_BIND_ADDR);
        if (link->cc->err) {
            sentinelEvent(LL_DEBUG,"-cmd-link-reconnection",ri,"%@ #%s",
                link->cc->errstr);
            instanceLinkCloseConnection(link,link->cc);
        } else {
            link->pending_commands = 0;
            link->cc_conn_time = mstime();
            link->cc->data = link;
            redisAeAttach(server.el,link->cc);
            redisAsyncSetConnectCallback(link->cc,
                    sentinelLinkEstablishedCallback);
            redisAsyncSetDisconnectCallback(link->cc,
                    sentinelDisconnectCallback);
            sentinelSendAuthIfNeeded(ri,link->cc);
            sentinelSetClientName(ri,link->cc,"cmd");

            /* Send a PING ASAP when reconnecting. */
            sentinelSendPing(ri);
        }
    }
    /* Pub / Sub */
    if ((ri->flags & (SRI_MASTER|SRI_SLAVE)) && link->pc == NULL) {
        link->pc = redisAsyncConnectBind(ri->addr->ip,ri->addr->port,NET_FIRST_BIND_ADDR);
        if (link->pc->err) {
            sentinelEvent(LL_DEBUG,"-pubsub-link-reconnection",ri,"%@ #%s",
                link->pc->errstr);
            instanceLinkCloseConnection(link,link->pc);
        } else {
            int retval;

            link->pc_conn_time = mstime();
            link->pc->data = link;
            redisAeAttach(server.el,link->pc);
            redisAsyncSetConnectCallback(link->pc,
                    sentinelLinkEstablishedCallback);
            redisAsyncSetDisconnectCallback(link->pc,
                    sentinelDisconnectCallback);
            sentinelSendAuthIfNeeded(ri,link->pc);
            sentinelSetClientName(ri,link->pc,"pubsub");
            /* Now we subscribe to the Sentinels "Hello" channel. */
            retval = redisAsyncCommand(link->pc,
                sentinelReceiveHelloMessages, ri, "SUBSCRIBE %s",
                    SENTINEL_HELLO_CHANNEL);
            if (retval != C_OK) {
                /* If we can't subscribe, the Pub/Sub connection is useless
                 * and we can simply disconnect it and try again. */
                instanceLinkCloseConnection(link,link->pc);
                return;
            }
        }
    }
    /* Clear the disconnected status only if we have both the connections
     * (or just the commands connection if this is a sentinel instance). */
    if (link->cc && (ri->flags & SRI_SENTINEL || link->pc))
        link->disconnected = 0;
}
```

**发送检测命令**

建立连接的函数之后紧接着的是sentinelSendPeriodicCommands()

```c
#define SENTINEL_MAX_PENDING_COMMANDS 100
#define SENTINEL_INFO_PERIOD 10000
#define SENTINEL_PING_PERIOD 1000

void sentinelSendPeriodicCommands(sentinelRedisInstance *ri) {
    mstime_t now = mstime();
    mstime_t info_period, ping_period;
    int retval;

    /* Return ASAP if we have already a PING or INFO already pending, or
     * in the case the instance is not properly connected. */
    //与此节点无连接，结束
    if (ri->link->disconnected) return;

    /* For INFO, PING, PUBLISH that are not critical commands to send we
     * also have a limit of SENTINEL_MAX_PENDING_COMMANDS. We don't
     * want to use a lot of memory just because a link is not working
     * properly (note that anyway there is a redundant protection about this,
     * that is, the link will be disconnected and reconnected if a long
     * timeout condition is detected. */
    //已发送但未回复的命令超过100，结束
    if (ri->link->pending_commands >=
        SENTINEL_MAX_PENDING_COMMANDS * ri->link->refcount) return;

    /* If this is a slave of a master in O_DOWN condition we start sending
     * it INFO every second, instead of the usual SENTINEL_INFO_PERIOD
     * period. In this state we want to closely monitor slaves in case they
     * are turned into masters by another Sentinel, or by the sysadmin.
     *
     * Similarly we monitor the INFO output more often if the slave reports
     * to be disconnected from the master, so that we can have a fresh
     * disconnection time figure. */
    //如果是从节点且所属的主节点被认为客观下线，则INFO命令的发送间隔设为1000ms
    //否则间隔被设为10000ms
    if ((ri->flags & SRI_SLAVE) &&
        ((ri->master->flags & (SRI_O_DOWN|SRI_FAILOVER_IN_PROGRESS)) ||
         (ri->master_link_down_time != 0)))
    {
        info_period = 1000;
    } else {
        info_period = SENTINEL_INFO_PERIOD;
    }

    /* We ping instances every time the last received pong is older than
     * the configured 'down-after-milliseconds' time, but every second
     * anyway if 'down-after-milliseconds' is greater than 1 second. */
    //可认为节点主观下线的时长
    ping_period = ri->down_after_period;
    //如果设置中时长大于1000ms，则改为1000ms
    if (ping_period > SENTINEL_PING_PERIOD) ping_period = SENTINEL_PING_PERIOD;

    //对主节点和从节点
    //如果没有收到过
    if ((ri->flags & SRI_SENTINEL) == 0 &&
        (ri->info_refresh == 0 ||
        (now - ri->info_refresh) > info_period))
    {
        /* Send INFO to masters and slaves, not sentinels. */
        //异步发送INFO命令
        //被绑定处理回复的sentinelInfoReplyCallback()调用sentinelRefreshInstanceInfo()
        //会在读取回复后更新ri->info_redresh的时间并减少一个发送未回复命令
        retval = redisAsyncCommand(ri->link->cc,
            sentinelInfoReplyCallback, ri, "INFO");
        //增加已发送未回复命令
        if (retval == C_OK) ri->link->pending_commands++;
    //对其他主节点，从节点与哨兵节点
    //如果PING命令超时
    } else if ((now - ri->link->last_pong_time) > ping_period &&
               (now - ri->link->last_ping_time) > ping_period/2) {
        /* Send PING to all the three kinds of instances. */
        //再次发送PING命令
        sentinelSendPing(ri);
    //发布超时
    } else if ((now - ri->last_pub_time) > SENTINEL_PUBLISH_PERIOD) {
        /* PUBLISH hello messages to all the three kinds of instances. */
        //发布一个hello消息
        sentinelSendHello(ri);
    }
}
```

**S_DOWN 主观下线**

对所有类型的节点，判断其是否可被认为使主观下线

```c
void sentinelCheckSubjectivelyDown(sentinelRedisInstance *ri) {
    mstime_t elapsed = 0;

    if (ri->link->act_ping_time)
        elapsed = mstime() - ri->link->act_ping_time;
    else if (ri->link->disconnected)
        elapsed = mstime() - ri->link->last_avail_time;

    /* Check if we are in need for a reconnection of one of the
     * links, because we are detecting low activity.
     *
     * 1) Check if the command link seems connected, was connected not less
     *    than SENTINEL_MIN_LINK_RECONNECT_PERIOD, but still we have a
     *    pending ping for more than half the timeout. */
    if (ri->link->cc &&
        (mstime() - ri->link->cc_conn_time) >
        SENTINEL_MIN_LINK_RECONNECT_PERIOD &&
        ri->link->act_ping_time != 0 && /* Ther is a pending ping... */
        /* The pending ping is delayed, and we did not received
         * error replies as well. */
        (mstime() - ri->link->act_ping_time) > (ri->down_after_period/2) &&
        (mstime() - ri->link->last_pong_time) > (ri->down_after_period/2))
    {
        instanceLinkCloseConnection(ri->link,ri->link->cc);
    }

    /* 2) Check if the pubsub link seems connected, was connected not less
     *    than SENTINEL_MIN_LINK_RECONNECT_PERIOD, but still we have no
     *    activity in the Pub/Sub channel for more than
     *    SENTINEL_PUBLISH_PERIOD * 3.
     */
    if (ri->link->pc &&
        (mstime() - ri->link->pc_conn_time) >
         SENTINEL_MIN_LINK_RECONNECT_PERIOD &&
        (mstime() - ri->link->pc_last_activity) > (SENTINEL_PUBLISH_PERIOD*3))
    {
        instanceLinkCloseConnection(ri->link,ri->link->pc);
    }

    /* Update the SDOWN flag. We believe the instance is SDOWN if:
     *
     * 1) It is not replying.
     * 2) We believe it is a master, it reports to be a slave for enough time
     *    to meet the down_after_period, plus enough time to get two times
     *    INFO report from the instance. */
    if (elapsed > ri->down_after_period ||
        (ri->flags & SRI_MASTER &&
         ri->role_reported == SRI_SLAVE &&
         mstime() - ri->role_reported_time >
          (ri->down_after_period+SENTINEL_INFO_PERIOD*2)))
    {
        /* Is subjectively down */
        if ((ri->flags & SRI_S_DOWN) == 0) {
            sentinelEvent(LL_WARNING,"+sdown",ri,"%@");
            ri->s_down_since_time = mstime();
            ri->flags |= SRI_S_DOWN;
        }
    } else {
        /* Is subjectively up */
        if (ri->flags & SRI_S_DOWN) {
            sentinelEvent(LL_WARNING,"-sdown",ri,"%@");
            ri->flags &= ~(SRI_S_DOWN|SRI_SCRIPT_KILL_SENT);
        }
    }
}
```

**O_DOWN 客观下线**

客观下线仅针对主节点，并且将主观下线的判断结果作为依据

```c
void sentinelCheckObjectivelyDown(sentinelRedisInstance *master) {
    dictIterator *di;
    dictEntry *de;
    unsigned int quorum = 0, odown = 0;

    if (master->flags & SRI_S_DOWN) {
        /* Is down for enough sentinels? */
        quorum = 1; /* the current sentinel. */
        /* Count all the other sentinels. */
        di = dictGetIterator(master->sentinels);
        while((de = dictNext(di)) != NULL) {
            sentinelRedisInstance *ri = dictGetVal(de);

            if (ri->flags & SRI_MASTER_DOWN) quorum++;
        }
        dictReleaseIterator(di);
        if (quorum >= master->quorum) odown = 1;
    }

    /* Set the flag accordingly to the outcome. */
    if (odown) {
        if ((master->flags & SRI_O_DOWN) == 0) {
            sentinelEvent(LL_WARNING,"+odown",master,"%@ #quorum %d/%d",
                quorum, master->quorum);
            master->flags |= SRI_O_DOWN;
            master->o_down_since_time = mstime();
        }
    } else {
        if (master->flags & SRI_O_DOWN) {
            sentinelEvent(LL_WARNING,"-odown",master,"%@");
            master->flags &= ~SRI_O_DOWN;
        }
    }
}
```

##### 00x16 故障转移

------

**确认故障转移**

仍然是在sentinelHandleRedisInstance()中，在完成S_DOWN标记后

用sentinelStartFailoverIfNeeded()进一步判断是否可以开始进行故障转移工作

需要满足条件：

- 主节点已被标识客观下线
- 没有正在进行的故障转移
- 一段时间内没有进行故障转移

```c
int sentinelStartFailoverIfNeeded(sentinelRedisInstance *master) {
    /* We can't failover if the master is not in O_DOWN state. */
    if (!(master->flags & SRI_O_DOWN)) return 0;

    /* Failover already in progress? */
    if (master->flags & SRI_FAILOVER_IN_PROGRESS) return 0;

    /* Last failover attempt started too little time ago? */
    if (mstime() - master->failover_start_time <
        master->failover_timeout*2)
    {
        if (master->failover_delay_logged != master->failover_start_time) {
            time_t clock = (master->failover_start_time +
                            master->failover_timeout*2) / 1000;
            char ctimebuf[26];

            ctime_r(&clock,ctimebuf);
            ctimebuf[24] = '\0'; /* Remove newline. */
            master->failover_delay_logged = master->failover_start_time;
            serverLog(LL_WARNING,
                "Next failover delay: I will not start a failover before %s",
                ctimebuf);
        }
        return 0;
    }

    sentinelStartFailover(master);
    return 1;
}
```

如果符合条件则调用sentinelStartFailover()函数在sentinel视角上将主节点设置未故障转移状态

```c
void sentinelStartFailover(sentinelRedisInstance *master) {
    serverAssert(master->flags & SRI_MASTER);

    master->failover_state = SENTINEL_FAILOVER_STATE_WAIT_START;
    master->flags |= SRI_FAILOVER_IN_PROGRESS;
    master->failover_epoch = ++sentinel.current_epoch;
    sentinelEvent(LL_WARNING,"+new-epoch",master,"%llu",
        (unsigned long long) sentinel.current_epoch);
    sentinelEvent(LL_WARNING,"+try-failover",master,"%@");
    master->failover_start_time = mstime()+rand()%SENTINEL_MAX_DESYNC;
    master->failover_state_change_time = mstime();
}
```

**确认客观下线&选举leader预处理**

当前sentinel确认故障转移状态后强制向其他sentinel发送 `SENTINEL is-master-down-by-addr <ip> <port> <current_epoch> <myid/*>` 命令最后判断主节点是否失效

最后一个参数，发送自己的id表示请求收到命令的sentinel选举自己为leader

发送"*"则表示发送投票

```c
#define SENTINEL_ASK_FORCED (1<<0)
#define SENTINEL_ASK_PERIOD 1000

void sentinelAskMasterStateToOtherSentinels(sentinelRedisInstance *master, int flags) {
    dictIterator *di;
    dictEntry *de;
	
    //遍历监控此主节点的所有sentinel(包括自己)
    di = dictGetIterator(master->sentinels);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        //距离这个sentinel最后一次回复SENTINEL is-master-down-by-addr命令的时间
        mstime_t elapsed = mstime() - ri->last_master_down_reply_time;
        char port[32];
        int retval;

        /* If the master state from other sentinel is too old, we clear it. */
        //间隔时间过长，清除本sentinel视角下这个sentinel的leader信息
        if (elapsed > SENTINEL_ASK_PERIOD*5) {
            ri->flags &= ~SRI_MASTER_DOWN;
            sdsfree(ri->leader);
            ri->leader = NULL;
        }

        /* Only ask if master is down to other sentinels if:
         *
         * 1) We believe it is down, or there is a failover in progress.
         * 2) Sentinel is connected.
         * 3) We did not received the info within SENTINEL_ASK_PERIOD ms. */
        //1.主节点没有客观下线，跳过这个sentinel
        if ((master->flags & SRI_S_DOWN) == 0) continue;
        //2.这个sentinel与主节点断连了，跳过
        if (ri->link->disconnected) continue;
        //3.SENTINEL_ASK_PERIOD时间内有回复且没有强制更新，跳过
        if (!(flags & SENTINEL_ASK_FORCED) &&
            mstime() - ri->last_master_down_reply_time < SENTINEL_ASK_PERIOD)
            continue;

        /* Ask */
        //以上三条都不满足，则向这个sentinel请求支持/询问leader信息
        ll2string(port,sizeof(port),master->addr->port);
        //如果当前主节点处于故障转移状态，则发送本节点的id，请求对方选自己为leader
        //否则发送"*"表示投票
        retval = redisAsyncCommand(ri->link->cc,
                    sentinelReceiveIsMasterDownReply, ri,
                    "SENTINEL is-master-down-by-addr %s %s %llu %s",
                    master->addr->ip, port,
                    sentinel.current_epoch,
                    (master->failover_state > SENTINEL_FAILOVER_STATE_NONE) ?
                    sentinel.myid : "*");
        //已发送未回复命令+1
        if (retval == C_OK) ri->link->pending_commands++;
    }
    dictReleaseIterator(di);
}
```

收到命令的sentinel响应询问命令

```c
void sentinelCommand(client *c) {
    //......
    } else if (!strcasecmp(c->argv[1]->ptr,"is-master-down-by-addr")) {
        /* SENTINEL IS-MASTER-DOWN-BY-ADDR <ip> <port> <current-epoch> <runid>
         *
         * Arguments:
         *
         * ip and port are the ip and port of the master we want to be
         * checked by Sentinel. Note that the command will not check by
         * name but just by master, in theory different Sentinels may monitor
         * differnet masters with the same name.
         *
         * current-epoch is needed in order to understand if we are allowed
         * to vote for a failover leader or not. Each Sentinel can vote just
         * one time per epoch.
         *
         * runid is "*" if we are not seeking for a vote from the Sentinel
         * in order to elect the failover leader. Otherwise it is set to the
         * runid we want the Sentinel to vote if it did not already voted.
         */
        sentinelRedisInstance *ri;
        long long req_epoch;
        uint64_t leader_epoch = 0;
        char *leader = NULL;
        long port;
        int isdown = 0;

        //命令+参数共为6个
        if (c->argc != 6) goto numargserr;
    	//获取目标主节点的port和当前纪元
        if (getLongFromObjectOrReply(c,c->argv[3],&port,NULL) != C_OK ||
            getLongLongFromObjectOrReply(c,c->argv[4],&req_epoch,NULL)
                                                              != C_OK)
            return;
        //根据ip，port查找主节点
        ri = getSentinelRedisInstanceByAddrAndRunID(sentinel.masters,
            c->argv[2]->ptr,port,NULL);

        /* It exists? Is actually a master? Is subjectively down? It's down.
         * Note: if we are in tilt mode we always reply with "0". */
        //主节点存在并被本节点标记客观下线，本sentinel未处于TILT模式
        //则设置同意主节点下线标志
        if (!sentinel.tilt && ri && (ri->flags & SRI_S_DOWN) &&
                                    (ri->flags & SRI_MASTER))
            isdown = 1;
    
        /* Vote for the master (or fetch the previous vote) if the request
         * includes a runid, otherwise the sender is not seeking for a vote. */
        //命令中包含id，则给发送者投一票(原英文注释可能有问题)
        //否则发送者并不是在请求支持
        //如果检测到在本纪元或更高纪元已投过票，则告知发送者自己支持的是谁(以最高纪元为准)
        if (ri && ri->flags & SRI_MASTER && strcasecmp(c->argv[5]->ptr,"*")) {
            //根据请求决定是否更新支持者，并返回当前支持者
            leader = sentinelVoteLeader(ri,(uint64_t)req_epoch,
                                            c->argv[5]->ptr,
                                            &leader_epoch);
        }

        /* Reply with a three-elements multi-bulk reply:
         * down state, leader, vote epoch. */
        //表示返回三条信息
        addReplyMultiBulkLen(c,3);
        //是否同意主节点下线
        addReply(c, isdown ? shared.cone : shared.czero);
        //支持leader的id，没有则发送"*"
        addReplyBulkCString(c, leader ? leader : "*");
        //支持leader的纪元
        addReplyLongLong(c, (long long)leader_epoch);
        if (leader) sdsfree(leader);
    }
	//......
}

//投票操作实现
//尝试为id为req_runid的sentinel投票
#define SENTINEL_MAX_DESYNC 1000

char *sentinelVoteLeader(sentinelRedisInstance *master, uint64_t req_epoch, char *req_runid, uint64_t *leader_epoch) {
   	//如果请求投票的纪元更高
    //则更新当前纪元的值
    if (req_epoch > sentinel.current_epoch) {
        sentinel.current_epoch = req_epoch;
        sentinelFlushConfig();
        sentinelEvent(LL_WARNING,"+new-epoch",master,"%llu",
            (unsigned long long) sentinel.current_epoch);
    }
	
    //如果当前主节点leader的纪元小于请求投票的sentinel的纪元
    if (master->leader_epoch < req_epoch && sentinel.current_epoch <= req_epoch)
    {
        //清除目前主节点的leader记录
        sdsfree(master->leader);
        //将本sentinel视角下主节点的leader设置为请求投票的sentinel
        //即为这个sentinel投票
        master->leader = sdsnew(req_runid);
        //更新leader的纪元记录
        master->leader_epoch = sentinel.current_epoch;
        sentinelFlushConfig();
        //发送为leader投票的通知
        sentinelEvent(LL_WARNING,"+vote-for-leader",master,"%s %llu",
            master->leader, (unsigned long long) master->leader_epoch);
        /* If we did not voted for ourselves, set the master failover start
         * time to now, in order to force a delay before we can start a
         * failover for the same master. */
        //如果不是投票给自己，随机延后故障转移开始时间
        if (strcasecmp(master->leader,sentinel.myid))
            master->failover_start_time = mstime()+rand()%SENTINEL_MAX_DESYNC;
    }
    //如果没有变化，则保持原来的投票
	
    //保存leader纪元
    *leader_epoch = master->leader_epoch;
    return master->leader ? sdsnew(master->leader) : NULL;
}
```

发送命令的一方设置了sentinelReceiveIsMasterDownReply()来处理回复

```c
void sentinelReceiveIsMasterDownReply(redisAsyncContext *c, void *reply, void *privdata) {
    sentinelRedisInstance *ri = privdata;
    instanceLink *link = c->data;
    redisReply *r;

    if (!reply || !link) return;
    //接收回复，已发送未回复命令-1
    link->pending_commands--;
    r = reply;

    /* Ignore every error or unexpected reply.
     * Note that if the command returns an error for any reason we'll
     * end clearing the SRI_MASTER_DOWN flag for timeout anyway. */
    if (r->type == REDIS_REPLY_ARRAY && r->elements == 3 &&
        r->element[0]->type == REDIS_REPLY_INTEGER &&
        r->element[1]->type == REDIS_REPLY_STRING &&
        r->element[2]->type == REDIS_REPLY_INTEGER)
    {
        //更新最近一次回复下线状态的时间
        ri->last_master_down_reply_time = mstime();
        //判断对方是否同意主节点下线
        if (r->element[0]->integer == 1) {
            ri->flags |= SRI_MASTER_DOWN;
        } else {
            ri->flags &= ~SRI_MASTER_DOWN;
        }
        //如果第二条回复不是"*"，则这条回复带有其支持信息
        if (strcmp(r->element[1]->str,"*")) {
            /* If the runid in the reply is not "*" the Sentinel actually
             * replied with a vote. */
            //更新本sentinel视角下对方sentinel支持的leader
            sdsfree(ri->leader);
            if ((long long)ri->leader_epoch != r->element[2]->integer)
                serverLog(LL_WARNING,
                    "%s voted for %s %llu", ri->name,
                    r->element[1]->str,
                    (unsigned long long) r->element[2]->integer);
            ri->leader = sdsnew(r->element[1]->str);
            ri->leader_epoch = r->element[2]->integer;
        }
    }
}
```

经过以上交互，一个sentinel向其他sentinel确认了一个主节点的客观下线，并且获取了其他sentinel最终支持哪个leader

**故障转移流程**

确认主节点客观下线后，开始分步执行故障转移

```c
void sentinelFailoverStateMachine(sentinelRedisInstance *ri) {
    serverAssert(ri->flags & SRI_MASTER);

    if (!(ri->flags & SRI_FAILOVER_IN_PROGRESS)) return;

    switch(ri->failover_state) {
        case SENTINEL_FAILOVER_STATE_WAIT_START:
            sentinelFailoverWaitStart(ri);
            break;
        case SENTINEL_FAILOVER_STATE_SELECT_SLAVE:
            sentinelFailoverSelectSlave(ri);
            break;
        case SENTINEL_FAILOVER_STATE_SEND_SLAVEOF_NOONE:
            sentinelFailoverSendSlaveOfNoOne(ri);
            break;
        case SENTINEL_FAILOVER_STATE_WAIT_PROMOTION:
            sentinelFailoverWaitPromotion(ri);
            break;
        case SENTINEL_FAILOVER_STATE_RECONF_SLAVES:
            sentinelFailoverReconfNextSlave(ri);
            break;
    }
}
```

每一个周期只进行故障转移的一步，共五步，其间failover_state状态连续

**准备故障转移**

之前最后一次确认主节点客观下线的同时，发现O_DOWN的节点进行了向其他节点发送了选举请求

，并获得了其他sentinel最终支持的leader

```c
#define SENTINEL_ELECTION_TIMEOUT 10000

void sentinelFailoverWaitStart(sentinelRedisInstance *ri) {
    char *leader;
    int isleader;

    /* Check if we are the leader for the failover epoch. */
    //获取故障转移选定纪元的leader
    leader = sentinelGetLeader(ri, ri->failover_epoch);
    //检查自己是否是leader
    isleader = leader && strcasecmp(leader,sentinel.myid) == 0;
    sdsfree(leader);

    /* If I'm not the leader, and it is not a forced failover via
     * SENTINEL FAILOVER, then I can't continue with the failover. */
    //如果当前sentient节点不是leader，又不要求强制故障转移，则结束
    //强制转移在failover作为sentinel命令执行时被设置
    if (!isleader && !(ri->flags & SRI_FORCE_FAILOVER)) {
        int election_timeout = SENTINEL_ELECTION_TIMEOUT;
	   
        /* The election timeout is the MIN between SENTINEL_ELECTION_TIMEOUT
         * and the configured failover timeout. */
        //当选后超时时间为SENTINEL_ELECTION_TIMEOUT与配置中failover_timeout中的最小值
        if (election_timeout > ri->failover_timeout)
            election_timeout = ri->failover_timeout;
        /* Abort the failover if I'm not the leader after some time. */
        //当前leader超时
        if (mstime() - ri->failover_start_time > election_timeout) {
            //发送取消故障转移的通知
            sentinelEvent(LL_WARNING,"-failover-abort-not-elected",ri,"%@");
            //取消对ri的故障转移(更改状态)
            sentinelAbortFailover(ri);
        }
        return;
    }
    //当前sentinel恰好为leader
    //发送本sentinel获胜，可进行转移的通知
    sentinelEvent(LL_WARNING,"+elected-leader",ri,"%@");
    //是否模拟故障
    if (sentinel.simfailure_flags & SENTINEL_SIMFAILURE_CRASH_AFTER_ELECTION)
        sentinelSimFailureCrash();
    //更新状态为 SENTINEL_FAILOVER_STATE_SELECT_SLAVE 等待选择晋升的节点
    ri->failover_state = SENTINEL_FAILOVER_STATE_SELECT_SLAVE;
    //更新状态改变时间
    ri->failover_state_change_time = mstime();
    sentinelEvent(LL_WARNING,"+failover-state-select-slave",ri,"%@");
}

//获取当前leader
//此函数不以调用它的sentinel主体，而是以O_DOWN的主节点为主体
char *sentinelGetLeader(sentinelRedisInstance *master, uint64_t epoch) {
    dict *counters;
    dictIterator *di;
    dictEntry *de;
    unsigned int voters = 0, voters_quorum;
    char *myvote;
    char *winner = NULL;
    uint64_t leader_epoch;
    uint64_t max_votes = 0;
	
    serverAssert(master->flags & (SRI_O_DOWN|SRI_FAILOVER_IN_PROGRESS));
    //投票统计字典
    counters = dictCreate(&leaderVotesDictType,NULL);
	//设置字典大小
    voters = dictSize(master->sentinels)+1; /* All the other sentinels and me.*/

    /* Count other sentinels votes */
    //遍历监控此主节点的所有sentinel
    di = dictGetIterator(master->sentinels);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *ri = dictGetVal(de);
        //如果这个sentinel选定了一个当前纪元的leader，则为它选定的leader投一票
        if (ri->leader != NULL && ri->leader_epoch == sentinel.current_epoch)
            sentinelLeaderIncr(counters,ri->leader);
    }
    dictReleaseIterator(di);

    /* Check what's the winner. For the winner to win, it needs two conditions:
     * 1) Absolute majority between voters (50% + 1).
     * 2) And anyway at least master->quorum votes. */
    //遍历统计字典，得出选举获胜的sentinel
    //1.票数过半(50%+1)
    //2.票数高与设置的master->quorum
    di = dictGetIterator(counters);
    while((de = dictNext(di)) != NULL) {
        uint64_t votes = dictGetUnsignedIntegerVal(de);

        if (votes > max_votes) {
            max_votes = votes;
            winner = dictGetKey(de);
        }
    }
    dictReleaseIterator(di);

    /* Count this Sentinel vote:
     * if this Sentinel did not voted yet, either vote for the most
     * common voted sentinel, or for itself if no vote exists at all. */
    //如果当前sentinel没投票，则由本sentinel模拟为其选择支持的leader
    //如果在之前有胜者，则投给胜者
    //无则投给本sentinel
    if (winner)
        myvote = sentinelVoteLeader(master,epoch,winner,&leader_epoch);
    else
        myvote = sentinelVoteLeader(master,epoch,sentinel.myid,&leader_epoch);

    if (myvote && leader_epoch == epoch) {
        //给刚刚模拟支持的leader增加一票
        uint64_t votes = sentinelLeaderIncr(counters,myvote);

        if (votes > max_votes) {
            max_votes = votes;
            winner = myvote;
        }
    }
	//计算需要的最小票数
    voters_quorum = voters/2+1;
    //胜者的票数小于最小票数或小于配置的限制
    //选举无效，无胜者
    if (winner && (max_votes < voters_quorum || max_votes < master->quorum))
        winner = NULL;
	
    //返回胜者
    winner = winner ? sdsnew(winner) : NULL;
    sdsfree(myvote);
    dictRelease(counters);
    return winner;
}
```

**选择晋升的从节点**

进入下一个周期，继续执行故障转移

状态为SENTINEL_FAILOVER_STATE_SELECT_SLAVE

需要选择一个从节点为其晋升

```c
void sentinelFailoverSelectSlave(sentinelRedisInstance *ri) {
    sentinelRedisInstance *slave = sentinelSelectSlave(ri);

    /* We don't handle the timeout in this state as the function aborts
     * the failover or go forward in the next state. */
    if (slave == NULL) {
        sentinelEvent(LL_WARNING,"-failover-abort-no-good-slave",ri,"%@");
        sentinelAbortFailover(ri);
    } else {
        sentinelEvent(LL_WARNING,"+selected-slave",slave,"%@");
        slave->flags |= SRI_PROMOTED;
        ri->promoted_slave = slave;
        ri->failover_state = SENTINEL_FAILOVER_STATE_SEND_SLAVEOF_NOONE;
        ri->failover_state_change_time = mstime();
        sentinelEvent(LL_NOTICE,"+failover-state-send-slaveof-noone",
            slave, "%@");
    }
}

sentinelRedisInstance *sentinelSelectSlave(sentinelRedisInstance *master) {
    sentinelRedisInstance **instance =
        zmalloc(sizeof(instance[0])*dictSize(master->slaves));
    sentinelRedisInstance *selected = NULL;
    int instances = 0;
    dictIterator *di;
    dictEntry *de;
    mstime_t max_master_down_time = 0;

    if (master->flags & SRI_S_DOWN)
        max_master_down_time += mstime() - master->s_down_since_time;
    max_master_down_time += master->down_after_period * 10;

    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);
        mstime_t info_validity_time;

        if (slave->flags & (SRI_S_DOWN|SRI_O_DOWN)) continue;
        if (slave->link->disconnected) continue;
        if (mstime() - slave->link->last_avail_time > SENTINEL_PING_PERIOD*5) continue;
        if (slave->slave_priority == 0) continue;

        /* If the master is in SDOWN state we get INFO for slaves every second.
         * Otherwise we get it with the usual period so we need to account for
         * a larger delay. */
        if (master->flags & SRI_S_DOWN)
            info_validity_time = SENTINEL_PING_PERIOD*5;
        else
            info_validity_time = SENTINEL_INFO_PERIOD*3;
        if (mstime() - slave->info_refresh > info_validity_time) continue;
        if (slave->master_link_down_time > max_master_down_time) continue;
        instance[instances++] = slave;
    }
    dictReleaseIterator(di);
    if (instances) {
        qsort(instance,instances,sizeof(sentinelRedisInstance*),
            compareSlavesForPromotion);
        selected = instance[0];
    }
    zfree(instance);
    return selected;
}
```

**执行晋升**

下面让这个从节点变为主节点

```c
void sentinelFailoverSendSlaveOfNoOne(sentinelRedisInstance *ri) {
    int retval;

    /* We can't send the command to the promoted slave if it is now
     * disconnected. Retry again and again with this state until the timeout
     * is reached, then abort the failover. */
    if (ri->promoted_slave->link->disconnected) {
        if (mstime() - ri->failover_state_change_time > ri->failover_timeout) {
            sentinelEvent(LL_WARNING,"-failover-abort-slave-timeout",ri,"%@");
            sentinelAbortFailover(ri);
        }
        return;
    }

    /* Send SLAVEOF NO ONE command to turn the slave into a master.
     * We actually register a generic callback for this command as we don't
     * really care about the reply. We check if it worked indirectly observing
     * if INFO returns a different role (master instead of slave). */
    retval = sentinelSendSlaveOf(ri->promoted_slave,NULL,0);
    if (retval != C_OK) return;
    sentinelEvent(LL_NOTICE, "+failover-state-wait-promotion",
        ri->promoted_slave,"%@");
    ri->failover_state = SENTINEL_FAILOVER_STATE_WAIT_PROMOTION;
    ri->failover_state_change_time = mstime();
}
```

处理晋升超时

```c
void sentinelFailoverWaitPromotion(sentinelRedisInstance *ri) {
    /* Just handle the timeout. Switching to the next state is handled
     * by the function parsing the INFO command of the promoted slave. */
    if (mstime() - ri->failover_state_change_time > ri->failover_timeout) {
        sentinelEvent(LL_WARNING,"-failover-abort-slave-timeout",ri,"%@");
        sentinelAbortFailover(ri);
    }
}
```

**同步新主节点**

向属于原主节点的从节点发送 `SLAVE OF` 命令，指向新的主节点，并开始同步

```c
void sentinelFailoverReconfNextSlave(sentinelRedisInstance *master) {
    dictIterator *di;
    dictEntry *de;
    int in_progress = 0;

    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);

        if (slave->flags & (SRI_RECONF_SENT|SRI_RECONF_INPROG))
            in_progress++;
    }
    dictReleaseIterator(di);

    di = dictGetIterator(master->slaves);
    while(in_progress < master->parallel_syncs &&
          (de = dictNext(di)) != NULL)
    {
        sentinelRedisInstance *slave = dictGetVal(de);
        int retval;

        /* Skip the promoted slave, and already configured slaves. */
        if (slave->flags & (SRI_PROMOTED|SRI_RECONF_DONE)) continue;

        /* If too much time elapsed without the slave moving forward to
         * the next state, consider it reconfigured even if it is not.
         * Sentinels will detect the slave as misconfigured and fix its
         * configuration later. */
        if ((slave->flags & SRI_RECONF_SENT) &&
            (mstime() - slave->slave_reconf_sent_time) >
            SENTINEL_SLAVE_RECONF_TIMEOUT)
        {
            sentinelEvent(LL_NOTICE,"-slave-reconf-sent-timeout",slave,"%@");
            slave->flags &= ~SRI_RECONF_SENT;
            slave->flags |= SRI_RECONF_DONE;
        }

        /* Nothing to do for instances that are disconnected or already
         * in RECONF_SENT state. */
        if (slave->flags & (SRI_RECONF_SENT|SRI_RECONF_INPROG)) continue;
        if (slave->link->disconnected) continue;

        /* Send SLAVEOF <new master>. */
        retval = sentinelSendSlaveOf(slave,
                master->promoted_slave->addr->ip,
                master->promoted_slave->addr->port);
        if (retval == C_OK) {
            slave->flags |= SRI_RECONF_SENT;
            slave->slave_reconf_sent_time = mstime();
            sentinelEvent(LL_NOTICE,"+slave-reconf-sent",slave,"%@");
            in_progress++;
        }
    }
    dictReleaseIterator(di);

    /* Check if all the slaves are reconfigured and handle timeout. */
    sentinelFailoverDetectEnd(master);
}
```

**转移收尾**

主要是确定所有从节点目标都被修正

```c
void sentinelFailoverDetectEnd(sentinelRedisInstance *master) {
    int not_reconfigured = 0, timeout = 0;
    dictIterator *di;
    dictEntry *de;
    mstime_t elapsed = mstime() - master->failover_state_change_time;

    /* We can't consider failover finished if the promoted slave is
     * not reachable. */
    if (master->promoted_slave == NULL ||
        master->promoted_slave->flags & SRI_S_DOWN) return;

    /* The failover terminates once all the reachable slaves are properly
     * configured. */
    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);

        if (slave->flags & (SRI_PROMOTED|SRI_RECONF_DONE)) continue;
        if (slave->flags & SRI_S_DOWN) continue;
        not_reconfigured++;
    }
    dictReleaseIterator(di);

    /* Force end of failover on timeout. */
    if (elapsed > master->failover_timeout) {
        not_reconfigured = 0;
        timeout = 1;
        sentinelEvent(LL_WARNING,"+failover-end-for-timeout",master,"%@");
    }

    if (not_reconfigured == 0) {
        sentinelEvent(LL_WARNING,"+failover-end",master,"%@");
        master->failover_state = SENTINEL_FAILOVER_STATE_UPDATE_CONFIG;
        master->failover_state_change_time = mstime();
        
    }

    /* If I'm the leader it is a good idea to send a best effort SLAVEOF
     * command to all the slaves still not reconfigured to replicate with
     * the new master. */
    if (timeout) {
        dictIterator *di;
        dictEntry *de;

        di = dictGetIterator(master->slaves);
        while((de = dictNext(di)) != NULL) {
            sentinelRedisInstance *slave = dictGetVal(de);
            int retval;

            if (slave->flags & (SRI_RECONF_DONE|SRI_RECONF_SENT)) continue;
            if (slave->link->disconnected) continue;

            retval = sentinelSendSlaveOf(slave,
                    master->promoted_slave->addr->ip,
                    master->promoted_slave->addr->port);
            if (retval == C_OK) {
                sentinelEvent(LL_NOTICE,"+slave-reconf-sent-be",slave,"%@");
                slave->flags |= SRI_RECONF_SENT;
            }
        }
        dictReleaseIterator(di);
    }
}
```

**更新主节点在线状态**

回到sentinelHandleRedisInstance()，紧接着再次执行sentinelAskMasterStateToOtherSentinels()

不管需不需要故障转移都会执行，flags为SENTINEL_NO_FLAGS

作用是向各sentinel发送 `SENTINEL is-master-down-by-addr` 更新主节点在线状态，不强制更新leader支持情况

**主从切换后sentinel视角下的状态更新**

再上一层，回到sentinelHandleDictOfRedisInstances()

因为进行了主从切换，进入switch_to_promoted分支

需要更新sentinel主节点的记录

更新sentinel视角下主节点的从节点记录

```c
void sentinelHandleDictOfRedisInstances(dict *instances) {
    //......
    if (switch_to_promoted)
        sentinelFailoverSwitchToPromotedSlave(switch_to_promoted);
    dictReleaseIterator(di);
}

void sentinelFailoverSwitchToPromotedSlave(sentinelRedisInstance *master) {
    sentinelRedisInstance *ref = master->promoted_slave ?
                                 master->promoted_slave : master;

    sentinelEvent(LL_WARNING,"+switch-master",master,"%s %s %d %s %d",
        master->name, master->addr->ip, master->addr->port,
        ref->addr->ip, ref->addr->port);

    sentinelResetMasterAndChangeAddress(master,ref->addr->ip,ref->addr->port);
}

int sentinelResetMasterAndChangeAddress(sentinelRedisInstance *master, char *ip, int port) {
    sentinelAddr *oldaddr, *newaddr;
    sentinelAddr **slaves = NULL;
    int numslaves = 0, j;
    dictIterator *di;
    dictEntry *de;

    newaddr = createSentinelAddr(ip,port);
    if (newaddr == NULL) return C_ERR;

    /* Make a list of slaves to add back after the reset.
     * Don't include the one having the address we are switching to. */
    di = dictGetIterator(master->slaves);
    while((de = dictNext(di)) != NULL) {
        sentinelRedisInstance *slave = dictGetVal(de);

        if (sentinelAddrIsEqual(slave->addr,newaddr)) continue;
        slaves = zrealloc(slaves,sizeof(sentinelAddr*)*(numslaves+1));
        slaves[numslaves++] = createSentinelAddr(slave->addr->ip,
                                                 slave->addr->port);
    }
    dictReleaseIterator(di);

    /* If we are switching to a different address, include the old address
     * as a slave as well, so that we'll be able to sense / reconfigure
     * the old master. */
    if (!sentinelAddrIsEqual(newaddr,master->addr)) {
        slaves = zrealloc(slaves,sizeof(sentinelAddr*)*(numslaves+1));
        slaves[numslaves++] = createSentinelAddr(master->addr->ip,
                                                 master->addr->port);
    }

    /* Reset and switch address. */
    sentinelResetMaster(master,SENTINEL_RESET_NO_SENTINELS);
    oldaddr = master->addr;
    master->addr = newaddr;
    master->o_down_since_time = 0;
    master->s_down_since_time = 0;

    /* Add slaves back. */
    for (j = 0; j < numslaves; j++) {
        sentinelRedisInstance *slave;

        slave = createSentinelRedisInstance(NULL,SRI_SLAVE,slaves[j]->ip,
                    slaves[j]->port, master->quorum, master);
        releaseSentinelAddr(slaves[j]);
        if (slave) sentinelEvent(LL_NOTICE,"+slave",slave,"%@");
    }
    zfree(slaves);

    /* Release the old address at the end so we are safe even if the function
     * gets the master->addr->ip and master->addr->port as arguments. */
    releaseSentinelAddr(oldaddr);
    sentinelFlushConfig();
    return C_OK;
}
```
