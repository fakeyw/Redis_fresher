# Cluster

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
    clusterNode *myself;  /* This node */
    uint64_t currentEpoch;
    int state;            /* CLUSTER_OK, CLUSTER_FAIL, ... */
    int size;             /* Num of master nodes with at least one slot */
    dict *nodes;          /* Hash table of name -> clusterNode structures */
    dict *nodes_black_list; /* Nodes we don't re-add for a few seconds. */
    clusterNode *migrating_slots_to[CLUSTER_SLOTS];
    clusterNode *importing_slots_from[CLUSTER_SLOTS];
    clusterNode *slots[CLUSTER_SLOTS];
    uint64_t slots_keys_count[CLUSTER_SLOTS];
    rax *slots_to_keys;
    /* The following fields are used to take the slave state on elections. */
    mstime_t failover_auth_time; /* Time of previous or next election. */
    int failover_auth_count;    /* Number of votes received so far. */
    int failover_auth_sent;     /* True if we already asked for votes. */
    int failover_auth_rank;     /* This slave rank for current auth request. */
    uint64_t failover_auth_epoch; /* Epoch of the current election. */
    int cant_failover_reason;   /* Why a slave is currently not able to
                                   failover. See the CANT_FAILOVER_* macros. */
    /* Manual failover state in common. */
    mstime_t mf_end;            /* Manual failover time limit (ms unixtime).
                                   It is zero if there is no MF in progress. */
    /* Manual failover state of master. */
    clusterNode *mf_slave;      /* Slave performing the manual failover. */
    /* Manual failover state of slave. */
    long long mf_master_offset; /* Master offset the slave needs to start MF
                                   or zero if stil not received. */
    int mf_can_start;           /* If non-zero signal that the manual failover
                                   can start requesting masters vote. */
    /* The followign fields are used by masters to take state on elections. */
    uint64_t lastVoteEpoch;     /* Epoch of the last vote granted. */
    int todo_before_sleep; /* Things to do in clusterBeforeSleep(). */
    /* Messages received and sent by type. */
    long long stats_bus_messages_sent[CLUSTERMSG_TYPE_COUNT];
    long long stats_bus_messages_received[CLUSTERMSG_TYPE_COUNT];
    long long stats_pfail_nodes;    /* Number of nodes in PFAIL status,
                                       excluding nodes without address. */
} clusterState;
```

初始化函数

```c
//cluster.c
void clusterInit(void) {
    int saveconf = 0;

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
    if (clusterLockConfig(server.cluster_configfile) == C_ERR)
        exit(1);

    /* Load or create a new nodes configuration. */
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

        for (j = 0; j < server.cfd_count; j++) {
            if (aeCreateFileEvent(server.el, server.cfd[j], AE_READABLE,
                clusterAcceptHandler, NULL) == AE_ERR)
                    serverPanic("Unrecoverable error creating Redis Cluster "
                                "file event.");
        }
    }

    /* The slots -> keys map is a radix tree. Initialize it here. */
    server.cluster->slots_to_keys = raxNew();
    memset(server.cluster->slots_keys_count,0,
           sizeof(server.cluster->slots_keys_count));

    /* Set myself->port / cport to my listening ports, we'll just need to
     * discover the IP address via MEET messages. */
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
    if (nodeIsSlave(myself)) return C_OK;

    /* Make sure we only have keys in DB0. */
    for (j = 1; j < server.dbnum; j++) {
        if (dictSize(server.db[j].dict)) return C_ERR;
    }

    /* Check that all the slots we see populated memory have a corresponding
     * entry in the cluster table. Otherwise fix the table. */
    for (j = 0; j < CLUSTER_SLOTS; j++) {
        if (!countKeysInSlot(j)) continue; /* No keys in this slot. */
        /* Check if we are assigned to this slot or if we are importing it.
         * In both cases check the next slot as the configuration makes
         * sense. */
        if (server.cluster->slots[j] == myself ||
            server.cluster->importing_slots_from[j] != NULL) continue;

        /* If we are here data and cluster config don't agree, and we have
         * slot 'j' populated even if we are not importing it, nor we are
         * assigned to this slot. Fix this condition. */

        update_config++;
        /* Case A: slot is unassigned. Take responsibility for it. */
        if (server.cluster->slots[j] == NULL) {
            serverLog(LL_WARNING, "I have keys for unassigned slot %d. "
                                    "Taking responsibility for it.",j);
            clusterAddSlot(myself,j);
        } else {
            serverLog(LL_WARNING, "I have keys for slot %d, but the slot is "
                                    "assigned to another node. "
                                    "Setting it to importing state.",j);
            server.cluster->importing_slots_from[j] = server.cluster->slots[j];
        }
    }
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
    if (port <= 0 || port > 65535 || cport <= 0 || cport > 65535) {
        errno = EINVAL;
        return 0;
    }

    /* Set norm_ip as the normalized string representation of the node
     * IP address. */
    memset(norm_ip,0,NET_IP_STR_LEN);
    if (sa.ss_family == AF_INET)
        inet_ntop(AF_INET,
            (void*)&(((struct sockaddr_in *)&sa)->sin_addr),
            norm_ip,NET_IP_STR_LEN);
    else
        inet_ntop(AF_INET6,
            (void*)&(((struct sockaddr_in6 *)&sa)->sin6_addr),
            norm_ip,NET_IP_STR_LEN);

    if (clusterHandshakeInProgress(norm_ip,port,cport)) {
        errno = EAGAIN;
        return 0;
    }

    /* Add the node with a random address (NULL as first argument to
     * createClusterNode()). Everything will be fixed during the
     * handshake. */
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
    handshake_timeout = server.cluster_node_timeout;
    if (handshake_timeout < 1000) handshake_timeout = 1000;

    /* Check if we have disconnected nodes and re-establish the connection.
     * Also update a few stats while we are here, that can be used to make
     * better decisions in other part of the code. */
    di = dictGetSafeIterator(server.cluster->nodes);
    server.cluster->stats_pfail_nodes = 0;
    while((de = dictNext(di)) != NULL) {
        clusterNode *node = dictGetVal(de);

        /* Not interested in reconnecting the link with myself or nodes
         * for which we have no address. */
        if (node->flags & (CLUSTER_NODE_MYSELF|CLUSTER_NODE_NOADDR)) continue;

        if (node->flags & CLUSTER_NODE_PFAIL)
            server.cluster->stats_pfail_nodes++;

        /* A Node in HANDSHAKE state has a limited lifespan equal to the
         * configured node timeout. */
        if (nodeInHandshake(node) && now - node->ctime > handshake_timeout) {
            clusterDelNode(node);
            continue;
        }

        if (node->link == NULL) {
            int fd;
            mstime_t old_ping_sent;
            clusterLink *link;

            fd = anetTcpNonBlockBindConnect(server.neterr, node->ip,
                node->cport, NET_FIRST_BIND_ADDR);
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
            link = createClusterLink(node);
            link->fd = fd;
            node->link = link;
            aeCreateFileEvent(server.el,link->fd,AE_READABLE,
                    clusterReadHandler,link);
            /* Queue a PING in the new connection ASAP: this is crucial
             * to avoid false positives in failure detection.
             *
             * If the node is flagged as MEET, we send a MEET message instead
             * of a PING one, to force the receiver to add us in its node
             * table. */
            old_ping_sent = node->ping_sent;
            clusterSendPing(link, node->flags & CLUSTER_NODE_MEET ?
                    CLUSTERMSG_TYPE_MEET : CLUSTERMSG_TYPE_PING);
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

    while(1) { /* Read as long as there is data to read. */
        rcvbuflen = sdslen(link->rcvbuf);
        if (rcvbuflen < 8) {
            /* First, obtain the first 8 bytes to get the full message
             * length. */
            readlen = 8 - rcvbuflen;
        } else {
            /* Finally read the full message. */
            hdr = (clusterMsg*) link->rcvbuf;
            if (rcvbuflen == 8) {
                /* Perform some sanity check on the message signature
                 * and length. */
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
            readlen = ntohl(hdr->totlen) - rcvbuflen;
            if (readlen > sizeof(buf)) readlen = sizeof(buf);
        }

        nread = read(fd,buf,readlen);
        if (nread == -1 && errno == EAGAIN) return; /* No more data ready. */

        if (nread <= 0) {
            /* I/O error... */
            serverLog(LL_DEBUG,"I/O error reading from node link: %s",
                (nread == 0) ? "connection closed" : strerror(errno));
            handleLinkIOError(link);
            return;
        } else {
            /* Read data and recast the pointer to the new buffer. */
            link->rcvbuf = sdscatlen(link->rcvbuf,buf,nread);
            hdr = (clusterMsg*) link->rcvbuf;
            rcvbuflen += nread;
        }

        /* Total length obtained? Process this packet. */
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

2. A与B建立连接时会触发B的clusterAcceptHandler()函数，类似socket的accept()，同样对可读socket(fd 文件描述符)设置clusterReadHandler()

   收到一条消息后，clusterReadHandler()将socket的数据读到clusterLink的rcvbuf(接收缓冲区)并判断消息是否读取完整

   完成接收，调用通用函数clusterProcessPacket()处理各种类型的消息

   此时为处理MEET并调用clusterSendPing()发送PONG消息

```c
int clusterProcessPacket(clusterLink *link) {
    //......
    /* Check if the sender is a known node. */
    sender = clusterLookupNode(hdr->sender);
    if (sender && !nodeInHandshake(sender)) {
        /* Update our curretEpoch if we see a newer epoch in the cluster. */
        senderCurrentEpoch = ntohu64(hdr->currentEpoch);
        senderConfigEpoch = ntohu64(hdr->configEpoch);
        if (senderCurrentEpoch > server.cluster->currentEpoch)
            server.cluster->currentEpoch = senderCurrentEpoch;
        /* Update the sender configEpoch if it is publishing a newer one. */
        if (senderConfigEpoch > sender->configEpoch) {
            sender->configEpoch = senderConfigEpoch;
            clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                 CLUSTER_TODO_FSYNC_CONFIG);
        }
        /* Update the replication offset info for this node. */
        sender->repl_offset = ntohu64(hdr->offset);
        sender->repl_offset_time = mstime();
        /* If we are a slave performing a manual failover and our master
         * sent its offset while already paused, populate the MF state. */
        if (server.cluster->mf_end &&
            nodeIsSlave(myself) &&
            myself->slaveof == sender &&
            hdr->mflags[0] & CLUSTERMSG_FLAG0_PAUSED &&
            server.cluster->mf_master_offset == 0)
        {
            server.cluster->mf_master_offset = sender->repl_offset;
            serverLog(LL_WARNING,
                "Received replication offset for paused "
                "master manual failover: %lld",
                server.cluster->mf_master_offset);
        }
    }
    
    /* Initial processing of PING and MEET requests replying with a PONG. */
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
        if ((type == CLUSTERMSG_TYPE_MEET || myself->ip[0] == '\0') &&
            server.cluster_announce_ip == NULL)
        {
            char ip[NET_IP_STR_LEN];

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
        if (!sender && type == CLUSTERMSG_TYPE_MEET) {
            clusterNode *node;

            node = createClusterNode(NULL,CLUSTER_NODE_HANDSHAKE);
            nodeIp2String(node->ip,link,hdr->myip);
            node->port = ntohs(hdr->port);
            node->cport = ntohs(hdr->cport);
            clusterAddNode(node);
            clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG);
        }

        /* If this is a MEET packet from an unknown node, we still process
         * the gossip section here since we have to trust the sender because
         * of the message type. */
        if (!sender && type == CLUSTERMSG_TYPE_MEET)
            clusterProcessGossipSection(hdr,link);

        /* Anyway reply with a PONG */
        clusterSendPing(link,CLUSTERMSG_TYPE_PONG);
    }
```

3. 之后A同样通过clusterProcessPacket()处理PONG消息

```c
//接上一块代码
	/* PING, PONG, MEET: process config information. */
    if (type == CLUSTERMSG_TYPE_PING || type == CLUSTERMSG_TYPE_PONG ||
        type == CLUSTERMSG_TYPE_MEET)
    {
        serverLog(LL_DEBUG,"%s packet received: %p",
            type == CLUSTERMSG_TYPE_PING ? "ping" : "pong",
            (void*)link->node);
        if (link->node) {
            if (nodeInHandshake(link->node)) {
                /* If we already have this node, try to change the
                 * IP/port of the node with the new one. */
                if (sender) {
                    serverLog(LL_VERBOSE,
                        "Handshake: we already know node %.40s, "
                        "updating the address if needed.", sender->name);
                    if (nodeUpdateAddressIfNeeded(sender,link,hdr))
                    {
                        clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                             CLUSTER_TODO_UPDATE_STATE);
                    }
                    /* Free this node as we already have it. This will
                     * cause the link to be freed as well. */
                    clusterDelNode(link->node);
                    return 0;
                }

                /* First thing to do is replacing the random name with the
                 * right node name if this was a handshake stage. */
                clusterRenameNode(link->node, hdr->sender);
                serverLog(LL_DEBUG,"Handshake with node %.40s completed.",
                    link->node->name);
                link->node->flags &= ~CLUSTER_NODE_HANDSHAKE;
                link->node->flags |= flags&(CLUSTER_NODE_MASTER|CLUSTER_NODE_SLAVE);
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG);
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
                link->node->flags |= CLUSTER_NODE_NOADDR;
                link->node->ip[0] = '\0';
                link->node->port = 0;
                link->node->cport = 0;
                freeClusterLink(link);
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG);
                return 0;
            }
        }

        /* Update the node address if it changed. */
        if (sender && type == CLUSTERMSG_TYPE_PING &&
            !nodeInHandshake(sender) &&
            nodeUpdateAddressIfNeeded(sender,link,hdr))
        {
            clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                 CLUSTER_TODO_UPDATE_STATE);
        }
        
        /* Update our info about the node */
        if (link->node && type == CLUSTERMSG_TYPE_PONG) {
            link->node->pong_received = mstime();
            link->node->ping_sent = 0;

            /* The PFAIL condition can be reversed without external
             * help if it is momentary (that is, if it does not
             * turn into a FAIL state).
             *
             * The FAIL condition is also reversible under specific
             * conditions detected by clearNodeFailureIfNeeded(). */
            if (nodeTimedOut(link->node)) {
                link->node->flags &= ~CLUSTER_NODE_PFAIL;
                clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                                     CLUSTER_TODO_UPDATE_STATE);
            } else if (nodeFailed(link->node)) {
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
        int del = !strcasecmp(c->argv[1]->ptr,"delslots");

        memset(slots,0,CLUSTER_SLOTS);
        /* Check that all the arguments are parseable and that all the
         * slots are not already busy. */
        for (j = 2; j < c->argc; j++) {
            if ((slot = getSlotOrReply(c,c->argv[j])) == -1) {
                zfree(slots);
                return;
            }
            if (del && server.cluster->slots[slot] == NULL) {
                addReplyErrorFormat(c,"Slot %d is already unassigned", slot);
                zfree(slots);
                return;
            } else if (!del && server.cluster->slots[slot]) {
                addReplyErrorFormat(c,"Slot %d is already busy", slot);
                zfree(slots);
                return;
            }
            if (slots[slot]++ == 1) {
                addReplyErrorFormat(c,"Slot %d specified multiple times",
                    (int)slot);
                zfree(slots);
                return;
            }
        }
        for (j = 0; j < CLUSTER_SLOTS; j++) {
            if (slots[j]) {
                int retval;

                /* If this slot was set as importing we can clear this
                 * state as now we are the real owner of the slot. */
                if (server.cluster->importing_slots_from[j])
                    server.cluster->importing_slots_from[j] = NULL;

                retval = del ? clusterDelSlot(j) :
                               clusterAddSlot(myself,j);
                serverAssertWithInfo(c,NULL,retval == C_OK);
            }
        }
        zfree(slots);
        clusterDoBeforeSleep(CLUSTER_TODO_UPDATE_STATE|CLUSTER_TODO_SAVE_CONFIG);
        addReply(c,shared.ok);
	} //......
	//......
}

//跟进add操作
int clusterAddSlot(clusterNode *n, int slot) {
    if (server.cluster->slots[slot]) return C_ERR;
    clusterNodeSetSlotBit(n,slot);
    server.cluster->slots[slot] = n;
    return C_OK;
}

//分配槽位底层实现
int clusterNodeSetSlotBit(clusterNode *n, int slot) {
    int old = bitmapTestBit(n->slots,slot);
    bitmapSetBit(n->slots,slot);
    if (!old) {
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
    master = (nodeIsSlave(myself) && myself->slaveof) ?
              myself->slaveof : myself;

    memset(hdr,0,sizeof(*hdr));
    hdr->ver = htons(CLUSTER_PROTO_VER);
    hdr->sig[0] = 'R';
    hdr->sig[1] = 'C';
    hdr->sig[2] = 'm';
    hdr->sig[3] = 'b';
    hdr->type = htons(type);
    memcpy(hdr->sender,myself->name,CLUSTER_NAMELEN);

    /* If cluster-announce-ip option is enabled, force the receivers of our
     * packets to use the specified address for this node. Otherwise if the
     * first byte is zero, they'll do auto discovery. */
    memset(hdr->myip,0,NET_IP_STR_LEN);
    if (server.cluster_announce_ip) {
        strncpy(hdr->myip,server.cluster_announce_ip,NET_IP_STR_LEN);
        hdr->myip[NET_IP_STR_LEN-1] = '\0';
    }

    /* Handle cluster-announce-port as well. */
    int announced_port = server.cluster_announce_port ?
                         server.cluster_announce_port : server.port;
    int announced_cport = server.cluster_announce_bus_port ?
                          server.cluster_announce_bus_port :
                          (server.port + CLUSTER_PORT_INCR);
	
    //向消息头中加入slot信息
    memcpy(hdr->myslots,master->slots,sizeof(hdr->myslots));
    memset(hdr->slaveof,0,CLUSTER_NAMELEN);
    if (myself->slaveof != NULL)
        memcpy(hdr->slaveof,myself->slaveof->name, CLUSTER_NAMELEN);
    hdr->port = htons(announced_port);
    hdr->cport = htons(announced_cport);
    hdr->flags = htons(myself->flags);
    hdr->state = server.cluster->state;

    /* Set the currentEpoch and configEpochs. */
    hdr->currentEpoch = htonu64(server.cluster->currentEpoch);
    hdr->configEpoch = htonu64(master->configEpoch);

    /* Set the replication offset. */
    if (nodeIsSlave(myself))
        offset = replicationGetSlaveOffset();
    else
        offset = server.master_repl_offset;
    hdr->offset = htonu64(offset);

    /* Set the message flags. */
    if (nodeIsMaster(myself) && server.cluster->mf_end)
        hdr->mflags[0] |= CLUSTERMSG_FLAG0_PAUSED;

    /* Compute the message length for certain messages. For other messages
     * this is up to the caller. */
    if (type == CLUSTERMSG_TYPE_FAIL) {
        totlen = sizeof(clusterMsg)-sizeof(union clusterMsgData);
        totlen += sizeof(clusterMsgDataFail);
    } else if (type == CLUSTERMSG_TYPE_UPDATE) {
        totlen = sizeof(clusterMsg)-sizeof(union clusterMsgData);
        totlen += sizeof(clusterMsgDataUpdate);
    }
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
        clusterNode *sender_master = NULL; /* Sender or its master if slave. */
        int dirty_slots = 0; /* Sender claimed slots don't match my view? */

        if (sender) {
            sender_master = nodeIsMaster(sender) ? sender : sender->slaveof;
            if (sender_master) {
                dirty_slots = memcmp(sender_master->slots,
                        hdr->myslots,sizeof(hdr->myslots)) != 0;
            }
        }

        /* 1) If the sender of the message is a master, and we detected that
         *    the set of slots it claims changed, scan the slots to see if we
         *    need to update our configuration. */
        if (sender && nodeIsMaster(sender) && dirty_slots)
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
        if (sender && dirty_slots) {
            int j;

            for (j = 0; j < CLUSTER_SLOTS; j++) {
                if (bitmapTestBit(hdr->myslots,j)) {
                    if (server.cluster->slots[j] == sender ||
                        server.cluster->slots[j] == NULL) continue;
                    if (server.cluster->slots[j]->configEpoch >
                        senderConfigEpoch)
                    {
                        serverLog(LL_VERBOSE,
                            "Node %.40s has old slots configuration, sending "
                            "an UPDATE message about %.40s",
                                sender->name, server.cluster->slots[j]->name);
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
        if (sender &&
            nodeIsMaster(myself) && nodeIsMaster(sender) &&
            senderConfigEpoch == myself->configEpoch)
        {
            clusterHandleConfigEpochCollision(sender);
        }

        /* Get info from the gossip section */
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
        clusterNode *n; /* The node the update is about. */
        uint64_t reportedConfigEpoch =
                    ntohu64(hdr->data.update.nodecfg.configEpoch);

        if (!sender) return 1;  /* We don't know the sender. */
        n = clusterLookupNode(hdr->data.update.nodecfg.nodename);
        if (!n) return 1;   /* We don't know the reported node. */
        if (n->configEpoch >= reportedConfigEpoch) return 1; /* Nothing new. */

        /* If in our current config the node is a slave, set it as a master. */
        if (nodeIsSlave(n)) clusterSetNodeAsMaster(n);

        /* Update the node's configEpoch. */
        n->configEpoch = reportedConfigEpoch;
        clusterDoBeforeSleep(CLUSTER_TODO_SAVE_CONFIG|
                             CLUSTER_TODO_FSYNC_CONFIG);

        /* Check the bitmap of served slots and update our
         * config accordingly. */
        clusterUpdateSlotsConfigWith(n,reportedConfigEpoch,
            hdr->data.update.nodecfg.slots);
    } else {
        serverLog(LL_WARNING,"Received unknown packet type: %d", type);
    }
    return 1;
}

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
    curmaster = nodeIsMaster(myself) ? myself : myself->slaveof;

    if (sender == myself) {
        serverLog(LL_WARNING,"Discarding UPDATE message about myself.");
        return;
    }

    for (j = 0; j < CLUSTER_SLOTS; j++) {
        if (bitmapTestBit(slots,j)) {
            /* The slot is already bound to the sender of this message. */
            if (server.cluster->slots[j] == sender) continue;

            /* The slot is in importing state, it should be modified only
             * manually via redis-trib (example: a resharding is in progress
             * and the migrating side slot was already closed and is advertising
             * a new config. We still want the slot to be closed manually). */
            if (server.cluster->importing_slots_from[j]) continue;

            /* We rebind the slot to the new node claiming it if:
             * 1) The slot was unassigned or the new node claims it with a
             *    greater configEpoch.
             * 2) We are not currently importing the slot. */
            if (server.cluster->slots[j] == NULL ||
                server.cluster->slots[j]->configEpoch < senderConfigEpoch)
            {
                /* Was this slot mine, and still contains keys? Mark it as
                 * a dirty slot. */
                if (server.cluster->slots[j] == myself &&
                    countKeysInSlot(j) &&
                    sender != myself)
                {
                    dirty_slots[dirty_slots_count] = j;
                    dirty_slots_count++;
                }

                if (server.cluster->slots[j] == curmaster)
                    newmaster = sender;
                clusterDelSlot(j);
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
    if (newmaster && curmaster->numslots == 0) {
        serverLog(LL_WARNING,
            "Configuration change detected. Reconfiguring myself "
            "as a replica of %.40s", sender->name);
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
    if (server.cluster_enabled) {
        addReplyError(c,"SLAVEOF not allowed in cluster mode.");
        return;
    }

    /* The special host/port combination "NO" "ONE" turns the instance
     * into a master. Otherwise the new master address is set. */
    if (!strcasecmp(c->argv[1]->ptr,"no") &&
        !strcasecmp(c->argv[2]->ptr,"one")) {
        if (server.masterhost) {
            replicationUnsetMaster();
            sds client = catClientInfoString(sdsempty(),c);
            serverLog(LL_NOTICE,"MASTER MODE enabled (user request from '%s')",
                client);
            sdsfree(client);
        }
    } else {
        long port;

        if ((getLongFromObjectOrReply(c, c->argv[2], &port, NULL) != C_OK))
            return;

        /* Check if we are already attached to the specified slave */
        if (server.masterhost && !strcasecmp(server.masterhost,c->argv[1]->ptr)
            && server.masterport == port) {
            serverLog(LL_NOTICE,"SLAVE OF would result into synchronization with the master we are already connected with. No operation performed.");
            addReplySds(c,sdsnew("+OK Already connected to specified master\r\n"));
            return;
        }
        /* There was no previous master or the user specified a different one,
         * we can continue. */
        replicationSetMaster(c->argv[1]->ptr, port);
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

    sdsfree(server.masterhost);
    server.masterhost = sdsnew(ip);
    server.masterport = port;
    if (server.master) {
        freeClient(server.master);
    }
    //block.c unblockClient操作
    disconnectAllBlockedClients(); /* Clients blocked in master, now slave. */

    /* Force our slaves to resync with us as well. They may hopefully be able
     * to partially resync with us, but we can notify the replid change. */
    //networking.c freeClient操作
    disconnectSlaves();
    //在非阻塞状况下关闭主从同步socket
    cancelReplicationHandshake();
    /* Before destroying our master state, create a cached master using
     * our own parameters, to later PSYNC with the new master. */
    if (was_master) replicationCacheMasterUsingMyself();
    server.repl_state = REPL_STATE_CONNECT;
    server.repl_down_since = 0;
}
```

断开主从关系

```c
void replicationUnsetMaster(void) {
    if (server.masterhost == NULL) return; /* Nothing to do. */
    sdsfree(server.masterhost);
    server.masterhost = NULL;
    /* When a slave is turned into a master, the current replication ID
     * (that was inherited from the master at synchronization time) is
     * used as secondary ID up to the current offset, and a new replication
     * ID is created to continue with a new replication history. */
    shiftReplicationId();
    if (server.master) freeClient(server.master);
    replicationDiscardCachedMaster();
    cancelReplicationHandshake();
    /* Disconnecting all the slaves is required: we need to inform slaves
     * of the replication ID change (see shiftReplicationId() call). However
     * the slaves will be able to partially resync with us, so it will be
     * a very fast reconnection. */
    disconnectSlaves();
    server.repl_state = REPL_STATE_NONE;

    /* We need to make sure the new master will start the replication stream
     * with a SELECT statement. This is forced after a full resync, but
     * with PSYNC version 2, there is no need for full resync after a
     * master switch. */
    server.slaveseldb = -1;

    /* Once we turn from slave to master, we consider the starting time without
     * slaves (that is used to count the replication backlog time to live) as
     * starting from now. Otherwise the backlog will be freed after a
     * failover if slaves do not connect immediately. */
    server.repl_no_slaves_since = server.unixtime;
}
```

##### 00x08 replicate节点复制

---

主从关系建立后，从节点的server.repl_state值被设为REPL_STATE_CONNECT，表示现在已有主节点，且需要连接主节点

这个动作定义在replicationCron()函数中

serverCron()中每1000ms调用一次replicationCron()

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
        if (server.masterauth) {
            err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"AUTH",server.masterauth,NULL);
            if (err) goto write_error;
            server.repl_state = REPL_STATE_RECEIVE_AUTH;
            return;
        } else {
            
            server.repl_state = REPL_STATE_SEND_PORT;
        }
    }

    /* Receive AUTH reply. */
    if (server.repl_state == REPL_STATE_RECEIVE_AUTH) {
        err = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
        if (err[0] == '-') {
            serverLog(LL_WARNING,"Unable to AUTH to MASTER: %s",err);
            sdsfree(err);
            goto error;
        }
        sdsfree(err);
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
        sds port = sdsfromlonglong(server.slave_announce_port ?
            server.slave_announce_port : server.port);
        err = sendSynchronousCommand(SYNC_CMD_WRITE,fd,"REPLCONF",
                "listening-port",port, NULL);
        sdsfree(port);
        if (err) goto write_error;
        sdsfree(err);
        server.repl_state = REPL_STATE_RECEIVE_PORT;
        return;
    }

    /* Receive REPLCONF listening-port reply. */
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
        /* Number of arguments must be odd to make sure that every
         * option has a corresponding value. */
        addReply(c,shared.syntaxerr);
        return;
    }

    /* Process every option-value pair. */
    for (j = 1; j < c->argc; j+=2) {
        if (!strcasecmp(c->argv[j]->ptr,"listening-port")) {
            long port;

            if ((getLongFromObjectOrReply(c,c->argv[j+1],
                    &port,NULL) != C_OK))
                return;
            c->slave_listening_port = port;
        } else if (!strcasecmp(c->argv[j]->ptr,"ip-address")) {
            sds ip = c->argv[j+1]->ptr;
            if (sdslen(ip) < sizeof(c->slave_ip)) {
                memcpy(c->slave_ip,ip,sdslen(ip)+1);
            } else {
                addReplyErrorFormat(c,"REPLCONF ip-address provided by "
                    "slave instance is too long: %zd bytes", sdslen(ip));
                return;
            }
        } else if (!strcasecmp(c->argv[j]->ptr,"capa")) {
            /* Ignore capabilities not understood by this master. */
            if (!strcasecmp(c->argv[j+1]->ptr,"eof"))
                c->slave_capa |= SLAVE_CAPA_EOF;
            else if (!strcasecmp(c->argv[j+1]->ptr,"psync2"))
                c->slave_capa |= SLAVE_CAPA_PSYNC2;
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
        } else if (!strcasecmp(c->argv[j]->ptr,"getack")) {
            /* REPLCONF GETACK is used in order to request an ACK ASAP
             * to the slave. */
            if (server.masterhost && server.master) replicationSendAck();
            return;
        } else {
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
        //这个值为-1时，代表当前主节点的replid(旧版本为run_id)与全局复制偏移量无效
        //当执行全量同步后，偏移量将被修正
        server.master_initial_offset = -1;

        //检查主节点缓存，判断是进行全量同步还是部分同步
        if (server.cached_master) {
            //有缓存，向主节点发送"PSYNC <run_id> <repl_offset>"，进行部分同步
            //replid 就是 run_id
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
    if (c->flags & CLIENT_SLAVE) return;

    /* Refuse SYNC requests if we are a slave but the link with our master
     * is not ok... */
    if (server.masterhost && server.repl_state != REPL_STATE_CONNECTED) {
        addReplySds(c,sdsnew("-NOMASTERLINK Can't SYNC while not connected with my master\r\n"));
        return;
    }

    /* SYNC can't be issued when the server has pending data to send to
     * the client about already issued commands. We need a fresh reply
     * buffer registering the differences between the BGSAVE and the current
     * dataset, so that we can copy to other slaves if needed. */
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
    if (!strcasecmp(c->argv[0]->ptr,"psync")) {
        if (masterTryPartialResynchronization(c) == C_OK) {
            server.stat_sync_partial_ok++;
            return; /* No full resync needed, return. */
        } else {
            char *master_replid = c->argv[1]->ptr;

            /* Increment stats for failed PSYNCs, but only if the
             * replid is not "?", as this is used by slaves to force a full
             * resync on purpose when they are not albe to partially
             * resync. */
            if (master_replid[0] != '?') server.stat_sync_partial_err++;
        }
    } else {
        /* If a slave uses SYNC, we are dealing with an old implementation
         * of the replication protocol (like redis-cli --slave). Flag the client
         * so that we don't expect to receive REPLCONF ACK feedbacks. */
        c->flags |= CLIENT_PRE_PSYNC;
    }

    /* Full resynchronization. */
    server.stat_sync_full++;

    /* Setup the slave as one waiting for BGSAVE to start. The following code
     * paths will change the state if we handle the slave differently. */
    c->replstate = SLAVE_STATE_WAIT_BGSAVE_START;
    if (server.repl_disable_tcp_nodelay)
        anetDisableTcpNoDelay(NULL, c->fd); /* Non critical if it fails. */
    c->repldbfd = -1;
    c->flags |= CLIENT_SLAVE;
    listAddNodeTail(server.slaves,c);

    /* Create the replication backlog if needed. */
    if (listLength(server.slaves) == 1 && server.repl_backlog == NULL) {
        /* When we create the backlog from scratch, we always use a new
         * replication ID and clear the ID2, since there is no valid
         * past history. */
        changeReplicationId();
        clearReplicationId2();
        createReplicationBacklog();
    }

    /* CASE 1: BGSAVE is in progress, with disk target. */
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
        while((ln = listNext(&li))) {
            slave = ln->value;
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) break;
        }
        /* To attach this slave, we check that it has at least all the
         * capabilities of the slave that triggered the current BGSAVE. */
        if (ln && ((c->slave_capa & slave->slave_capa) == slave->slave_capa)) {
            /* Perfect, the server is already registering differences for
             * another slave. Set the right state, and copy the buffer. */
            copyClientOutputBuffer(c,slave);
            replicationSetupSlaveForFullResync(c,slave->psync_initial_offset);
            serverLog(LL_NOTICE,"Waiting for end of BGSAVE for SYNC");
        } else {
            /* No way, we need to wait for the next BGSAVE in order to
             * register differences. */
            serverLog(LL_NOTICE,"Can't attach the slave to the current BGSAVE. Waiting for next BGSAVE for SYNC");
        }

    /* CASE 2: BGSAVE is in progress, with socket target. */
    } else if (server.rdb_child_pid != -1 &&
               server.rdb_child_type == RDB_CHILD_TYPE_SOCKET)
    {
        /* There is an RDB child process but it is writing directly to
         * children sockets. We need to wait for the next BGSAVE
         * in order to synchronize. */
        serverLog(LL_NOTICE,"Current BGSAVE has socket target. Waiting for next BGSAVE for SYNC");

    /* CASE 3: There is no BGSAVE is progress. */
    } else {
        if (server.repl_diskless_sync && (c->slave_capa & SLAVE_CAPA_EOF)) {
            /* Diskless replication RDB child is created inside
             * replicationCron() since we want to delay its start a
             * few seconds to wait for more slaves to arrive. */
            if (server.repl_diskless_sync_delay)
                serverLog(LL_NOTICE,"Delay next BGSAVE for diskless SYNC");
        } else {
            /* Target is disk (or the slave is not capable of supporting
             * diskless replication) and we don't have a BGSAVE in progress,
             * let's start one. */
            if (server.aof_child_pid == -1) {
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
    int socket_target = server.repl_diskless_sync && (mincapa & SLAVE_CAPA_EOF);
    listIter li;
    listNode *ln;

    serverLog(LL_NOTICE,"Starting BGSAVE for SYNC with target: %s",
        socket_target ? "slaves sockets" : "disk");

    rdbSaveInfo rsi, *rsiptr;
    rsiptr = rdbPopulateSaveInfo(&rsi);
    /* Only do rdbSave* when rsiptr is not NULL,
     * otherwise slave will miss repl-stream-db. */
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
        while((ln = listNext(&li))) {
            client *slave = ln->value;

            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
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
//接slaveTryPartialResynchronization()写部分
    /* If reached this point, we should be in REPL_STATE_RECEIVE_PSYNC. */
    if (server.repl_state != REPL_STATE_RECEIVE_PSYNC) {
        serverLog(LL_WARNING,"syncWithMaster(): state machine error, "
                             "state should be RECEIVE_PSYNC but is %d",
                             server.repl_state);
        goto error;
    }

    psync_result = slaveTryPartialResynchronization(fd,1);
    /* Reading half */
    reply = sendSynchronousCommand(SYNC_CMD_READ,fd,NULL);
    if (sdslen(reply) == 0) {
        /* The master may send empty newlines after it receives PSYNC
         * and before to reply, just to keep the connection alive. */
        sdsfree(reply);
        return PSYNC_WAIT_REPLY;
    }

    aeDeleteFileEvent(server.el,fd,AE_READABLE);

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
        replicationDiscardCachedMaster();
        sdsfree(reply);
        return PSYNC_FULLRESYNC;
    }

    if (!strncmp(reply,"+CONTINUE",9)) {
        /* Partial resync was accepted. */
        serverLog(LL_NOTICE,
            "Successful partial resynchronization with master.");

        /* Check the new replication ID advertised by the master. If it
         * changed, we need to set the new ID as primary ID, and set or
         * secondary ID as the old master ID up to the current offset, so
         * that our sub-slaves will be able to PSYNC with us after a
         * disconnection. */
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
                memcpy(server.replid2,server.cached_master->replid,
                    sizeof(server.replid2));
                server.second_replid_offset = server.master_repl_offset+1;

                /* Update the cached master ID and our own primary ID to the
                 * new one. */
                memcpy(server.replid,new,sizeof(server.replid));
                memcpy(server.cached_master->replid,new,sizeof(server.replid));

                /* Disconnect all the sub-slaves: they need to be notified. */
                disconnectSlaves();
            }
        }

        /* Setup the replication to continue. */
        sdsfree(reply);
        replicationResurrectCachedMaster(fd);

        /* If this instance was restarted and we read the metadata to
         * PSYNC from the persistence file, our replication backlog could
         * be still not initialized. Create it. */
        if (server.repl_backlog == NULL) createReplicationBacklog();
        return PSYNC_CONTINUE;
    }

    /* If we reach this point we received either an error (since the master does
     * not understand PSYNC or because it is in a special state and cannot
     * serve our request), or an unexpected reply from the master.
     *
     * Return PSYNC_NOT_SUPPORTED on errors we don't understand, otherwise
     * return PSYNC_TRY_LATER if we believe this is a transient error. */

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
    while(maxtries--) {
        snprintf(tmpfile,256,
            "temp-%d.%ld.rdb",(int)server.unixtime,(long int)getpid());
        dfd = open(tmpfile,O_CREAT|O_WRONLY|O_EXCL,0644);
        if (dfd != -1) break;
        sleep(1);
    }
    if (dfd == -1) {
        serverLog(LL_WARNING,"Opening the temp file needed for MASTER <-> SLAVE synchronization: %s",strerror(errno));
        goto error;
    }

    /* Setup the non blocking download of the bulk file. */
    if (aeCreateFileEvent(server.el,fd, AE_READABLE,readSyncBulkPayload,NULL)
            == AE_ERR)
    {
        serverLog(LL_WARNING,
            "Can't create readable event for SYNC: %s (fd=%d)",
            strerror(errno),fd);
        goto error;
    }

    server.repl_state = REPL_STATE_TRANSFER;
    server.repl_transfer_size = -1;
    server.repl_transfer_read = 0;
    server.repl_transfer_last_fsync_off = 0;
    server.repl_transfer_fd = dfd;
    server.repl_transfer_lastio = server.unixtime;
    server.repl_transfer_tmpfile = zstrdup(tmpfile);
    return;

error:
    aeDeleteFileEvent(server.el,fd,AE_READABLE|AE_WRITABLE);
    if (dfd != -1) close(dfd);
    close(fd);
    server.repl_transfer_s = -1;
    server.repl_state = REPL_STATE_CONNECT;
    return;

write_error: /* Handle sendSynchronousCommand(SYNC_CMD_WRITE) errors. */
    serverLog(LL_WARNING,"Sending command to master in replication handshake: %s", err);
    sdsfree(err);
    goto error;
}
```

从节点将打开一个临时文件等待写入，并更改状态为REPL_STATE_TRANSFER

主节点中，rdb文件的发送不是主动执行，而是放在循环事件serverCron()中

serverCron() -> backgroundSaveHandler() -> backgroundSaveDoneHandlerDisk() -> updateSlavesWaitingBgsave() -> sendBulkToSlave()

```c
void updateSlavesWaitingBgsave(int bgsaveerr, int type) {
    listNode *ln;
    int startbgsave = 0;
    int mincapa = -1;
    listIter li;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) {
            startbgsave = 1;
            mincapa = (mincapa == -1) ? slave->slave_capa :
                                        (mincapa & slave->slave_capa);
        } else if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_END) {
            struct redis_stat buf;

            /* If this was an RDB on disk save, we have to prepare to send
             * the RDB from disk to the slave socket. Otherwise if this was
             * already an RDB -> Slaves socket transfer, used in the case of
             * diskless replication, our work is trivial, we can just put
             * the slave online. */
            if (type == RDB_CHILD_TYPE_SOCKET) {
                serverLog(LL_NOTICE,
                    "Streamed RDB transfer with slave %s succeeded (socket). Waiting for REPLCONF ACK from slave to enable streaming",
                        replicationGetSlaveName(slave));
                /* Note: we wait for a REPLCONF ACK message from slave in
                 * order to really put it online (install the write handler
                 * so that the accumulated data can be transfered). However
                 * we change the replication state ASAP, since our slave
                 * is technically online now. */
                slave->replstate = SLAVE_STATE_ONLINE;
                slave->repl_put_online_on_ack = 1;
                slave->repl_ack_time = server.unixtime; /* Timeout otherwise. */
            } else {
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
    if (server.masterhost != NULL) return;

    /* If there aren't slaves, and there is no backlog buffer to populate,
     * we can return ASAP. */
    if (server.repl_backlog == NULL && listLength(slaves) == 0) return;

    /* We can't have slaves attached and no backlog. */
    serverAssert(!(listLength(slaves) != 0 && server.repl_backlog == NULL));

    /* Send SELECT command to every slave if needed. */
    if (server.slaveseldb != dictid) {
        robj *selectcmd;

        /* For a few DBs we have pre-computed SELECT command. */
        if (dictid >= 0 && dictid < PROTO_SHARED_SELECT_CMDS) {
            selectcmd = shared.select[dictid];
        } else {
            int dictid_len;

            dictid_len = ll2string(llstr,sizeof(llstr),dictid);
            selectcmd = createObject(OBJ_STRING,
                sdscatprintf(sdsempty(),
                "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n",
                dictid_len, llstr));
        }

        /* Add the SELECT command into the backlog. */
        if (server.repl_backlog) feedReplicationBacklogWithObject(selectcmd);

        /* Send it to slaves. */
        listRewind(slaves,&li);
        while((ln = listNext(&li))) {
            client *slave = ln->value;
            if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) continue;
            addReply(slave,selectcmd);
        }

        if (dictid < 0 || dictid >= PROTO_SHARED_SELECT_CMDS)
            decrRefCount(selectcmd);
    }
    server.slaveseldb = dictid;

    /* Write the command to the replication backlog if any. */
    if (server.repl_backlog) {
        char aux[LONG_STR_SIZE+3];

        /* Add the multi bulk reply length. */
        aux[0] = '*';
        len = ll2string(aux+1,sizeof(aux)-1,argc);
        aux[len+1] = '\r';
        aux[len+2] = '\n';
        feedReplicationBacklog(aux,len+3);

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
    while((ln = listNext(&li))) {
        client *slave = ln->value;

        /* Don't feed slaves that are still waiting for BGSAVE to start */
        if (slave->replstate == SLAVE_STATE_WAIT_BGSAVE_START) continue;

        /* Feed slaves that are waiting for the initial SYNC (so these commands
         * are queued in the output buffer until the initial SYNC completes),
         * or are already in sync with the master. */

        /* Add the multi bulk length. */
        addReplyMultiBulkLen(slave,argc);

        /* Finally any additional argument that was not stored inside the
         * static buffer if any (from j to argc). */
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
    c->flags |= CLIENT_SLAVE;
    c->replstate = SLAVE_STATE_ONLINE;
    c->repl_ack_time = server.unixtime;
    c->repl_put_online_on_ack = 0;
    listAddNodeTail(server.slaves,c);
    /* We can't use the connection buffers since they are used to accumulate
     * new commands at this stage. But we are sure the socket send buffer is
     * empty so this write will never fail actually. */
    if (c->slave_capa & SLAVE_CAPA_PSYNC2) {
        buflen = snprintf(buf,sizeof(buf),"+CONTINUE %s\r\n", server.replid);
    } else {
        buflen = snprintf(buf,sizeof(buf),"+CONTINUE\r\n");
    }
    if (write(c->fd,buf,buflen) != buflen) {
        freeClientAsync(c);
        return C_OK;
    }
    psync_len = addReplyReplicationBacklog(c,psync_offset);
    serverLog(LL_NOTICE,
        "Partial resynchronization request from %s accepted. Sending %lld bytes of backlog starting from offset %lld.",
            replicationGetSlaveName(c),
            psync_len, psync_offset);
    /* Note that we don't need to set the selected DB at server.slaveseldb
     * to -1 to force the master to emit SELECT, since the slave already
     * has this state from the previous connection with the master. */

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



##### 00x12 sentinel周期任务

---

serverCorn

​	sentinelTimer (per 100ms)

​		sentinelCheckTiltCondition

​		sentinelHandleDictOfRedisInstances

​			sentinelHandleDictOfRedisInstances (递归) 

​			sentinelHandleRedisInstances  

​				sentinelReconnectInstance

​				sentinelSendPeriodicCommands

​				sentinelCheckSubjectivelyDown

​				sentinelCheckObjectivelyDown

​		sentinelRunPendingScripts

​		sentinelCollectTerminatedScripts

​		sentinelKillTimedoutScripts

##### 00x13 Tilt模式

---



##### 00x14 执行脚本

---



##### 00x15 节点监控

---



##### 00x16 故障转移

---









