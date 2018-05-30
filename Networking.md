# Networking

[TOC]

#### 客户端

##### 00x01 连接

---

```c
static int cliConnect(int force) {
    if (context == NULL || force) {
        if (context != NULL) {
            redisFree(context);
        }
		
        //根据配置确定使用哪种连接方式
        if (config.hostsocket == NULL) {
            //正常tcp连接
            context = redisConnect(config.hostip,config.hostport);
        } else {
            //在无外网的环境下可用unix系统的文件socket进行本地通信
            context = redisConnectUnix(config.hostsocket);
        }

        if (context->err) {
            fprintf(stderr,"Could not connect to Redis at ");
            if (config.hostsocket == NULL)
                fprintf(stderr,"%s:%d: %s\n",config.hostip,config.hostport,context->errstr);
            else
                fprintf(stderr,"%s: %s\n",config.hostsocket,context->errstr);
            redisFree(context);
            context = NULL;
            return REDIS_ERR;
        }

        /* Set aggressive KEEP_ALIVE socket option in the Redis context socket
         * in order to prevent timeouts caused by the execution of long
         * commands. At the same time this improves the detection of real
         * errors. */
        //保持socket的连接状，以支持执行时间要求较长的命令与错误检测
        anetKeepAlive(NULL, context->fd, REDIS_CLI_KEEPALIVE_INTERVAL);

        /* Do AUTH and select the right DB. */
        //向server发送AUTH命令 (AUTH passwd)
        if (cliAuth() != REDIS_OK)
            return REDIS_ERR;
        //发送SELECT命令，选择database
        if (cliSelect() != REDIS_OK)
            return REDIS_ERR;
    }
    return REDIS_OK;
}
```

两种不同的连接方式定义在hiredis/net.c中

hiredis是redis数据库的C语言客户端库

在连接时，调用redisContextInit()函数保存连接环境的结构体

```c
//hiredis.h
//保存连接环境的结构体
typedef struct redisContext {
    int err; /* Error flags, 0 when there is no error */
    char errstr[128]; /* String representation of error when applicable */
    int fd;
    int flags;
    char *obuf; /* Write buffer */
    redisReader *reader; /* Protocol reader */
	
    //type有两种 REDIS_CONN_TCP REDIS_CONN_UNIX
    enum redisConnectionType connection_type;
    struct timeval *timeout;
	
    //两种连接类型的信息
    struct {
        char *host;
        char *source_addr;
        int port;
    } tcp;

    struct {
        char *path;
    } unix_sock;

} redisContext;

//tcp连接底层实现
//hiredis/net.c
static int _redisContextConnectTcp(redisContext *c, const char *addr, int port,
                                   const struct timeval *timeout,
                                   const char *source_addr) {
    int s, rv, n;
    char _port[6];  /* strlen("65535"); */
    struct addrinfo hints, *servinfo, *bservinfo, *p, *b;
    int blocking = (c->flags & REDIS_BLOCK);
    int reuseaddr = (c->flags & REDIS_REUSEADDR);
    int reuses = 0;
    long timeout_msec = -1;

    servinfo = NULL;
    //保存连接方式
    c->connection_type = REDIS_CONN_TCP;
    //保存端口
    c->tcp.port = port;

    /* We need to take possession of the passed parameters
     * to make them reusable for a reconnect.
     * We also carefully check we don't free data we already own,
     * as in the case of the reconnect method.
     *
     * This is a bit ugly, but atleast it works and doesn't leak memory.
     **/
    //以下写法是为了防止内存泄漏
    //保存host
    if (c->tcp.host != addr) {
        if (c->tcp.host)
            free(c->tcp.host);

        c->tcp.host = strdup(addr);
    }
	
    //保存连接超时时间
    if (timeout) {
        if (c->timeout != timeout) {
            if (c->timeout == NULL)
                c->timeout = malloc(sizeof(struct timeval));

            memcpy(c->timeout, timeout, sizeof(struct timeval));
        }
    } else {
        if (c->timeout)
            free(c->timeout);
        c->timeout = NULL;
    }
	
    //将timeval结构中的时间解析到long类型的timeout_msec中
    if (redisContextTimeoutMsec(c, &timeout_msec) != REDIS_OK) {
        __redisSetError(c, REDIS_ERR_IO, "Invalid timeout specified");
        goto error;
    }
	
    //保存资源地址，可用netdb库函数getaddrinfo()解析(DNS)
    if (source_addr == NULL) {
        free(c->tcp.source_addr);
        c->tcp.source_addr = NULL;
    } else if (c->tcp.source_addr != source_addr) {
        free(c->tcp.source_addr);
        c->tcp.source_addr = strdup(source_addr);
    }

    snprintf(_port, 6, "%d", port);
    memset(&hints,0,sizeof(hints));
    //保存协议类型为ipv4
    hints.ai_family = AF_INET;
    //基于tcp
    hints.ai_socktype = SOCK_STREAM;

    /* Try with IPv6 if no IPv4 address was found. We do it in this order since
     * in a Redis client you can't afford to test if you have IPv6 connectivity
     * as this would add latency to every connect. Otherwise a more sensible
     * route could be: Use IPv6 if both addresses are available and there is IPv6
     * connectivity. */
    //尝试寻找ipv6地址
    if ((rv = getaddrinfo(c->tcp.host,_port,&hints,&servinfo)) != 0) {
         hints.ai_family = AF_INET6;
         if ((rv = getaddrinfo(addr,_port,&hints,&servinfo)) != 0) {
            __redisSetError(c,REDIS_ERR_OTHER,gai_strerror(rv));
            return REDIS_ERR;
        }
    }
    //遍历addrinfo
    for (p = servinfo; p != NULL; p = p->ai_next) {
addrretry:
        //创建socket
        if ((s = socket(p->ai_family,p->ai_socktype,p->ai_protocol)) == -1)
            continue;

        c->fd = s;
        //设置socket为非阻塞
        if (redisSetBlocking(c,0) != REDIS_OK)
            goto error;
        //用地址连接
        if (c->tcp.source_addr) {
            int bound = 0;
            /* Using getaddrinfo saves us from self-determining IPv4 vs IPv6 */
            if ((rv = getaddrinfo(c->tcp.source_addr, NULL, &hints, &bservinfo)) != 0) {
                char buf[128];
                snprintf(buf,sizeof(buf),"Can't get addr: %s",gai_strerror(rv));
                __redisSetError(c,REDIS_ERR_OTHER,buf);
                goto error;
            }

            if (reuseaddr) {
                n = 1;
                if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*) &n,
                               sizeof(n)) < 0) {
                    goto error;
                }
            }
            
            //绑定本地端口
            for (b = bservinfo; b != NULL; b = b->ai_next) {
                if (bind(s,b->ai_addr,b->ai_addrlen) != -1) {
                    bound = 1;
                    break;
                }
            }
            freeaddrinfo(bservinfo);
            if (!bound) {
                char buf[128];
                snprintf(buf,sizeof(buf),"Can't bind socket: %s",strerror(errno));
                __redisSetError(c,REDIS_ERR_OTHER,buf);
                goto error;
            }
        }
        //连接某host的端口
        if (connect(s,p->ai_addr,p->ai_addrlen) == -1) {
            if (errno == EHOSTUNREACH) {
                redisContextCloseFd(c);
                continue;
            } else if (errno == EINPROGRESS && !blocking) {
                /* This is ok. */
            } else if (errno == EADDRNOTAVAIL && reuseaddr) {
                if (++reuses >= REDIS_CONNECT_RETRIES) {
                    goto error;
                } else {
                    redisContextCloseFd(c);
                    goto addrretry;
                }
            } else {
                if (redisContextWaitReady(c,timeout_msec) != REDIS_OK)
                    goto error;
            }
        }
        //设置socket为阻塞
        if (blocking && redisSetBlocking(c,1) != REDIS_OK)
            goto error;
        //开启tcp TCP_NODELAY 选项，禁用Nagle’s Algorithm
        //关于Nagle算法，其作用是做短时等待，将tcp的小包组合为大包
        //关闭后所有包都会立即发送
        if (redisSetTcpNoDelay(c) != REDIS_OK)
            goto error;

        c->flags |= REDIS_CONNECTED;
        rv = REDIS_OK;
        goto end;
    }
    if (p == NULL) {
        char buf[128];
        snprintf(buf,sizeof(buf),"Can't create socket: %s",strerror(errno));
        __redisSetError(c,REDIS_ERR_OTHER,buf);
        goto error;
    }

error:
    rv = REDIS_ERR;
end:
    freeaddrinfo(servinfo);
    return rv;  // Need to return REDIS_OK if alright
}

//unix socket连接底层实现
//因为直接操作本地文件，所以比tcp简单一些
int redisContextConnectUnix(redisContext *c, const char *path, const struct timeval *timeout) {
    int blocking = (c->flags & REDIS_BLOCK);
    struct sockaddr_un sa;
    long timeout_msec = -1;

    //创建socket，设置为非阻塞
    if (redisCreateSocket(c,AF_LOCAL) < 0)
        return REDIS_ERR;
    if (redisSetBlocking(c,0) != REDIS_OK)
        return REDIS_ERR;

    //连接模式设为unix socket
    c->connection_type = REDIS_CONN_UNIX;
    //保存socket所用文件路径
    if (c->unix_sock.path != path)
        c->unix_sock.path = strdup(path);

    if (timeout) {
        if (c->timeout != timeout) {
            if (c->timeout == NULL)
                c->timeout = malloc(sizeof(struct timeval));

            memcpy(c->timeout, timeout, sizeof(struct timeval));
        }
    } else {
        if (c->timeout)
            free(c->timeout);
        c->timeout = NULL;
    }

    if (redisContextTimeoutMsec(c,&timeout_msec) != REDIS_OK)
        return REDIS_ERR;
    
    sa.sun_family = AF_LOCAL;
    strncpy(sa.sun_path,path,sizeof(sa.sun_path)-1);
    //连接
    if (connect(c->fd, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        if (errno == EINPROGRESS && !blocking) {
            /* This is ok. */
        } else {
            if (redisContextWaitReady(c,timeout_msec) != REDIS_OK)
                return REDIS_ERR;
        }
    }

    /* Reset socket to be blocking after connect(2). */
    if (blocking && redisSetBlocking(c,1) != REDIS_OK)
        return REDIS_ERR;

    c->flags |= REDIS_CONNECTED;
    return REDIS_OK;
}

```

##### 00x02 通信

---

发送命令

```c
//hiredis.c
//从buffer向socket写入信息
//buffer最后为空 返回REDIS_OK
int redisBufferWrite(redisContext *c, int *done) {
    int nwritten;

    /* Return early when the context has seen an error. */
    if (c->err)
        return REDIS_ERR;

    if (sdslen(c->obuf) > 0) {
        //将输出缓冲区的数据写入fd
        nwritten = write(c->fd,c->obuf,sdslen(c->obuf));
        //写入失败
        if (nwritten == -1) {
            if ((errno == EAGAIN && !(c->flags & REDIS_BLOCK)) || (errno == EINTR)) {
                /* Try again later */
            } else {
                __redisSetError(c,REDIS_ERR_IO,NULL);
                return REDIS_ERR;
            }
        //写入成功(不确定是否写完)
        } else if (nwritten > 0) {
            //写完了
            if (nwritten == (signed)sdslen(c->obuf)) {
                sdsfree(c->obuf);
                c->obuf = sdsempty();
            //没有写完，修正输出缓冲区内容
            } else {
                sdsrange(c->obuf,nwritten,-1);
            }
        }
    }
    if (done != NULL) *done = (sdslen(c->obuf) == 0);
    return REDIS_OK;
}
```

读回复

```c
int redisBufferRead(redisContext *c) {
    char buf[1024*16];
    int nread;

    /* Return early when the context has seen an error. */
    if (c->err)
        return REDIS_ERR;
	
    //跟write一个套路，先读再判断读的情况
    //不过先读到一个临时的buffer里
    nread = read(c->fd,buf,sizeof(buf));
    //读失败
    if (nread == -1) {
        if ((errno == EAGAIN && !(c->flags & REDIS_BLOCK)) || (errno == EINTR)) {
            /* Try again later */
        } else {
            __redisSetError(c,REDIS_ERR_IO,NULL);
            return REDIS_ERR;
        }
    //空读
    } else if (nread == 0) {
        __redisSetError(c,REDIS_ERR_EOF,"Server closed the connection");
        return REDIS_ERR;
    } else {
        //清理reader中的buf，写入临时buf中的内容
        if (redisReaderFeed(c->reader,buf,nread) != REDIS_OK) {
            __redisSetError(c,c->reader->err,c->reader->errstr);
            return REDIS_ERR;
        }
    }
    return REDIS_OK;
}
```

命令发送-接收回复流程

在redisSendCommand()中被调用

```c
//被cliReadReply()调用
//hiredis.c
int redisGetReply(redisContext *c, void **reply) {
    int wdone = 0;
    void *aux = NULL;

    /* Try to read pending replies */
    //从c->reader中读reply内容到aux中
    if (redisGetReplyFromReader(c,&aux) == REDIS_ERR)
        return REDIS_ERR;

    /* For the blocking context, flush output buffer and read reply */
    //如果reply读出内容为空
    if (aux == NULL && c->flags & REDIS_BLOCK) {
        /* Write until done */
        do {
            //向c->fd写入c->obuf的内容
            //这里的内容是在cliSendCommand()函数中写入的
            if (redisBufferWrite(c,&wdone) == REDIS_ERR)
                return REDIS_ERR;
        } while (!wdone);

        /* Read until there is a reply */
        //读server的回复
        do {
            if (redisBufferRead(c) == REDIS_ERR)
                return REDIS_ERR;
            if (redisGetReplyFromReader(c,&aux) == REDIS_ERR)
                return REDIS_ERR;
        } while (aux == NULL);
    }

    /* Set reply object */
    if (reply != NULL) *reply = aux;
    return REDIS_OK;
}

//redis-cli.c
static int cliReadReply(int output_raw_strings) {
    void *_reply;
    redisReply *reply;
    sds out = NULL;
    int output = 1;

    //发送命令内容，获取回复，写入_reply
    if (redisGetReply(context,&_reply) != REDIS_OK) {
        if (config.shutdown) {
            redisFree(context);
            context = NULL;
            return REDIS_OK;
        }
        if (config.interactive) {
            //检查交互状态
            /* Filter cases where we should reconnect */
            if (context->err == REDIS_ERR_IO &&
                (errno == ECONNRESET || errno == EPIPE))
                return REDIS_ERR;
            if (context->err == REDIS_ERR_EOF)
                return REDIS_ERR;
        }
        //报错并结束当前进程
        cliPrintContextError();
        exit(1);
        return REDIS_ERR; /* avoid compiler warning */
    }

    reply = (redisReply*)_reply;

    config.last_cmd_type = reply->type;

    /* Check if we need to connect to a different node and reissue the
     * request. */
    //需要重定向
    if (config.cluster_mode && reply->type == REDIS_REPLY_ERROR &&
        (!strncmp(reply->str,"MOVED",5) || !strcmp(reply->str,"ASK")))
    {
        char *p = reply->str, *s;
        int slot;

        output = 0;
        /* Comments show the position of the pointer as:
         *
         * [S] for pointer 's'
         * [P] for pointer 'p'
         */
        //确定命令中host与port位置
        s = strchr(p,' ');      /* MOVED[S]3999 127.0.0.1:6381 */
        p = strchr(s+1,' ');    /* MOVED[S]3999[P]127.0.0.1:6381 */
        *p = '\0';
        slot = atoi(s+1);
        s = strrchr(p+1,':');    /* MOVED 3999[P]127.0.0.1[S]6381 */
        *s = '\0';
        sdsfree(config.hostip);
        config.hostip = sdsnew(p+1);
        config.hostport = atoi(s+1);
        if (config.interactive)
            printf("-> Redirected to slot [%d] located at %s:%d\n",
                slot, config.hostip, config.hostport);
        config.cluster_reissue_command = 1;
        cliRefreshPrompt();
    }
	
    //不符合之前的条件，output没有被设为0
    if (output) {
        if (output_raw_strings) {
            out = cliFormatReplyRaw(reply);
        } else {
            //分情况对回复内容解析
            if (config.output == OUTPUT_RAW) {
                out = cliFormatReplyRaw(reply);
                out = sdscat(out,"\n");
            } else if (config.output == OUTPUT_STANDARD) {
                out = cliFormatReplyTTY(reply,"");
            } else if (config.output == OUTPUT_CSV) {
                out = cliFormatReplyCSV(reply);
                out = sdscat(out,"\n");
            }
        }
        //写入标准输出(屏幕)
        fwrite(out,sdslen(out),1,stdout);
        sdsfree(out);
    }
    freeReplyObject(reply);
    return REDIS_OK;
}
```

#### 服务端

##### 00x03 创建连接

---

在initServer()中，对监听端口的可写事件绑定了acceptTcpHandler()/acceptUnixHandler()，两者对tcpsocket/unixsocket处理后产出通用的文件描述符(fd)，调用更底层的acceptCommonHandler()尝试创建客户端实例

```c
//socket已经在上层函数连接，向acceptCommonHandler直接传入相应fd
#define MAX_ACCEPTS_PER_CALL 1000
static void acceptCommonHandler(int fd, int flags, char *ip) {
    client *c;
    //创建客户端对象
    if ((c = createClient(fd)) == NULL) {
        serverLog(LL_WARNING,
            "Error registering fd event for the new client: %s (fd=%d)",
            strerror(errno),fd);
        close(fd); /* May be already closed, just ignore errors */
        return;
    }
    /* If maxclient directive is set and this is one client more... close the
     * connection. Note that we create the client instead to check before
     * for this condition, since now the socket is already set in non-blocking
     * mode and we can send an error for free using the Kernel I/O */
    //限制连接的客户端数量
    if (listLength(server.clients) > server.maxclients) {
        char *err = "-ERR max number of clients reached\r\n";

        /* That's a best effort error message, don't check write errors */
        if (write(c->fd,err,strlen(err)) == -1) {
            /* Nothing to do, Just to avoid the warning... */
        }
        server.stat_rejected_conn++;
        freeClient(c);
        return;
    }

    /* If the server is running in protected mode (the default) and there
     * is no password set, nor a specific interface is bound, we don't accept
     * requests from non loopback interfaces. Instead we try to explain the
     * user what to do to fix it if needed. */
    //检测在安全模式开启下的安全性
    if (server.protected_mode &&
        server.bindaddr_count == 0 &&
        server.requirepass == NULL &&
        !(flags & CLIENT_UNIX_SOCKET) &&
        ip != NULL)
    {
        if (strcmp(ip,"127.0.0.1") && strcmp(ip,"::1")) {
            char *err =
                "-DENIED Redis is running in protected mode because protected "
                "mode is enabled, no bind address was specified, no "
                "authentication password is requested to clients. In this mode "
                "connections are only accepted from the loopback interface. "
                "If you want to connect from external computers to Redis you "
                "may adopt one of the following solutions: "
                "1) Just disable protected mode sending the command "
                "'CONFIG SET protected-mode no' from the loopback interface "
                "by connecting to Redis from the same host the server is "
                "running, however MAKE SURE Redis is not publicly accessible "
                "from internet if you do so. Use CONFIG REWRITE to make this "
                "change permanent. "
                "2) Alternatively you can just disable the protected mode by "
                "editing the Redis configuration file, and setting the protected "
                "mode option to 'no', and then restarting the server. "
                "3) If you started the server manually just for testing, restart "
                "it with the '--protected-mode no' option. "
                "4) Setup a bind address or an authentication password. "
                "NOTE: You only need to do one of the above things in order for "
                "the server to start accepting connections from the outside.\r\n";
            if (write(c->fd,err,strlen(err)) == -1) {
                /* Nothing to do, Just to avoid the warning... */
            }
            server.stat_rejected_conn++;
            freeClient(c);
            return;
        }
    }
	
    //连接成功增加服务器计数
    server.stat_numconnections++;
    c->flags |= flags;
}
```

##### 00x04 对接客户端

---

server在客户端连接时会创建一个client结构，可以理解为对当前连接的客户端的建模

```c
client *createClient(int fd) {
    client *c = zmalloc(sizeof(client));

    /* passing -1 as fd it is possible to create a non connected client.
     * This is useful since all the commands needs to be executed
     * in the context of a client. When commands are executed in other
     * contexts (for instance a Lua script) we need a non connected client. */
    if (fd != -1) {
        //socket设为非阻塞
        anetNonBlock(NULL,fd);
        //开启tcp TCP_NODELAY 选项，禁用Nagle’s Algorithm
        anetEnableTcpNoDelay(NULL,fd);
        if (server.tcpkeepalive)
            //设置keep-alive
            anetKeepAlive(NULL,fd,server.tcpkeepalive);
        //设置readQueryFromClient()处理可读事件
        if (aeCreateFileEvent(server.el,fd,AE_READABLE,
            readQueryFromClient, c) == AE_ERR)
        {
            close(fd);
            zfree(c);
            return NULL;
        }
    }
	
    //默认选择0号db
    selectDb(c,0);
    //设置当前client的id
    uint64_t client_id;
    atomicGetIncr(server.next_client_id,client_id,1);
    c->id = client_id;
    //保存socket
    c->fd = fd;
    //client别名
    c->name = NULL;
    //初始化缓冲区偏移量
    c->bufpos = 0;
    //初始化缓冲区
    c->querybuf = sdsempty();
    //初始化等待缓冲区
    c->pending_querybuf = sdsempty();
    c->querybuf_peak = 0;
    //初始化协议类型，telnet/redis-cli
    c->reqtype = 0;
    //初始化参数个数
    c->argc = 0;
    //初始化命令参数
    c->argv = NULL;
    //初始化当前命令，最近一次执行的命令
    c->cmd = c->lastcmd = NULL;
    //初始化未读命令数量
    c->multibulklen = 0;
    //初始化读入参数长度
    c->bulklen = -1;
    //初始化已发送字节数
    c->sentlen = 0;
    //初始化client状态
    c->flags = 0;
    //设置client创建时间，最近一次交互时间
    c->ctime = c->lastinteraction = server.unixtime;
    //初始化认证状态
    c->authenticated = 0;
    //初始化复制状态
    c->replstate = REPL_STATE_NONE;
    //从节点是否在向主节点发送ack
    c->repl_put_online_on_ack = 0;
    //初始化复制偏移量
    c->reploff = 0;
    //初始化已读偏移量(主节点视角)
    c->read_reploff = 0;
    //初始化通过ack接收到的偏移量
    c->repl_ack_off = 0;
    //初始化通过ack接收到偏移量用时
    c->repl_ack_time = 0;
    //初始化从节点使用的port
    c->slave_listening_port = 0;
    //初始化从节点ip
    c->slave_ip[0] = '\0';
    //初始化capability
    c->slave_capa = SLAVE_CAPA_NONE;
    //初始化回复链表
    c->reply = listCreate();
    //初始化回复字节数
    c->reply_bytes = 0;
    //初始化输出缓冲区内存限制
    c->obuf_soft_limit_reached_time = 0;
    //设置释放与复制的方法
    listSetFreeMethod(c->reply,freeClientReplyValue);
    listSetDupMethod(c->reply,dupClientReplyValue);
    //初始化阻塞类型
    c->btype = BLOCKED_NONE;
    //初始化阻塞超时时间
    c->bpop.timeout = 0;
    //初始化造成阻塞的key的dict
    c->bpop.keys = dictCreate(&objectKeyPointerValueDictType,NULL);
    //初始化需要解除阻塞的key的dict
    c->bpop.target = NULL;
    //初始化阻塞状态
    c->bpop.numreplicas = 0;
    //初始化目的复制偏移量
    c->bpop.reploffset = 0;
    //初始化全局复制偏移量
    c->woff = 0;
    //监控的key
    c->watched_keys = listCreate();
    //订阅频道
    c->pubsub_channels = dictCreate(&objectKeyPointerValueDictType,NULL);
    //保存匹配模板
    c->pubsub_patterns = listCreate();
    //初始化peerid
    c->peerid = NULL;
    //设置pub/sub释放与匹配方法
    listSetFreeMethod(c->pubsub_patterns,decrRefCountVoid);
    listSetMatchMethod(c->pubsub_patterns,listMatchObjects);
    //将这个客户端加入链表
    if (fd != -1) listAddNodeTail(server.clients,c);
    //初始化client的mstate
    initClientMultiState(c);
    return c;
}
```

断开客户端连接的底层实现

```c
//将client从全局列表中去除，断开socket
//被freeClient()调用
void unlinkClient(client *c) {
    listNode *ln;

    /* If this is marked as current client unset it. */
    //解除当前操作客户端记录
    if (server.current_client == c) server.current_client = NULL;

    /* Certain operations must be done only if the client has an active socket.
     * If the client was already unlinked or if it's a "fake client" the
     * fd is already set to -1. */
    //从客户端链表中删除当前客户端
    if (c->fd != -1) {
        /* Remove from the list of active clients. */
        ln = listSearchKey(server.clients,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients,ln);

        /* Unregister async I/O handlers and close the socket. */
        //删除设置的可读可写时间处理函数
        aeDeleteFileEvent(server.el,c->fd,AE_READABLE);
        aeDeleteFileEvent(server.el,c->fd,AE_WRITABLE);
        //关闭socket
        close(c->fd);
        c->fd = -1;
    }

    /* Remove from the list of pending writes if needed. */
    //如果缓冲区中有内容等待输出，则从等待回复的列表中删除这一client
    if (c->flags & CLIENT_PENDING_WRITE) {
        ln = listSearchKey(server.clients_pending_write,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_pending_write,ln);
        c->flags &= ~CLIENT_PENDING_WRITE;
    }

    /* When client was just unblocked because of a blocking operation,
     * remove it from the list of unblocked clients. */
    //必要时从非阻塞clients中删除此client
    if (c->flags & CLIENT_UNBLOCKED) {
        ln = listSearchKey(server.unblocked_clients,c);
        serverAssert(ln != NULL);
        listDelNode(server.unblocked_clients,ln);
        c->flags &= ~CLIENT_UNBLOCKED;
    }
}

//释放客户端
void freeClient(client *c) {
    listNode *ln;

    /* If it is our master that's beging disconnected we should make sure
     * to cache the state to try a partial resynchronization later.
     *
     * Note that before doing this we make sure that the client is not in
     * some unexpected state, by checking its flags. */
    //释放对象是自己所属主节点模拟的客户端
    if (server.master && c->flags & CLIENT_MASTER) {
        serverLog(LL_WARNING,"Connection with master lost.");
        if (!(c->flags & (CLIENT_CLOSE_AFTER_REPLY|
                          CLIENT_CLOSE_ASAP|
                          CLIENT_BLOCKED|
                          CLIENT_UNBLOCKED)))
        {
           	//保存主节点的client结构，以便重连后进行部分重同步
            replicationCacheMaster(c);
            return;
        }
    }

    /* Log link disconnection with slave */
    //释放对象是从属于自己的从节点
    if ((c->flags & CLIENT_SLAVE) && !(c->flags & CLIENT_MONITOR)) {
        serverLog(LL_WARNING,"Connection with slave %s lost.",
            //获取从节点ip:port
            replicationGetSlaveName(c));
    }

    /* Free the query buffer */
    //清空缓冲区
    sdsfree(c->querybuf);
    sdsfree(c->pending_querybuf);
    c->querybuf = NULL;

    /* Deallocate structures used to block on blocking ops. */
    //清除阻塞占用的结构
    if (c->flags & CLIENT_BLOCKED) unblockClient(c);
    dictRelease(c->bpop.keys);

    /* UNWATCH all the keys */
    //清除client监控的key
    unwatchAllKeys(c);
    listRelease(c->watched_keys);

    /* Unsubscribe from all the pubsub channels */
    //清除pub/sub相关结构与函数
    pubsubUnsubscribeAllChannels(c,0);
    pubsubUnsubscribeAllPatterns(c,0);
    dictRelease(c->pubsub_channels);
    listRelease(c->pubsub_patterns);

    /* Free data structures. */
    //清空回复与参数
    listRelease(c->reply);
    freeClientArgv(c);

    /* Unlink the client: this will close the socket, remove the I/O
     * handlers, and remove references of the client from different
     * places where active clients may be referenced. */
    //断开连接
    unlinkClient(c);

    /* Master/slave cleanup Case 1:
     * we lost the connection with a slave. */
    //清理主从结构信息
    if (c->flags & CLIENT_SLAVE) {
        if (c->replstate == SLAVE_STATE_SEND_BULK) {
            if (c->repldbfd != -1) close(c->repldbfd);
            if (c->replpreamble) sdsfree(c->replpreamble);
        }
        list *l = (c->flags & CLIENT_MONITOR) ? server.monitors : server.slaves;
        ln = listSearchKey(l,c);
        serverAssert(ln != NULL);
        listDelNode(l,ln);
        /* We need to remember the time when we started to have zero
         * attached slaves, as after some time we'll free the replication
         * backlog. */
        if (c->flags & CLIENT_SLAVE && listLength(server.slaves) == 0)
            server.repl_no_slaves_since = server.unixtime;
        refreshGoodSlavesCount();
    }

    /* Master/slave cleanup Case 2:
     * we lost the connection with the master. */
    //从节点与主节点断连，设当前复制状态为REPL_STATE_CONNECT，记录断开时长
    if (c->flags & CLIENT_MASTER) replicationHandleMasterDisconnection();

    /* If this client was scheduled for async freeing we need to remove it
     * from the queue. */
    //从要关闭的client队列中删除这个client
    if (c->flags & CLIENT_CLOSE_ASAP) {
        ln = listSearchKey(server.clients_to_close,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_to_close,ln);
    }

    /* Release other dynamically allocated client structure fields,
     * and finally release the client structure itself. */
    //清除其他对象
    if (c->name) decrRefCount(c->name);
    zfree(c->argv);
    freeClientMultiState(c);
    sdsfree(c->peerid);
    zfree(c);
}
```

执行异步断开连接，主要在主从同步中使用

目的是避免底层函数向客户端输出缓冲区写入数据时，客户端被关闭

```c
//向待关闭客户端队列中加入新的客户端
void freeClientAsync(client *c) {
    if (c->flags & CLIENT_CLOSE_ASAP || c->flags & CLIENT_LUA) return;
    c->flags |= CLIENT_CLOSE_ASAP;
    listAddNodeTail(server.clients_to_close,c);
}

//处理待关闭客户端队列中的客户端
//在serverCron()周期函数中被调用
void freeClientsInAsyncFreeQueue(void) {
    while (listLength(server.clients_to_close)) {
        listNode *ln = listFirst(server.clients_to_close);
        client *c = listNodeValue(ln);

        c->flags &= ~CLIENT_CLOSE_ASAP;
        freeClient(c);
        listDelNode(server.clients_to_close,ln);
    }
}
```

##### 00x05 通信

---

命令读取

```c
//redis-cli协议解析
//设置argc，将解析出的参数存入argv
int processMultibulkBuffer(client *c) {
    char *newline = NULL;
    long pos = 0;
    int ok;
    long long ll;

    if (c->multibulklen == 0) {
        /* The client should have been reset */
        serverAssertWithInfo(c,NULL,c->argc == 0);

        /* Multi bulk length cannot be read without a \r\n */
        newline = strchr(c->querybuf,'\r');
        if (newline == NULL) {
            if (sdslen(c->querybuf) > PROTO_INLINE_MAX_SIZE) {
                addReplyError(c,"Protocol error: too big mbulk count string");
                setProtocolError("too big mbulk count string",c,0);
            }
            return C_ERR;
        }

        /* Buffer should also contain \n */
        if (newline-(c->querybuf) > ((signed)sdslen(c->querybuf)-2))
            return C_ERR;

        /* We know for sure there is a whole line since newline != NULL,
         * so go ahead and find out the multi bulk length. */
        serverAssertWithInfo(c,NULL,c->querybuf[0] == '*');
        ok = string2ll(c->querybuf+1,newline-(c->querybuf+1),&ll);
        if (!ok || ll > 1024*1024) {
            addReplyError(c,"Protocol error: invalid multibulk length");
            setProtocolError("invalid mbulk count",c,pos);
            return C_ERR;
        }

        pos = (newline-c->querybuf)+2;
        if (ll <= 0) {
            sdsrange(c->querybuf,pos,-1);
            return C_OK;
        }

        c->multibulklen = ll;

        /* Setup argv array on client structure */
        if (c->argv) zfree(c->argv);
        c->argv = zmalloc(sizeof(robj*)*c->multibulklen);
    }

    serverAssertWithInfo(c,NULL,c->multibulklen > 0);
    while(c->multibulklen) {
        /* Read bulk length if unknown */
        if (c->bulklen == -1) {
            newline = strchr(c->querybuf+pos,'\r');
            if (newline == NULL) {
                if (sdslen(c->querybuf) > PROTO_INLINE_MAX_SIZE) {
                    addReplyError(c,
                        "Protocol error: too big bulk count string");
                    setProtocolError("too big bulk count string",c,0);
                    return C_ERR;
                }
                break;
            }

            /* Buffer should also contain \n */
            if (newline-(c->querybuf) > ((signed)sdslen(c->querybuf)-2))
                break;

            if (c->querybuf[pos] != '$') {
                addReplyErrorFormat(c,
                    "Protocol error: expected '$', got '%c'",
                    c->querybuf[pos]);
                setProtocolError("expected $ but got something else",c,pos);
                return C_ERR;
            }

            ok = string2ll(c->querybuf+pos+1,newline-(c->querybuf+pos+1),&ll);
            if (!ok || ll < 0 || ll > server.proto_max_bulk_len) {
                addReplyError(c,"Protocol error: invalid bulk length");
                setProtocolError("invalid bulk length",c,pos);
                return C_ERR;
            }

            pos += newline-(c->querybuf+pos)+2;
            if (ll >= PROTO_MBULK_BIG_ARG) {
                size_t qblen;

                /* If we are going to read a large object from network
                 * try to make it likely that it will start at c->querybuf
                 * boundary so that we can optimize object creation
                 * avoiding a large copy of data. */
                sdsrange(c->querybuf,pos,-1);
                pos = 0;
                qblen = sdslen(c->querybuf);
                /* Hint the sds library about the amount of bytes this string is
                 * going to contain. */
                if (qblen < (size_t)ll+2)
                    c->querybuf = sdsMakeRoomFor(c->querybuf,ll+2-qblen);
            }
            c->bulklen = ll;
        }

        /* Read bulk argument */
        if (sdslen(c->querybuf)-pos < (size_t)(c->bulklen+2)) {
            /* Not enough data (+2 == trailing \r\n) */
            break;
        } else {
            /* Optimization: if the buffer contains JUST our bulk element
             * instead of creating a new object by *copying* the sds we
             * just use the current sds string. */
            if (pos == 0 &&
                c->bulklen >= PROTO_MBULK_BIG_ARG &&
                sdslen(c->querybuf) == (size_t)(c->bulklen+2))
            {
                c->argv[c->argc++] = createObject(OBJ_STRING,c->querybuf);
                sdsIncrLen(c->querybuf,-2); /* remove CRLF */
                /* Assume that if we saw a fat argument we'll see another one
                 * likely... */
                c->querybuf = sdsnewlen(NULL,c->bulklen+2);
                sdsclear(c->querybuf);
                pos = 0;
            } else {
                c->argv[c->argc++] =
                    createStringObject(c->querybuf+pos,c->bulklen);
                pos += c->bulklen+2;
            }
            c->bulklen = -1;
            c->multibulklen--;
        }
    }

    /* Trim to pos */
    if (pos) sdsrange(c->querybuf,pos,-1);

    /* We're done when c->multibulk == 0 */
    if (c->multibulklen == 0) return C_OK;

    /* Still not ready to process the command */
    return C_ERR;
}

//处理缓冲区内容，调用以下两个函数
//processInlineBuffer()处理Telnet的请求协议
//processMultibulkBuffer()处理redis-cli请求协议
void processInputBuffer(client *c) {
    server.current_client = c;
    /* Keep processing while there is something in the input buffer */
    while(sdslen(c->querybuf)) {
        /* Return if clients are paused. */
        if (!(c->flags & CLIENT_SLAVE) && clientsArePaused()) break;

        /* Immediately abort if the client is in the middle of something. */
        if (c->flags & CLIENT_BLOCKED) break;

        /* CLIENT_CLOSE_AFTER_REPLY closes the connection once the reply is
         * written to the client. Make sure to not let the reply grow after
         * this flag has been set (i.e. don't process more commands).
         *
         * The same applies for clients we want to terminate ASAP. */
        if (c->flags & (CLIENT_CLOSE_AFTER_REPLY|CLIENT_CLOSE_ASAP)) break;

        /* Determine request type when unknown. */
        if (!c->reqtype) {
            if (c->querybuf[0] == '*') {
                c->reqtype = PROTO_REQ_MULTIBULK;
            } else {
                c->reqtype = PROTO_REQ_INLINE;
            }
        }

        if (c->reqtype == PROTO_REQ_INLINE) {
            if (processInlineBuffer(c) != C_OK) break;
        } else if (c->reqtype == PROTO_REQ_MULTIBULK) {
            if (processMultibulkBuffer(c) != C_OK) break;
        } else {
            serverPanic("Unknown request type");
        }

        /* Multibulk processing could see a <= 0 length. */
        if (c->argc == 0) {
            resetClient(c);
        } else {
            /* Only reset the client when the command was executed. */
            if (processCommand(c) == C_OK) {
                if (c->flags & CLIENT_MASTER && !(c->flags & CLIENT_MULTI)) {
                    /* Update the applied replication offset of our master. */
                    c->reploff = c->read_reploff - sdslen(c->querybuf);
                }

                /* Don't reset the client structure for clients blocked in a
                 * module blocking command, so that the reply callback will
                 * still be able to access the client argv and argc field.
                 * The client will be reset in unblockClientFromModule(). */
                if (!(c->flags & CLIENT_BLOCKED) || c->btype != BLOCKED_MODULE)
                    resetClient(c);
            }
            /* freeMemoryIfNeeded may flush slave output buffers. This may
             * result into a slave, that may be the active client, to be
             * freed. */
            if (server.current_client == NULL) break;
        }
    }
    server.current_client = NULL;
}

//读client输入缓冲区
//被设置为来自client的可读事件的处理函数
#define PROTO_IOBUF_LEN         (1024*16)  /* Generic I/O buffer size */
void readQueryFromClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    client *c = (client*) privdata;
    int nread, readlen;
    size_t qblen;
    UNUSED(el);
    UNUSED(mask);
	
    //默认读长度为16M
    readlen = PROTO_IOBUF_LEN;
    /* If this is a multi bulk request, and we are processing a bulk reply
     * that is large enough, try to maximize the probability that the query
     * buffer contains exactly the SDS string representing the object, even
     * at the risk of requiring more read(2) calls. This way the function
     * processMultiBulkBuffer() can avoid copying buffers to create the
     * Redis Object representing the argument. */
    //对于多条命令，检查并设置要读取的长度与余下的长度
    if (c->reqtype == PROTO_REQ_MULTIBULK && c->multibulklen && c->bulklen != -1
        && c->bulklen >= PROTO_MBULK_BIG_ARG)
    {
        ssize_t remaining = (size_t)(c->bulklen+2)-sdslen(c->querybuf);

        if (remaining < readlen) readlen = remaining;
    }

    //输入缓冲区的大小
    qblen = sdslen(c->querybuf);
    //如果本次输入更大，更新缓冲区峰值
    if (c->querybuf_peak < qblen) c->querybuf_peak = qblen;
    //根据本次读的长度，扩展缓冲区空间
    c->querybuf = sdsMakeRoomFor(c->querybuf, readlen);
    //读至输入缓冲区
    nread = read(fd, c->querybuf+qblen, readlen);
    if (nread == -1) {//读出错
        if (errno == EAGAIN) {
            return;
        } else {
            serverLog(LL_VERBOSE, "Reading from client: %s",strerror(errno));
            freeClient(c);
            return;
        }
    } else if (nread == 0) {//空读
        serverLog(LL_VERBOSE, "Client closed connection");
        freeClient(c);
        return;
    } else if (c->flags & CLIENT_MASTER) {
        //如果当前节点为主节点，将读出的内容复制到pending_querybuf
        /* Append the query buffer to the pending (not applied) buffer
         * of the master. We'll use this buffer later in order to have a
         * copy of the string applied by the last command executed. */
        c->pending_querybuf = sdscatlen(c->pending_querybuf,
                                        c->querybuf+qblen,nread);
    }

    //更新输入缓冲区的空间信息
    sdsIncrLen(c->querybuf,nread);
    //更新最后一次与client交互的时间
    c->lastinteraction = server.unixtime;
    //更新主节点复制偏移量
    if (c->flags & CLIENT_MASTER) c->read_reploff += nread;
    //更新从网络输入的字节数
    server.stat_net_input_bytes += nread;
    //输入缓冲区过长，断开并清理client
    if (sdslen(c->querybuf) > server.client_max_querybuf_len) {
        sds ci = catClientInfoString(sdsempty(),c), bytes = sdsempty();

        bytes = sdscatrepr(bytes,c->querybuf,64);
        serverLog(LL_WARNING,"Closing client that reached max query buffer length: %s (qbuf initial bytes: %s)", ci, bytes);
        sdsfree(ci);
        sdsfree(bytes);
        freeClient(c);
        return;
    }

    /* Time to process the buffer. If the client is a master we need to
     * compute the difference between the applied offset before and after
     * processing the buffer, to understand how much of the replication stream
     * was actually applied to the master state: this quantity, and its
     * corresponding part of the replication stream, will be propagated to
     * the sub-slaves and to the replication backlog. */
    //非主节点，直接处理信息
    if (!(c->flags & CLIENT_MASTER)) {
        processInputBuffer(c);
    //是主节点
    } else {
        //在处理同时要更新复制偏移量
        size_t prev_offset = c->reploff;
        processInputBuffer(c);
        size_t applied = c->reploff - prev_offset;
        if (applied) {
            replicationFeedSlavesFromMasterStream(server.slaves,
                    c->pending_querybuf, applied);
            sdsrange(c->pending_querybuf,applied,-1);
        }
    }
}
```

写入回复

```c
//在多种情况下被设为对client的可写事件的处理函数
#define NET_MAX_WRITES_PER_EVENT (1024*64)
void sendReplyToClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    UNUSED(el);
    UNUSED(mask);
    writeToClient(fd,privdata,1);
}

//将输出缓冲区内容写入socket
int writeToClient(int fd, client *c, int handler_installed) {
    ssize_t nwritten = 0, totwritten = 0;
    size_t objlen;
    sds o;

    //client还有内容要回复
    //循环处理
    while(clientHasPendingReplies(c)) {
        //静态缓冲区中还没发送完成
        if (c->bufpos > 0) {
            //写入
            nwritten = write(fd,c->buf+c->sentlen,c->bufpos-c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            /* If the buffer was sent, set bufpos to zero to continue with
             * the remainder of the reply. */
            //更新偏移量
            if ((int)c->sentlen == c->bufpos) {
                c->bufpos = 0;
                c->sentlen = 0;
            }
        //已发送完成
        } else {
            //处理回复链表中 的内容
            o = listNodeValue(listFirst(c->reply));
            objlen = sdslen(o);
		
            //跳过空对象并将其删除
            if (objlen == 0) {
                listDelNode(c->reply,listFirst(c->reply));
                continue;
            }

            //写入
            nwritten = write(fd, o + c->sentlen, objlen - c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            /* If we fully sent the object on head go to the next one */
            //发送完成就删除节点，重置发送过的数据长度，更新回复链表字节数
            if (c->sentlen == objlen) {
                listDelNode(c->reply,listFirst(c->reply));
                c->sentlen = 0;
                c->reply_bytes -= objlen;
                /* If there are no longer objects in the list, we expect
                 * the count of reply bytes to be exactly zero. */
                if (listLength(c->reply) == 0)
                    serverAssert(c->reply_bytes == 0);
            }
        }
        /* Note that we avoid to send more than NET_MAX_WRITES_PER_EVENT
         * bytes, in a single threaded server it's a good idea to serve
         * other clients as well, even if a very large request comes from
         * super fast link that is always able to accept data (in real world
         * scenario think about 'KEYS *' against the loopback interface).
         *
         * However if we are over the maxmemory limit we ignore that and
         * just deliver as much data as it is possible to deliver.
         *
         * Moreover, we also send as much as possible if the client is
         * a slave (otherwise, on high-speed traffic, the replication
         * buffer will grow indefinitely) */
        //如果本次写入大小超过64M，则会中断
        //但如果服务器使用内存超过设置的maxmemory，则强制继续发送
        if (totwritten > NET_MAX_WRITES_PER_EVENT &&
            (server.maxmemory == 0 ||
             zmalloc_used_memory() < server.maxmemory) &&
            !(c->flags & CLIENT_SLAVE)) break;
    }
    //更新写入到网络的字节数
    server.stat_net_output_bytes += totwritten;
    //读失败
    if (nwritten == -1) {
        if (errno == EAGAIN) {
            nwritten = 0;
        } else {
            serverLog(LL_VERBOSE,
                "Error writing to client: %s", strerror(errno));
            freeClient(c);
            return C_ERR;
        }
    }
    //空读
    if (totwritten > 0) {
        /* For clients representing masters we don't count sending data
         * as an interaction, since we always send REPLCONF ACK commands
         * that take some time to just fill the socket output buffer.
         * We just rely on data / pings received for timeout detection. */
        if (!(c->flags & CLIENT_MASTER)) c->lastinteraction = server.unixtime;
    }
    //发送完成
    if (!clientHasPendingReplies(c)) {
        c->sentlen = 0;
        //解除可读事件
        if (handler_installed) aeDeleteFileEvent(server.el,c->fd,AE_WRITABLE);

        /* Close connection after entire reply has been sent. */
        //如果有回复后立即关闭的flag，则释放client
        if (c->flags & CLIENT_CLOSE_AFTER_REPLY) {
            freeClient(c);
            return C_ERR;
        }
    }
    return C_OK;
}
```

#### redis通信协议

##### 00x06 命令发送格式

---

命令的包装函数跟了很久

先从发送函数开始，跟到写入部分

[redis-cli.c] cliReadReply -> [hiredis.c] redisGetReply ->  [hiredis.c] redisBufferWrite

-> [builtin] write -> 将client结构中的obuf内容写入fd

没有找到包装函数，但发现了输出缓冲区

推测处理函数或其上层函数在cliReadReply上层函数中，有一部分是写入obuf

[redis-cli.c] cliReadReply &lt;- [redis-cli.c] cliSendCommand 

-&gt; [hiredis.c] redisAppendCommandArgv -> [hiredis.c] redisFormatSdsCommandArgv

```c
int redisFormatSdsCommandArgv(sds *target, int argc, const char **argv,
                              const size_t *argvlen)
{
    sds cmd;
    unsigned long long totlen;
    int j;
    size_t len;

    /* Abort on a NULL target */
    if (target == NULL)
        return -1;

    /* Calculate our total size */
    totlen = 1+countDigits(argc)+2;
    for (j = 0; j < argc; j++) {
        len = argvlen ? argvlen[j] : strlen(argv[j]);
        totlen += bulklen(len);
    }

    /* Use an SDS string for command construction */
    cmd = sdsempty();
    if (cmd == NULL)
        return -1;

    /* We already know how much storage we need */
    cmd = sdsMakeRoomFor(cmd, totlen);
    if (cmd == NULL)
        return -1;

    /* Construct command */
    cmd = sdscatfmt(cmd, "*%i\r\n", argc);
    for (j=0; j < argc; j++) {
        len = argvlen ? argvlen[j] : strlen(argv[j]);
        cmd = sdscatfmt(cmd, "$%u\r\n", len);
        cmd = sdscatlen(cmd, argv[j], len);
        cmd = sdscatlen(cmd, "\r\n", sizeof("\r\n")-1);
    }

    assert(sdslen(cmd)==totlen);

    *target = cmd;
    return totlen;
}
```

##### 00x07 命令回复格式

---

ERROR

-ERR 开头

```c
void addReplyErrorLength(client *c, const char *s, size_t len) {
    addReplyString(c,"-ERR ",5);
    addReplyString(c,s,len);
    addReplyString(c,"\r\n",2);
}
```

Status

\+ 开头

```c
void addReplyStatusLength(client *c, const char *s, size_t len) {
    addReplyString(c,"+",1);
    addReplyString(c,s,len);
    addReplyString(c,"\r\n",2);
}
```

Long Long

: 开头

```c
void addReplyLongLong(client *c, long long ll) {
    if (ll == 0)
        addReply(c,shared.czero);
    else if (ll == 1)
        addReply(c,shared.cone);
    else
        addReplyLongLongWithPrefix(c,ll,':');
}
```

Bulk String (大字符串)

$ 开头

```c
void addReplyBulkLen(client *c, robj *obj) {
    size_t len;

    if (sdsEncodedObject(obj)) {
        len = sdslen(obj->ptr);
    } else {
        long n = (long)obj->ptr;

        /* Compute how many bytes will take this integer as a radix 10 string */
        len = 1;
        if (n < 0) {
            len++;
            n = -n;
        }
        while((n = n/10) != 0) {
            len++;
        }
    }

    if (len < OBJ_SHARED_BULKHDR_LEN)
        addReply(c,shared.bulkhdr[len]);
    else
        addReplyLongLongWithPrefix(c,len,'$');
}
```

MutiBulk (数组，可嵌套)

```c
void addReplyMultiBulkLen(client *c, long length) {
    if (length < OBJ_SHARED_BULKHDR_LEN)
        addReply(c,shared.mbulkhdr[length]);
    else
        addReplyLongLongWithPrefix(c,length,'*');
}
```