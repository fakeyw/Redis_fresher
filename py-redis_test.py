import redis
from datetime import datetime

r_conn = redis.Redis(host='192.168.179.128',port=6379,db=0)
#获取与远程（或本地）redis服务的连接

r_conn.set('time_now',datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
t = r_conn.get('time_now')
print(t)