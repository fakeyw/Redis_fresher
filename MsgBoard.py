from flask import Flask
import redis
from urllib import parse

r_conn = redis.Redis(host='192.168.179.128',port=6379,password='111111',db=0)
Mboard = Flask(__name__)

@Mboard.route(methods=['GET'],'/')
def main_page():
	msgs = r_conn.lrange('t_list',0,r_conn.llen('t_list')) #get all msg
	return resp

@Mboard.route(methods=['GET'],'/op')
def op_page():
	return resp
	
@Mboard.route(methods=['POST'],'/add')
def add():
	title = request.form['title']
	content = request.form['ctt']
	msg = parse.quote(title)+' '+parse.quote(content)
	r_conn.lpush('msg_list',msg)
	return True
	
'''
>>> r_conn.lpush('t_list',2)
2
>>> r_conn.lrange('t_list',0,r_conn.llen('t_list'))
[b'2', b'1']
'''
if __name__ == '__main__':
    app.run(port=30000,debug=True)