from flask import Flask
import redis
from urllib import parse

r_conn = redis.Redis(host='xxx.xxx.xxx.xxx',port=7777,db=0)
Mboard = Flask(__name__)

@Mboard.route('/',methods=['GET','POST'])
def main_page():
	print(1)
	msgs = r_conn.lrange('msg_list',0,r_conn.llen('msg_list')) #get all msg
	patt ='''
	<div class='msg'>
		{msg}
	</div>
	'''
	resp = ''
	for i in msgs:
		resp+=patt.format(msg=i.decode('utf-8'))
	return resp

@Mboard.route('/op',methods=['GET'])
def op_page():
	return 0
	
@Mboard.route('/add',methods=['POST'])
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
    Mboard.run(port=30000,debug=True)