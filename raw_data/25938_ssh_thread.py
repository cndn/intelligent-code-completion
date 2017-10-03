#!/usr/bin/python
#coding:utf-8
import paramiko
import sys
import datetime
import threading
import Queue
import getopt

def usage():

	print """

              -h,-H,--help         帮助页面 
              -C, --cmd            执行命令模式 
              -M, --command        执行具体命令 
              -S, --sendfile       传输文件模式 
              -L, --localpath      本地文件路径 
              -R, --remotepath     远程服务器路径 

	     IP列表格式:

   	     IP地址		用户名     密码     端口
	     192.168.1.1        root	  123456    22

      	e.g.
              批量执行命令格式： -C "IP列表" -M '执行的命令'
              批量传送文件：     -S "IP列表" -L "本地文件路径" -R "远程文件路径"
	      错误日志文件：$PWD/ssh_errors.log

"""

def ssh(queue_get,cmd):
	try:
		hostip=queue_get[0]
                username=queue_get[1]
                password=queue_get[2]
                port=queue_get[3]
        	s=paramiko.SSHClient()
       	 	s.load_system_host_keys()
        	s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
       		s.connect(hostname=hostip,port=port,username=username, password=password)
        	stdin,stdout,stderr=s.exec_command(cmd)
        	print "\033[42m---------------------------------%s---------------------------\033[0m \n %s" %(hostip,stdout.read())
        	s.close()
	except Exception,ex:
        	print "\033[42m---------------------------------%s---------------------------\033[0m\n %s : \t%s" %(hostip,hostip,ex)
                #print "\n",hostip,":\t",ex,"\n"
		ssh_errors=open("ssh_errors.log","a")
		ssh_errors.write("%s\t%s:\t%s\n"%(now,hostip,ex))
		ssh_errors.close()
                pass
def sftp(queue_get,localpath,remotepath):
	try:
		hostip=queue_get[0]
		username=queue_get[1]
                password=queue_get[2]
                port=int(queue_get[3])
 		t=paramiko.Transport((hostip,port))
               	t.connect(username=username,password=password)
                sftp=paramiko.SFTPClient.from_transport(t)
		sftp.put(localpath,remotepath)
		print "Upload file %s to %s : %s: %s" %(localpath,hostip,remotepath,now)
		sftp.close()
		t.close()
        except Exception,ex:
      		print "\n",hostip,":\t",ex,"\n"
               	ssh_errors=open("ssh_errors.log","a")
               	ssh_errors.write("%s\t%s:\t%s\n"%(now,hostip,ex))
               	ssh_errors.close()
               	pass

if __name__ == '__main__':
	try:
		opts,args= opts, args = getopt.getopt(sys.argv[1:], "(hH)C:M:S:L:R:", ["help","cmd=","command=","sendfile=","localpath=","remotepath="])
		now=datetime.datetime.now()
		if   len(sys.argv) == 1 :
			usage()	
			sys.exit()
		if sys.argv[1] in ("-h","-H","--help"):
			usage()
			sys.exit()
		elif sys.argv[1] in ("-C","--cmd"):
			for opt,arg in opts:
				if opt in ("-C","--cmd"):
					iplist=arg
				if opt in ("-M","--command="):
					cmd=arg
			
			file=open(iplist)
			threads = []
               		myqueue = Queue.Queue(maxsize = 0)
			for l in file.readlines():
    				if  len(l)==1 or  l.startswith('#'):
		       			continue
				f=l.split()
				myqueue.put(f)
			file.close()
			for x in xrange(0,myqueue.qsize()):
				if myqueue.empty():
                            		break
                       		mutex = threading.Lock()
                       	 	mutex.acquire()
                        	mutex.release()
                        	threads.append(threading.Thread(target=ssh, args=(myqueue.get(),cmd)))
               		for t in threads:
                       		t.start()
                       		t.join()
		elif sys.argv[1] in ("-S","--sendfile"):
			for opt,arg in opts:
				if opt in ("-S","--sendfile"):
					iplist=arg
				if opt in ("-L","--localpath="):
					localpath=arg
				if opt in ("-R","--remotepath="):
					remotepath=arg

			file=open(iplist)
			threads = []
               		myqueue = Queue.Queue(maxsize = 0)
			for l in file.readlines():
    				if  len(l)==1 or  l.startswith('#'):
		       			continue
				f=l.split()
				myqueue.put(f)
			file.close()
			for x in xrange(0,myqueue.qsize()):
				if myqueue.empty():
                            		break
                       		mutex = threading.Lock()
                       	 	mutex.acquire()
                        	mutex.release()
                        	threads.append(threading.Thread(target=sftp, args=(myqueue.get(),localpath,remotepath)))
               		for t in threads:
                       		t.start()
                       		t.join()
		
		else:
			print "\033[31m非法参数，请重新输入！\033[0m"
			#usage()
	except Exception,ex:
		usage()
		print ex
