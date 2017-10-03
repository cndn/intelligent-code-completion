#!/usr/bin/python
#coding:utf-8
import os
import datetime
import tarfile
import json
from baidupan.baidupan import BaiduPan



	
def mysql_backup():
	db_host='localhost'
	db_user='root'
	db_password='password'
	mysqldump='/usr/local/mysql/bin/mysqldump'

	#print db_bak_name	
	cmd="%s -u%s  -p%s --database  wordpress >  %s"%(mysqldump,db_user,db_password,db_bak_name)

	if os.popen(cmd):
		tar=tarfile.open(db_bak,'w:bz2')
		tar.add(db_bak_name)
		return "Success"




#mysql_backup()
def blog_backup():
	blog_dir='/data/wordpress/'

	blog_tar=tarfile.open(blog_bak,'w:bz2')
	blog_tar.add(blog_dir)
	return "Success"



def upload_bpcs(upload_dir,upload_file,del_file):
	access_token="access"#从百度云获取
	disk=BaiduPan(access_token)
	bpcs_dir='/apps/bpcs_uploader/'
	if not disk.meta(bpcs_dir+upload_dir):
		disk.mkdir(bpcs_dir+upload_dir)
	#查看使用情况
	#print disk.quota()
	disk.upload(upload_file, path=bpcs_dir+upload_dir+upload_file,ondup='overwrite') #上传文件，如果存在，直接覆盖
	if disk.meta(bpcs_dir+upload_dir+del_file): #删除历史文件
		disk.rm(bpcs_dir+upload_dir+del_file)

if __name__ == '__main__':

	today=datetime.datetime.now().date()
	del_date=today-datetime.timedelta(days=7)
	back_dir='/data/backup/'
	logfile=back_dir+'bpcs.log'
	os.chdir(back_dir)

	#mysql
	db_bak_name='mysql-'+str(today)+'.sql'
	db_bak='mysql-'+str(today)+'.tar.bz2'
	db_del='mysql-'+str(del_date)+'.tar.bz2'

	#blog
	blog_bak='blog-'+str(today)+'.tar.bz2'
	blog_del='blog-'+str(del_date)+'.tar.bz2'

	log=open(logfile,'a')
	log.write("##########%s###########\n"%datetime.datetime.now())
	try:
		if os.path.exists(back_dir):
			os.chdir(back_dir)
		else:
			os.mkdir(back_dir)
			os.chdir(back_dir)
		
		if mysql_backup():
			upload_bpcs('mysql/', db_bak, db_del)			
			log.write('Mysql upload Success !\n')
			os.system('rm -rf %s %s '%(db_bak_name,db_bak))
		else:
			log.write('mysqldump failed !\n')
		if blog_backup():
			upload_bpcs('blog/', blog_bak, blog_del)
			log.write('blog upload Success !\n')
			os.system('rm -rf %s'%(blog_bak))
		else :
			log.write('blog backup failed !\n')
		log.close()
	except Exception, e:
		print e
		



	


