#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
cur_dir=$(pwd)
ins_dir=/NoGFW

# CHECK: check_system check_network check_folder check_file check_service check_prots
# PREHEAT: preheat_info preheat_sys preheat_SID
# INSTALL: install_baisc install_depends install_mysql install_php install_nginx install_nodejs install_redis install_pfring
# CODING: coding_mysql coding_server coding_nogfw coding_web
# SETTING: setting_default setting_startup
# CLEAN: clean_all

function check_system()
{
	# Check system version
	sbd=$(cat /etc/issue.net | grep Ubuntu | awk '{print $2}')
	sbd=${sbd%.*}
	if [[ $sbd = "14.04" ]]; then
		echo "System check is OK."
	else
		echo "System version is wrong."
		exit
	fi
}

function check_network()
{
	# Check network
	nbd=$(curl -I -s http://www.baidu.com/ | grep HTTP | awk '{print $2}')
	if [[ $nbd = 200 ]]; then
		echo "Network check is OK."
	else
		echo "Network check is wrong."
		exit
	fi
}

function check_folder()
{
	# Check folder
	cd $cur_dir
	if [[ -d default ]]; then
		echo "default is find."
		exit
	else
		mkdir default
	fi
	if [[ -d build ]]; then
		echo "build is find."
	else
		echo "build is no find."
		exit
	fi
	if [[ -d conf ]]; then
		echo "conf is find."
	else
		echo "conf is no find."
		exit
	fi
	if [[ -d server ]]; then
		echo "server is find."
	else
		echo "server is no find."
		exit
	fi
	if [[ -d database ]]; then
		echo "database is find."
	else
		echo "database is no find."
		exit
	fi
	if [[ -d web ]]; then
		echo "web is find."
	else
		echo "web is no find."
		exit
	fi
	if [[ -d src ]]; then
		echo "src is find."
	else
		echo "src is no find."
		exit
	fi
}

function check_file()
{
	cd $cur_dir
	cp ./src/* /tmp
	cd /tmp
	if [ -s php-5.4.36.tar.gz ]; then
		echo "php-5.4.36.tar.gz [found]"
	else
		echo "php-5.4.36.tar.gz [not found]"
		exit
	fi

	if [ -s pcre-8.12.tar.gz ]; then
		echo "pcre-8.12.tar.gz [found]"
	else
		echo "pcre-8.12.tar.gz [not found]"
		exit
	fi

	if [ -s nginx-1.6.2.tar.gz ]; then
		echo "nginx-1.6.2.tar.gz [found]"
	else
		echo "nginx-1.6.2.tar.gz [not found]"
		exit
	fi

	if [ -s libiconv-1.14.tar.gz ]; then
		echo "libiconv-1.14.tar.gz [found]"
	else
		echo "libiconv-1.14.tar.gz [not found]"
		exit
	fi

	if [ -s libmcrypt-2.5.8.tar.gz ]; then
		echo "libmcrypt-2.5.8.tar.gz [found]"
	else
		echo "libmcrypt-2.5.8.tar.gz [not found]"
		exit
	fi

	if [ -s libxml2-2.7.8.tar.gz ]; then
		echo "libxml2-2.7.8.tar.gz [found]"
	else
		echo "libxml2-2.7.8.tar.gz [not found]"
		exit
	fi

	if [ -s freetype-2.4.12.tar.gz ]; then
		echo "freetype-2.4.12.tar.gz [found]"
	else
		echo "freetype-2.4.12.tar.gz [not found]"
		exit
	fi

	if [ -s autoconf-2.69.tar.gz ]; then
		echo "autoconf-2.69.tar.gz [found]"
	else
		echo "autoconf-2.69.tar.gz [not found]"
		exit
	fi

	if [ -s redis-2.2.5.tar.gz ]; then
		echo "redis-2.2.5.tar.gz [found]"
	else
		echo "redis-2.2.5.tar.gz [not found]"
		exit
	fi

	if [ -s PF_RING.tar.gz ]; then
		echo "PF_RING.tar.gz [found]"
	else
		echo "PF_RING.tar.gz [not found]"
		exit
	fi

	if [ -s node-v0.10.35.tar.gz ]; then
		echo "node-v0.10.35.tar.gz [found]"
	else
		echo "node-v0.10.35.tar.gz [not found]"
		exit
	fi

	if [ -s init.d.nginx ]; then
		echo "init.d.nginx [found]"
	else
		echo "init.d.nginx [not found]"
		exit
	fi

	if [ -s ZendGuardLoader-70429-PHP-5.4-linux-glibc23-i386.tar.gz ]; then
		echo "ZendGuardLoader-70429-PHP-5.4-linux-glibc23-i386.tar.gz [found]"
	else
		echo "ZendGuardLoader-70429-PHP-5.4-linux-glibc23-i386.tar.gz [not found]"
		exit
	fi

	if [ -s ZendGuardLoader-70429-PHP-5.4-linux-glibc23-x86_64.tar.gz ]; then
		echo "ZendGuardLoader-70429-PHP-5.4-linux-glibc23-x86_64.tar.gz [found]"
	else
		echo "ZendGuardLoader-70429-PHP-5.4-linux-glibc23-x86_64.tar.gz [not found]"
		exit
	fi
	}

function preheat_write_baisc()
{
	cd $cur_dir
	echo "hostname NoGFW"$1 >>$SID
	echo "system "$2 >>$SID
	echo "root "$3 >>$SID
	echo "mysql "$4 >>$SID
}

function preheat_write_intface()
{
	cd $cur_dir
	if [[ $1 = 7 ]]; then
		echo "interface sfp1 "$2  >>$SID
	elif [[ $1 = 8 ]]; then
		echo "interface sfp2 "$2  >>$SID
	else
		echo "interface eth"$1" "$2  >>$SID
	fi
}

function preheat_info()
{
	cd $cur_dir
	mv /etc/apt/sources.list /etc/apt/sources.list.bak
	cp conf/sources.list /etc/apt/sources.list
	apt-get update
	apt-get -y install binutils binutils-multiarch
	inum=$(ifconfig -a | grep HWaddr | wc -l)
	tnum=$(date +%y%m)
	spwd=$(cat /dev/urandom | sed 's/[^a-zA-Z0-9]//g' | strings -n 8 | head -n 1)
	rpwd=$(cat /dev/urandom | sed 's/[^a-zA-Z0-9]//g' | strings -n 8 | head -n 1)
	mpwd=$(cat /dev/urandom | sed 's/[^a-zA-Z0-9]//g' | strings -n 8 | head -n 1)
	if [[ $inum = 4 ]] || [[ $inum = 6 ]] || [[ $inum = 8 ]]; then
		echo "interface test ok."
	else
		echo "interface test not ok."
		exit
	fi
	if [[ ! -n "$tnum" ]]; then
		echo "MFD test not ok."
		exit
	else
		echo "MFD test ok."
	fi
	if [[ ! -n "$spwd" ]]; then
		echo "sys passwd test not ok."
		exit
	else
		echo "sys passwd test ok."
	fi
	if [[ ! -n "$rpwd" ]]; then
		echo "mysql root test not ok."
		exit
	else
		echo "mysql root test ok."
	fi
	if [[ ! -n "$mpwd" ]]; then
		echo "mysql passwd test not ok."
		exit
	else
		echo "mysql passwd test ok."
	fi
}

function preheat_SID()
{
	for (( i = 0; i < 9999; i++ )); do
		rsn=$RANDOM
		i=$rsn
	done
	SID="SN"$inum$tnum$rsn
	if [[ ! -n "$SID" ]]; then
		echo "SID test not ok."
		exit
	else
		echo "SID test ok."
	fi
	if [[ ! -n "$rsn" ]]; then
		echo "rsn test not ok."
		exit

	else
		echo "rsn test ok."
	fi
	if [[ -s $SID ]]; then
		echo 'SID is repeat.'
		exit
	fi
}

function preheat_write()
{
	preheat_write_baisc $rsn $spwd $rpwd $mpwd
	ifconfig -a | grep HWaddr | awk '{print $5}' | sort -n>/tmp/HWaddr
	opt=$(cat /tmp/HWaddr | wc -l)
	if [[ $opt > 6 ]]; then
		eos=$(cat /tmp/HWaddr | head -n 1)
		mac=${eos:0:14}
		soe=$(cat /tmp/HWaddr | grep $mac | wc -l)
		if [[ $soe = 2 ]]; then
			for (( i = 1; i < 3; i++ ));
			do
				h1=$(cat /tmp/HWaddr | head -n 1)
				sed -i "s/$h1//g" /tmp/HWaddr
				sed -i '/^$/d' /tmp/HWaddr
				echo $h1 >>/tmp/HWaddr
			done
		fi
		n=1
		while read LINE
		do
			preheat_write_intface $n $LINE
			n=$(($n + 1))
		done </tmp/HWaddr
		rm -fr /tmp/HWaddr
	else
		n=1
		while read LINE
		do
			preheat_write_intface $n $LINE
			n=$(($n + 1))
		done </tmp/HWaddr
		rm -fr /tmp/HWaddr
	fi
}

function install_baisc_inte()
{
	cd $cur_dir
	echo "allow-hotplug "$1 >>./default/interfaces
	echo "iface "$1" inet manual" >>./default/interfaces
	echo "" >>./default/interfaces
}

function install_baisc_rule()
{
	echo SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{address}==\"$2\", ATTR{dev_id}==\"0x0\", ATTR{type}==\"1\", KERNEL==\"eth*\", NAME=\"$1\" >>/etc/udev/rules.d/70-persistent-net.rules
	echo "" >>/etc/udev/rules.d/70-persistent-net.rules
}

function install_baisc()
{
	cd $cur_dir
	apt-get update
	apt-get upgrade -y
	apt-get autoremove -y
	apt-get -fy install
	for packages in m4 cpp g++ gcc tar vim zip cron curl file flex gawk less make nano re2c wget bison bzip2 cmake p7zip patch unrar unzip zlibc rcconf zlib1g libpq5 mcrypt gettext libpng3 libtool libxml2 numactl openssl autoconf automake binutils libpcre3 libcurl3 diffutils e2fsprogs libc6-dev libjpeg62 libmhash2 libpq-dev libbz2-1.0 libbz2-dev libssl-dev libzip-dev zlib1g-dev libpng-dev libperl-dev libpng12-0 libcap-dev libltdl-dev libncurses5 libpcrecpp0 libjpeg-dev libxml2-dev libevent-dev libglib2.0-0 libpcre3-dev libsasl2-dev libltdl3-dev libpng12-dev libmhash-dev libfreetype6 libmcrypt-dev libjpeg62-dev libglib2.0-dev debian-keyring build-essential libncurses5-dev ca-certificates libfreetype6-dev libcurl4-gnutls-dev libcurl4-openssl-dev debian-archive-keyring;
	do apt-get install -y $packages --force-yes;apt-get -fy install;apt-get -y autoremove; done

	# Synchronization time
	rm -rf /etc/localtime
	ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	apt-get install -y ntpdate
	ntpdate -u pool.ntp.org
	date

	# Disable SeLinux
	if [ -s /etc/selinux/config ]; then
	sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
	fi

	# Config hostname
	hname=$(cat $cur_dir/$SID | grep hostname | awk '{print $2}')
	hostname $hname
	sed -i "s/^127.0.1.1.*/127.0.1.1       $hname/g" /etc/hosts
	echo $hname >/etc/hostname

	# Config ssh
	sed -i 's/^PermitRootLogin/\#PermitRootLogin/g' /etc/ssh/sshd_config
	sed -i 's/^Port 22/Port 32768/g' /etc/ssh/sshd_config
	service ssh restart

	# Config interface
	cd $cur_dir
	cat $SID | grep interface >/tmp/inttomac
	cp ./conf/interfaces ./default/
	echo "" >/etc/udev/rules.d/70-persistent-net.rules
	while read LINE
	do
		n=$(echo $LINE | awk '{print $2}')
		m=$(echo $LINE | awk '{print $3}')
		install_baisc_inte $n
		install_baisc_rule $n $m
	done </tmp/inttomac
	rm -fr /tmp/inttomac

	# Config mgr interface
	cd $cur_dir
	echo "auto eth1:1" >>./default/interfaces
	echo "iface eth1:1 inet static" >>./default/interfaces
	echo "address 192.168.88.88" >>./default/interfaces
	echo "netmask 255.255.255.0" >>./default/interfaces
	echo "gateway 192.168.88.254" >>./default/interfaces
	echo "" >>./default/interfaces
	echo "auto eth1:6" >>./default/interfaces
	echo "iface eth1:6 inet static" >>./default/interfaces
	echo "address 8.8.8.8" >>./default/interfaces
	echo "netmask 255.255.255.252" >>./default/interfaces
}

function install_depends()
{
	cd /tmp
	tar zxf autoconf-2.69.tar.gz
	cd autoconf-2.69/
	./configure --prefix=/usr/local/autoconf-2.69
	make && make install
	cd ../

	tar zxf libiconv-1.14.tar.gz
	cd libiconv-1.14/
	./configure
	make && make install
	cd ../

	cd /tmp
	tar zxf libmcrypt-2.5.8.tar.gz
	cd libmcrypt-2.5.8/
	./configure
	make && make install

	ldconfig

	cd libltdl/
	./configure --enable-ltdl-install
	make && make install
	cd ../../

	ln -s /usr/local/lib/libmcrypt.la /usr/lib/libmcrypt.la
	ln -s /usr/local/lib/libmcrypt.so /usr/lib/libmcrypt.so
	ln -s /usr/local/lib/libmcrypt.so.4 /usr/lib/libmcrypt.so.4
	ln -s /usr/local/lib/libmcrypt.so.4.4.8 /usr/lib/libmcrypt.so.4.4.8

	ldconfig

	cd /tmp
	tar zxf libxml2-2.7.8.tar.gz
	cd libxml2-2.7.8/
	./configure --prefix=/usr
	make && make install
	cd ../

	cd /tmp
	tar zxf freetype-2.4.12.tar.gz
	cd freetype-2.4.12/
	./configure --prefix=/usr/local/freetype
	make && make install
	cd ../
	echo "/usr/local/freetype/lib" > /etc/ld.so.conf.d/freetype.conf
	
	ldconfig
	
	ln -sf /usr/local/freetype/include/freetype2 /usr/local/include
	ln -sf /usr/local/freetype/include/ft2build.h /usr/local/include

	if [ `getconf WORD_BIT` = '32' ] && [ `getconf LONG_BIT` = '64' ] ; then
	        ln -s /usr/lib/x86_64-linux-gnu/libpng* /usr/lib/
	        ln -s /usr/lib/x86_64-linux-gnu/libjpeg* /usr/lib/
	else
	        ln -s /usr/lib/i386-linux-gnu/libpng* /usr/lib/
	        ln -s /usr/lib/i386-linux-gnu/libjpeg* /usr/lib/
	fi

	ulimit -v unlimited

	if [ ! `grep -l "/lib"    '/etc/ld.so.conf'` ]; then
		echo "/lib" >> /etc/ld.so.conf
	fi

	if [ ! `grep -l '/usr/lib'    '/etc/ld.so.conf'` ]; then
		echo "/usr/lib" >> /etc/ld.so.conf
	fi

	if [ -d "/usr/lib64" ] && [ ! `grep -l '/usr/lib64'    '/etc/ld.so.conf'` ]; then
		echo "/usr/lib64" >> /etc/ld.so.conf
	fi

	if [ ! `grep -l '/usr/local/lib'    '/etc/ld.so.conf'` ]; then
		echo "/usr/local/lib" >> /etc/ld.so.conf
	fi

	ldconfig

	echo "* soft nproc 65535" >>/etc/security/limits.conf
	echo "* hard nproc 65535" >>/etc/security/limits.conf
	echo "* soft nofile 65535" >>/etc/security/limits.conf
	echo "* hard nofile 65535" >>/etc/security/limits.conf

	echo "fs.file-max=65535" >> /etc/sysctl.conf
	echo "kernel.msgmax=1048576" >> /etc/sysctl.conf
	echo "kernel.msgmnb=16777216" >> /etc/sysctl.conf
}

function install_mysql()
{
	mysqlrootpwd=$(cat $cur_dir/$SID | grep root | awk '{print $2}')
	mysqlpwd=$(cat $cur_dir/$SID | grep mysql | awk '{print $2}')

	echo "mysql-server-5.5 mysql-server/root_password password $mysqlrootpwd" >/tmp/mysql.preseed
	echo "mysql-server-5.5 mysql-server/root_password_again password $mysqlrootpwd" >>/tmp/mysql.preseed
	cat /tmp/mysql.preseed | sudo debconf-set-selections
	rm /tmp/mysql.preseed
	apt-get -y install mysql-server

cat > /tmp/mysql_sec_script<<EOF
CREATE DATABASE NoGFW;
use mysql;
UPDATE user SET Password=password('$mysqlrootpwd')WHERE User='root';
delete from user where not (user='root');
delete from user where user='root' and Host='ubuntu';
delete from user where user='root' and Host='::1';
use NoGFW;
grant all privileges on NoGFW.* to NoGFW@localhost identified by '$mysqlpwd';
flush privileges;
EOF

	mysql -u root -p$mysqlrootpwd -h localhost < /tmp/mysql_sec_script
	rm -f /tmp/mysql_sec_script
	/etc/init.d/mysql restart
}

function install_php()
{
	cd /tmp
	export PHP_AUTOCONF=/usr/local/autoconf-2.13/bin/autoconf
	export PHP_AUTOHEADER=/usr/local/autoconf-2.13/bin/autoheader
	tar zxf php-5.4.36.tar.gz
	cd php-5.4.36/
	./configure --prefix=/usr/local/php --with-config-file-path=/usr/local/php/etc --enable-fpm --with-fpm-user=www --with-fpm-group=www --with-mysql --with-mysqli --with-pdo-mysql --with-iconv-dir --with-freetype-dir --with-jpeg-dir --with-png-dir --with-zlib --with-libxml-dir=/usr --enable-xml --disable-rpath --enable-magic-quotes --enable-safe-mode --enable-bcmath --enable-shmop --enable-sysvsem --enable-inline-optimization --with-curl --enable-mbregex --enable-mbstring --with-mcrypt --enable-ftp --with-gd --enable-gd-native-ttf --with-openssl --with-mhash --enable-pcntl --enable-sockets --with-xmlrpc --enable-zip --enable-soap --without-pear --with-gettext --disable-fileinfo

	make ZEND_EXTRA_LIBS='-liconv'
	make install

	rm -f /usr/bin/php
	ln -s /usr/local/php/bin/php /usr/bin/php
	ln -s /usr/local/php/bin/phpize /usr/bin/phpize
	ln -s /usr/local/php/sbin/php-fpm /usr/bin/php-fpm

	echo "Copy new php configure file."
	mkdir -p /usr/local/php/etc
	cp php.ini-production /usr/local/php/etc/php.ini

	cd /tmp
	# php extensions
	echo "Modify php.ini......"
	sed -i 's/post_max_size = 8M/post_max_size = 50M/g' /usr/local/php/etc/php.ini
	sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 50M/g' /usr/local/php/etc/php.ini
	sed -i 's/;date.timezone =/date.timezone = PRC/g' /usr/local/php/etc/php.ini
	sed -i 's/short_open_tag = Off/short_open_tag = On/g' /usr/local/php/etc/php.ini
	sed -i 's/; cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /usr/local/php/etc/php.ini
	sed -i 's/; cgi.fix_pathinfo=0/cgi.fix_pathinfo=0/g' /usr/local/php/etc/php.ini
	sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /usr/local/php/etc/php.ini
	sed -i 's/max_execution_time = 30/max_execution_time = 300/g' /usr/local/php/etc/php.ini
	sed -i 's/register_long_arrays = On/;register_long_arrays = On/g' /usr/local/php/etc/php.ini
	sed -i 's/magic_quotes_gpc = On/;magic_quotes_gpc = On/g' /usr/local/php/etc/php.ini
	sed -i 's/disable_functions =.*/disable_functions = passthru,exec,system,chroot,scandir,chgrp,chown,shell_exec,proc_open,proc_get_status,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server/g' /usr/local/php/etc/php.ini

	echo "Install ZendGuardLoader for PHP 5.4"
	if [ `getconf WORD_BIT` = '32' ] && [ `getconf LONG_BIT` = '64' ] ; then
		tar zxvf ZendGuardLoader-70429-PHP-5.4-linux-glibc23-x86_64.tar.gz
		mkdir -p /usr/local/zend/
		\cp ZendGuardLoader-70429-PHP-5.4-linux-glibc23-x86_64/php-5.4.x/ZendGuardLoader.so /usr/local/zend/ 
	else
		tar zxvf ZendGuardLoader-70429-PHP-5.4-linux-glibc23-i386.tar.gz
		mkdir -p /usr/local/zend/
		\cp ZendGuardLoader-70429-PHP-5.4-linux-glibc23-i386/php-5.4.x/ZendGuardLoader.so /usr/local/zend/
	fi

	echo "Write ZendGuardLoader to php.ini......"
cat >>/usr/local/php/etc/php.ini<<EOF
;eaccelerator

;ionCube

[Zend Optimizer] 
zend_extension=/usr/local/zend/ZendGuardLoader.so
zend_loader.enable=1
zend_loader.disable_licensing=0
zend_loader.obfuscation_level_support=3
zend_loader.license_path=
EOF

	echo "Creating new php-fpm configure file......"
cat >/usr/local/php/etc/php-fpm.conf<<EOF
[global]
pid = /usr/local/php/var/run/php-fpm.pid
error_log = /usr/local/php/var/log/php-fpm.log
log_level = notice

[www]
listen = /tmp/php-cgi.sock
listen.backlog = -1
listen.allowed_clients = 127.0.0.1
listen.owner = www
listen.group = www
listen.mode = 0666
user = www
group = www
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 6
request_terminate_timeout = 100
request_slowlog_timeout = 0
slowlog = var/log/slow.log
EOF

	echo "Copy php-fpm init.d file......"
	cp /tmp/php-5.4.36/sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm
	chmod +x /etc/init.d/php-fpm
}

function install_nginx()
{
	groupadd www
	useradd -s /sbin/nologin -g www www
	cd /tmp
	tar zxf pcre-8.12.tar.gz
	cd pcre-8.12/
	./configure
	make && make install
	cd ../

	ldconfig

	tar zxf nginx-1.6.2.tar.gz
	cd nginx-1.6.2/
	sed -i 's/nginx" CRLF/NoGFW" CRLF/g' ./src/http/ngx_http_header_filter_module.c
	sed -i 's/1006002/5001008/g' ./src/core/nginx.h
	sed -i 's/1.6.2/5.1.8/g' ./src/core/nginx.h
	sed -i 's/nginx\//nogfw\//g' ./src/core/nginx.h
	sed =i 's/"NGINX"/"NoGFW"/g' ./src/core/nginx.h
	./configure --user=www --group=www --prefix=/usr/local/nginx --with-http_stub_status_module --with-http_ssl_module --with-http_gzip_static_module --with-ipv6
	make && make install
	cd ../

	ln -s /usr/local/nginx/sbin/nginx /usr/bin/nginx
	cp init.d.nginx /etc/init.d/nginx
	chmod +x /etc/init.d/nginx

	rm -f /usr/local/nginx/conf/nginx.conf
	cd $cur_dir/conf
	cp nginx.conf /usr/local/nginx/conf/nginx.conf

	mkdir -p /NoGFW/
	mkdir -p /NoGFW/www/
	mkdir -p /NoGFW/logs
	chown -R www:www /NoGFW/
}

function install_nodejs()
{
	apt-get -y install libmysqlclient-dev
	cd /tmp
	tar zxf node-v0.10.35.tar.gz
	cd node-v0.10.35
	./configure --prefix=/usr/local/nodejs
	make && make install
	ln -s /usr/local/nodejs/bin/node /usr/bin/node
	ln -s /usr/local/nodejs/bin/npm /usr/bin/npm
}

function install_pfring_kernel()
{
	cd /tmp
	tar zxf PF_RING.tar.gz
	cd PF_RING/kernel
	./configure
	make && make install
}

function install_pfring_libpcap()
{
	apt-get -y install libnuma-dev
	cd /tmp
	cd PF_RING/userland/lib
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
	export LIBS='-L/usr/local/lib'
	./configure
	make && make install
	cd /tmp
	cd PF_RING/userland/libpcap
	sed -i 's/2\*1024\*1024/10\*1024\*1024/g' pcap-linux.c
	./configure
	make && make install
}

function install_pfring_driver()
{
	int=$(ifconfig | grep Link | awk '{print $1}' | grep -v -E ":|lo" | grep 1)
	for ide in $int; do
		ver=$(ethtool -i $ide | grep driver | awk '{print $2}')
		if [[ $ide = e1000 ]]; then
			ide_dir=PF_RING/drivers/DNA/e1000-8.0.35-DNA/src
		elif [[ $ide = e1000e ]]; then
			ide_dir=PF_RING/drivers/ZC/intel/e1000e/e1000e-3.0.4.1-zc/src
		elif [[ $ide = igb ]]; then
			ide_dir=PF_RING/drivers/ZC/intel/igb/igb-5.2.5-zc/src
		elif [[ $ide = ixgbe ]]; then
			ide_dir=PF_RING/drivers/ZC/intel/ixgbe/ixgbe-3.22.3-zc/src
		fi
		cd /tmp
		cd $ide_dir
		make && make install
	done
}

function install_pfring()
{
	install_pfring_kernel
	install_pfring_libpcap
	install_pfring_driver
}

function coding_mysql()
{
	cd $cur_dir
	cp database/alldata.sql /tmp/alldata.sql
	if [[ $inum = 6 ]]; then
		cp database/data6.sql /tmp/data6.sql
	elif [[ $inum = 8 ]]; then
		cp database/data6.sql /tmp/data6.sql
	fi
	sed -i "s/123456/$SID/g" /tmp/data*.sql
	sed -i "s/bodao/$hname/g" /tmp/data*.sql
	sed -i "s/server/NoGFW$inum000/g" /tmp/data*.sql
#	sed -i "s///g" /tmp/data*.sql
}


function coding_server()
{
	cd $cur_dir
	if [[ -d $ins_dir/srv ]]; then
		rm -fr $ins_dir/srv
		mkdir $ins_dir/srv
	else
		mkdir $ins_dir/srv
	fi
	cp server/* $ins_dir/srv
	sed -i "s/mysqlpwd/$mysqlpwd/g" $ins_dir/srv/config.js
}


function coding_nogfw()
{
	apt-get -y install libnet-dev
	cd $cur_dir
	if [[ -d $ins_dir/bin ]]; then
		rm -fr $ins_dir/bin
		mkdir $ins_dir/bin
	else
		mkdir $ins_dir/bin
	fi
	cd $cur_dir/build
	make clean
	make && make install
}

function coding_web()
{
	cd $cur_dir
	if [[ -d $ins_dir/www ]]; then
		rm -fr $ins_dir/www
		mkdir $ins_dir/www
	else
		mkdir $ins_dir/www
	fi
	cd $cur_dir/build
	make clean
	make && make install
}

function setting_default()
{
	cd $cur_dir
	rm /etc/network/interfaces
	cp default/interfaces /etc/network/interfaces

	sed -i 's/\#GRUB_HIDDEN_TIMEOUT=0/GRUB_HIDDEN_TIMEOUT=0/g' /etc/default/grub
	sed -i 's/GRUB_TIMEOUT=2/GRUB_TIMEOUT=0/g' /etc/default/grub
	sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="net.ifnames=1 biosdevname=0"/g' /etc/default/grub
	update-grub
	chmod +w /boot/grub/grub.cfg
	sed -i 's/=-1/=0/g' /boot/grub/grub.cfg
	chmod -w /boot/grub/grub.cfg

	suppwd=$(cat $SID | grep system | awk '{print $2}')
	echo root:$suppwd | /usr/sbin/chpasswd
}

function setting_startup()
{
	cd $cur_dir
	sed -i 's/sleep.*/sleep 1/g' /etc/init/failsafe.conf

}

function check_exec()
{
	check_system
	check_network
	check_folder
	check_file
}

function preheat_exec()
{
	preheat_info
	preheat_SID
	preheat_write
}

function install_exec()
{
	install_baisc
	install_depends
	install_mysql
	install_php
	install_nginx
	install_nodejs
	install_pfring
}

function coding_exec()
{
	coding_mysql
	coding_server
	coding_nogfw
	coding_web
}

function setting_exec()
{
	setting_default
	setting_startup
}

check_exec
preheat_exec
install_exec
coding_exec
setting_exec