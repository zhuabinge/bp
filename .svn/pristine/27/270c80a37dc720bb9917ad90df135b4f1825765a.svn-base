#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Check if user is root
if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root to install lnmp"
    exit 1
fi

function install_redis()
{
	apt-get -y install redis-server
	ldconfig
	sleep 5
	cd /tmp
	tar zxf redis-2.2.5.tar.gz
	cd redis-2.2.5/
	sed -i '/redis.so/d' /usr/local/php/etc/php.ini
	/usr/local/php/bin/phpize
	./configure --with-php-config=/usr/local/php/bin/php-config
	make && make install
	cd ../
sed -i '/the dl()/i\
extension = "redis.so"' /usr/local/php/etc/php.ini
}

install_redis