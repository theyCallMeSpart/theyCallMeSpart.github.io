+++
title = "Over the Wire: Bandit"
date = 2023-02-19
description = "Over the Wire: Bandit"
tags = [
    "Over the Wire",
    "Write-up"
]
+++

# Bandit

Flag from level n is password for level n+1.

`~ ssh banditX@bandit.labs.overthewire.org -p 2220` ssh to n with password n-1.

WECHALLUSER=“Spart” WECHALLTOKEN=“660F4-239AC-55178-E6945-1B195-0A95F” wechall

## Level 1

```
~ ssh bandit0@bandit.labs.overthewire.org -p 2220
bandit0@bandit:~$ cat readme
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

## Level 1

```
~ ssh bandit1@bandit.labs.overthewire.org -p 2220
bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

## Level 2

```
~ bandit2@bandit.labs.overthewire.org -p 2220
bandit2@bandit:~$ cat "spaces in this filename"
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

## Level 3

```
~ ssh bandit3@bandit.labs.overthewire.org -p 2220
bandit3@bandit:~$ cd inhere/
bandit3@bandit:~/inhere$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

## Level 4

```
~ ssh bandit4@bandit.labs.overthewire.org -p 2220
bandit4@bandit:~$ cd inhere/
bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```

## Level 5

```
ssh bandit5@bandit.labs.overthewire.org -p 2220
bandit1@bandit:~$ cat maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

## Level 6

```
bandit6@bandit:~$ find / -group bandit6 -user bandit7 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

## Level 7

```
bandit7@bandit:~$ grep "millionth" data.txt
millionth cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

## Level 8

```
bandit8@bandit:~$ sort data.txt | uniq -c | grep -w "1"
1 UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

## Level 9

```
bandit9@bandit:~$ strings data.txt | grep =
========== the*2i"4
=:G e
========== password
<I=zsGi
Z)========== is
A=|t&E
Zdb=
c^ LAh=3G
*SF=s
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
S=A.H&^
```

## Level 10

```
bandit10@bandit:~$ base64 -d ./data.txt
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

## Level 11

```
bandit11@bandit:~$ cat ./data.txt | tr '[a-zA-Z]' '[n-za-mN-ZA-M]'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```

## Level 12

```
bandit12@bandit:/tmp/spart$ xxd -r data.txt > data
bandit12@bandit:/tmp/spart$ file data
data: gzip compressed data, was "data2.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:/tmp/spart$ mv data data2.gz
bandit12@bandit:/tmp/spart$ gzip -d data2.gz
bandit12@bandit:/tmp/spart$ mv data2 data3.bz
bandit12@bandit:/tmp/spart$ bzip2 -d data3.bz
bandit12@bandit:/tmp/spart$ file data3
data3: gzip compressed data, was "data4.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
.
.
.
bandit12@bandit:/tmp/spart$ tar -xvf data5.tar
.
.
.
bandit12@bandit:/tmp/spart$ file data8.bin
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu May  7 18:14:30 2020, max compression, from Unix
bandit12@bandit:/tmp/spart$ mv data8.bin data9.gz
bandit12@bandit:/tmp/spart$ gzip -d data9.gz
bandit12@bandit:/tmp/spart$ cat data9

The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

## Level 13

```
bandit13@bandit: ssh bandit14@localhost -p 22 -i sshkey.private
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
```

## Level 14

```
bandit14@bandit:~$ nc localhost 30000
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

## Level 15

```
bandit15@bandit:~$ openssl s_client -connect localhost:30001
BfMYroe26WYalil77FoDi9qh59eK5xNr
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd
```

## Level 16

```
22/tcp    open  ssh
113/tcp   open  ident
6010/tcp  open  x11
30000/tcp open  ndmps
30001/tcp open  pago-services1
30002/tcp open  pago-services2
31046/tcp open  unknown
31518/tcp open  unknown
31691/tcp open  unknown
31790/tcp open  unknown
31960/tcp open  unknown
42239/tcp open  unknown
43761/tcp open  unknown

bandit16@bandit:~$ openssl s_client -connect localhost:31790
cluFn7wTiGryunymYOu4RcffSxQluehd
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```

## Level 17

```
ssh bandit17@bandit.labs.overthewire.org -p 2220 -i /tmp/key.key
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
---
> kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
```

## Level 18

```
ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat ~/readme"
bandit18@bandit.labs.overthewire.org's password: kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x
```

## Level 19

```
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j
```

## Level 20

```
bandit20@bandit:~$ echo "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -lvp 1337 &
[1] 11376
bandit20@bandit:~$ listening on [any] 1337 ...

bandit20@bandit:~$ ps -aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
bandit20  3392  0.0  0.1  21308  5252 pts/12   Ss   16:40   0:00 -bash
bandit20 11376  0.0  0.0   6300  1608 pts/12   S    16:55   0:00 nc -lvp 1337
bandit20 11389  0.0  0.0  19188  2472 pts/12   R+   16:55   0:00 ps -aux
bandit20@bandit:~$ ./suconnect 1337 GbKksEFF4yrVs6il55v6gwY5aVje5f0j
connect to [127.0.0.1] from localhost [127.0.0.1] 38034
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```

## Level 21

```
bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

## Level 22

```
bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
bandit22@bandit:~$ mytarget=$(echo I am user bandit23 | md5sum | cut -d ' ' -f 1)
bandit22@bandit:~$ echo $mytarget
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

## Level 23

```
bandit23@bandit:vim /tmp/run.sh
cat /etc/bandit_pass/bandit24 > /tmp/bandit24.pass
bandit23@bandit:/tmp$ chmod 777 /tmp/run.sh
bandit23@bandit:/tmp$ cp run.sh /var/spool/bandit24/
bandit23@bandit:/tmp$ cat /tmp/bandit24.pass
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

## Level 24

```
bandit24@bandit:/tmp$ nc localhost 30002 UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG
```

```
#!/usr/bin/env python3
# coding: utf-8import sys
import socketpincode = 0
password = "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ"
try:
    # Connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 30002))
    
    # Print welcome message
    welcome_msg = s.recv(2048)
    print(welcome_msg)    # Try brute-forcing
    while pincode < 10000:
        pincode_string = str(pincode).zfill(4)
        message=password+" "+pincode_string+"\n"        # Send message
        s.sendall(message.encode())
        receive_msg = s.recv(1024)        # Check result
        if "Wrong" in receive_msg:
            print("Wrong PINCODE: %s" % pincode_string)
        else:
            print(receive_msg)
            break
        pincode += 1
finally:
    sys.exit(1)
```

You can also generate every possibilities and paste them after opening a nc session.

## Level 25

```
bandit25@bandit:~$ ssh bandit26@localhost -i bandit26.sshkey

bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext

ssh -i bandit26.sshkey -t bandit26@localhost cat text.txt (in a very small terminal)

press v to open Vi in a more window

enter “:e /etc/bandit_pass/bandit26”

5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z
:shell
```

## Level 26

```
./bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea
```

## Level 27

```
ssh bandit27@bandit.labs.overthewire.org -p 2220

bandit27@bandit:/tmp$ git clone ssh://bandit27-git@localhost/home/bandit27-git/repo repo2

bandit27@bandit:/tmp/repo2$ cat README
The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2
```

## Level 28

```
bandit28@bandit:/tmp/repo3$ git show
bbc96594b4e001778eee9975372716b2
```

## Level 29

```
bandit29@bandit:/tmp/repo2$ git checkout dev
Branch dev set up to track remote branch dev from origin.
Switched to a new branch 'dev'
bandit29@bandit:/tmp/repo2$ git log -p
 ## credentials

 - username: bandit30
-- password: <no passwords in production!>
+- password: 5b90576bedb2cc04c86a9e924ce42faf
```

## Level 30

```
bandit30@bandit:/tmp/repo$ git checkout origin/master
Note: checking out 'origin/master'.
bandit30@bandit:/tmp/repo$ git log
bandit30@bandit:/tmp/repo$ git tag
secret
bandit30@bandit:/tmp/repo$ git show secret
47e603bb428404d265f59c42920d81e5
```

## Level 31

```
bandit31@bandit:/tmp/repo3$ cat README.md
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master

bandit31@bandit:/tmp/repo3$ cat .gitignore
*.txt
bandit31@bandit:/tmp/repo3$ echo 'May I come in?' > key.txt
bandit31@bandit:/tmp/repo3$ cat key.txt
May I come in?
bandit31@bandit:/tmp/repo3$ git add -f key.txt
bandit31@bandit:/tmp/repo3$ git commit -m "May I come in?"
bandit31@bandit:/tmp/repo3$ git push
remote: Well done! Here is the password for the next level:
remote: 56a9bf19c63d650ce78e6ec0354ee45e
```

## Level 32

```
WELCOME TO THE UPPERCASE SHELL
>> $0
$ ls -la *
-rwsr-x--- 1 bandit33 bandit32 7556 May  7 20:14 uppershell
$ cat /etc/bandit_pass/bandit33
c9c3199ddf4121b10cf581a98d51caee
```

## Level 33

```
ssh bandit33@bandit.labs.overthewire.org -p 2220
c9c3199ddf4121b10cf581a98d51caee
```
