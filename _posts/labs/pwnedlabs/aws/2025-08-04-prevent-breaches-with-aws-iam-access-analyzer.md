---
title: Prevent Breaches with AWS IAM Access Analyzer
description: Prevent Breaches with AWS IAM Access Analyzer 
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
It's your first day as blue team consultant for your client Huge Logistics, and you have set up several AWS-native services to supplement your existing security suite. Your goal now is to set up IAM Access Analyzer, identify what issues might be present and work to remediate them.

# Walkthrough
Authenticate using given credentials
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDA4RAAI74V4HHEQBXJH",
    "Account": "861141532459",
    "Arn": "arn:aws:iam::861141532459:user/security"
}
```

Now we change the password to login to AWS console
```
└─$ aws iam update-login-profile --user-name security --password '<REDACTED>'
```

After authenticating to AWS console, navigate to `Access Analyzer`, which is contained and part of the Identity and Access Management (IAM) service. IAM Access Analyzer can be used to:
- Identify resources that are shared outside our "zone of trust" (AWS account)
- Identify IAM users and roles with assigned permissions that they do not use (and could potentially be safe to remove)

In `Access Analyzer`, click `Create Analyzer`

![](prevent-breaches-with-aws-iam-access-analyzer-1.png)

Select the default selection of `External access analysis` and click `Create analyzer`

![](prevent-breaches-with-aws-iam-access-analyzer-2.png)

Analyzer was created

![](prevent-breaches-with-aws-iam-access-analyzer-3.png)

Let's analyze the findings. Set filter `All` instead of `Active`

![](prevent-breaches-with-aws-iam-access-analyzer-4.png)

We find the serious misconfiguration, where any AWS user has access to perform any action on the bucket

![](prevent-breaches-with-aws-iam-access-analyzer-5.png)

If we click the S3 bucket under `Resource`, it will open the tab with this bucket. We can see `to_delete` public folder, which contains AWS access keys

![](prevent-breaches-with-aws-iam-access-analyzer-6.png)

![](prevent-breaches-with-aws-iam-access-analyzer-7.png)

To address this issue, we would:
- disable the exposed AWS access key
- identify the AWS IAM user they belong to (kate)
- understand when the key has been used and what resources the user has been accessing

After that we focus on removing this access. Under `Bucket policy`, click the `Edit` button.

![](prevent-breaches-with-aws-iam-access-analyzer-8.png)

Now, replace the policy with a more restrictive one, that just allows access by the IAM users `security` and `kate` (if it's confirmed by the security team as not compromised) 
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::861141532459:user/security",
          "arn:aws:iam::861141532459:user/kate"
        ]
      },
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::huge-logistics-tmp-44accbabeb8b/*",
        "arn:aws:s3:::huge-logistics-tmp-44accbabeb8b"
      ]
    }
  ]
}
```

Save the policy

![](prevent-breaches-with-aws-iam-access-analyzer-9.png)

Now if we `Rescan` the finding, we should see that status has been changed to `Resolved`

![](prevent-breaches-with-aws-iam-access-analyzer-10.png)

Let's move to next finding related to the same S3 bucket. Any AWS account can list the contents of the bucket

![](prevent-breaches-with-aws-iam-access-analyzer-11.png)

Now, click on S3 bucket under `Resources` again and navigate to `Permissions` tab. There scroll to `Access Control List (ACL)` section and click `Edit`

![](prevent-breaches-with-aws-iam-access-analyzer-12.png)

We see the problematic ACL, so `Untick the Everyone (public access): List` setting and click `Save changes`

![](prevent-breaches-with-aws-iam-access-analyzer-13.png)

![](prevent-breaches-with-aws-iam-access-analyzer-14.png)

After rescaning the finding, it will be changed to `Resolved` status

![](prevent-breaches-with-aws-iam-access-analyzer-15.png)

Continue with the next finding. It shows that any AWS user that is aware of the bucket name would be able to list and read the bucket contents

![](prevent-breaches-with-aws-iam-access-analyzer-16.png)

Now, similarly as with the first findings, change the policy so that only the user `Francesco` (who adds and accesses customer data) and `security` should have access
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::861141532459:user/security",
          "arn:aws:iam::861141532459:user/francesco"
        ]
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::huge-logistics-custdata-44accbabeb8b",
        "arn:aws:s3:::huge-logistics-custdata-44accbabeb8b/*"
      ]
    }
  ]
}
```

Save the changes and rescan

![](prevent-breaches-with-aws-iam-access-analyzer-17.png)

Let's resolve `OrganizationAccessAccessRole` finding next. According to documentation, this role is automatically created for any AWS account that is a member of an AWS Organization. 
```
AWS Organizations is an account management service that allows businesses to consolidate multiple AWS accounts into an organization, which then share billing details (and optionally also AWS credits), and this also allows centralized management of resources
```

![](prevent-breaches-with-aws-iam-access-analyzer-18.png)

This configuration is intended, thus click `Archive`

![](prevent-breaches-with-aws-iam-access-analyzer-19.png)

Let's move on to the next finding. We can see that EC2 EBS snapshot has been shared with the AWS account ID of a consultant. 

![](prevent-breaches-with-aws-iam-access-analyzer-20.png)

The snapshot contained infrastructure as code backups that might have contained sensitive credentials, so remove access (Make sure that the credentials have already been rotated...). Click on the URL under `Resources` 

![](prevent-breaches-with-aws-iam-access-analyzer-21.png)

Select the snapshot and click on the `Actions` menu and then select `Snapshot settings > Modify permissions`

![](prevent-breaches-with-aws-iam-access-analyzer-22.png)


Under the `Shared Accounts` section, selecte the target AWS account ID and click `Remove selected`, then `Modify permissions`

![](prevent-breaches-with-aws-iam-access-analyzer-23.png)

After permissions have been changed, rescan the finding to resolve it

![](prevent-breaches-with-aws-iam-access-analyzer-24.png)

It's also possible to use `Unused access analyzer`, that identifies permissions that could potentially be removed (principle of least privilege). But this is a paid service (with cost based on the number of IAM users and roles in account). Still worth considering as part of risk reduction strategy. Overall, it's really useful service, which is helpful in applying the principle of least privilege throughout cloud environment.
