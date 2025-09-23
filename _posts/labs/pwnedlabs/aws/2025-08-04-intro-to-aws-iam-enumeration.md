---
title: Intro to AWS IAM Enumeration
description: Intro to AWS IAM Enumeration
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
You are a security consultant hired by the global logistics company, Huge Logistics. Following suspicious activity, you are tasked with enumerating the IAM user dev01 and mapping out any potentially compromised resources. Your mission is to enumerate and evaluate IAM roles, policies, and permissions.

Learning outcomes:

- Familiarity with the AWS CLI
- Understanding of the basic AWS IAM components
- Ability to list, retrieve and interpret IAM policies

# Walkthrough
[AWS Identity and Access Management (IAM)](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html) is a web service that helps you securely control access to AWS resources. With IAM, you can manage permissions that control which AWS resources users can access. You use IAM to control who is authenticated (signed in) and authorized (has permissions) to use resources. IAM provides the infrastructure necessary to control authentication and authorization for your AWS accounts.

To interact with AWS we have to use [AWS Management Console](https://aws.amazon.com/console/) and [AWS CLI](https://aws.amazon.com/cli/). There are also other ways to interact with AWS, like APIs and SDKs.

First, we can visit `https://794929857501.signin.aws.amazon.com/console` which will redirect us to AWS Management Console. It will parse URL and automatically populates AWS Account ID to `794929857501`. 

![](intro-to-aws-iam-enumeration-1.png)

Login with provided credentials

![](intro-to-aws-iam-enumeration-2.png)

We can click `GuardDuty` and start investigating

![](intro-to-aws-iam-enumeration-3.png)

But for this lab, we will mostly use AWS CLI. To authenticate we need to use AWS Access Key and Secret Key. We are provided with those.

The Access Key and Secret Access Key are set of credentials used to authenticate API requests, a.k.a. "username and password". These keys are generated through the AWS Management Console and are linked to an IAM (Identity and Access Management) user or AWS root account. The secret access key can be retrieved only at the time of creation. 

- `Access Key ID`: 20-character alphanumeric string (e.g., "AKIAIOSFODNN7EXAMPLE"), which is used to identify the user/account making a programmatic request to an AWS service. It can be shared, like a username.
- `Secret Access Key`: 40-character string (e.g., "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") which serves as the "password" for authentication requests along with the corresponding Access Key ID. It should should never be shared or stored in an insecure manner.

Set the keys using `aws configure`

![](intro-to-aws-iam-enumeration-4.png)

Now we can interact with AWS. Running `aws sts get-caller-identity` is similar to `whoami` command.  
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDA3SFMDAPOWFB7BSGME",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/dev01"
}
```

Retrieve infromation about the user with `aws iam get-user`
```
└─$ aws iam get-user
{
    "User": {
        "Path": "/",
        "UserName": "dev01",
        "UserId": "AIDA3SFMDAPOWFB7BSGME",
        "Arn": "arn:aws:iam::794929857501:user/dev01",
        "CreateDate": "2023-09-28T21:56:31Z",
        "PasswordLastUsed": "2025-08-05T18:06:54Z",
        "Tags": [
            {
                "Key": "AKIA3SFMDAPOWC2NR5LO",
                "Value": "dev01"
            }
        ]
    }
}
```

There are no groups
```
└─$ aws iam list-groups-for-user --user-name dev01
{
    "Groups": []
}
```
But there are some [policies](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/policy-list.html)
```
└─$ aws iam list-attached-user-policies --user-name dev01
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonGuardDutyReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess"
        },
        {
            "PolicyName": "dev01",
            "PolicyArn": "arn:aws:iam::794929857501:policy/dev01"
        }
    ]
}

```

We have a permission to read access to Amazon GuardDuty resources (entities and data structures that GuardDuty uses to detect, store, and report findings about potential security threats in AWS environment) and some custom policy named `dev01`. 

We can check custom policy, which might be [inline policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html)
```
└─$ aws iam list-user-policies --user-name dev01
{
    "PolicyNames": [
        "cloudshell",
        "S3_Access"
    ]
}
```

We can start examining the policies in more detail. Let's start with `AmazonGuardDutyReadOnlyAccess` which is Amazon policy. Both Amazon and customer managed policies can have multiple versions, which is done to preserve, review, and roll back to previous policy versions. Only inline policies do not support versioning. To examine the policy we need to use `PolicyArn`, that refers to the Amazon Resource Name, which is a combination of the AWS account ID, resource type and resource name. The `ARN` is a globally unique reference to the object.
```
└─$ aws iam list-policy-versions --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess
{
    "Versions": [
        {
            "VersionId": "v4",
            "IsDefaultVersion": true,
            "CreateDate": "2023-11-16T23:07:06Z"
        },
        {
            "VersionId": "v3",
            "IsDefaultVersion": false,
            "CreateDate": "2021-02-16T23:37:57Z"
        },
        {
            "VersionId": "v2",
            "IsDefaultVersion": false,
            "CreateDate": "2018-04-25T21:07:17Z"
        },
        {
            "VersionId": "v1",
            "IsDefaultVersion": false,
            "CreateDate": "2017-11-28T22:29:40Z"
        }
    ]
}
```

We can see the `v4` version, let's examine it
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess --version-id v4
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "guardduty:Describe*",
                        "guardduty:Get*",
                        "guardduty:List*"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "organizations:ListDelegatedAdministrators",
                        "organizations:ListAWSServiceAccessForOrganization",
                        "organizations:DescribeOrganizationalUnit",
                        "organizations:DescribeAccount",
                        "organizations:DescribeOrganization",
                        "organizations:ListAccounts"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v4",
        "IsDefaultVersion": true,
        "CreateDate": "2023-11-16T23:07:06Z"
    }
}

```

In AWS, the `List`, `Describe`, and `Get` actions serve different purposes when interacting with resources. `List` actions are used to retrieve collections of resources, typically returning basic information like resource IDs or names—essentially answering "what exists". `Describe` actions provide more detailed metadata about one or more resources, such as configurations or properties, often used after listing to gather more context. `Get` actions are used to retrieve the actual content or data of a specific resource, such as findings, settings, or results. Thus, we can view `GuardDuty` resources using `Describe`, `Get`, and `List` actions. It also allows viewing organizational details like accounts, OUs, and delegated administrators. 

Let's check customer managed policy, which also has multiple versions
```
└─$ aws iam list-policy-versions --policy-arn arn:aws:iam::794929857501:policy/dev01
{
    "Versions": [
        {
            "VersionId": "v7",
            "IsDefaultVersion": true,
            "CreateDate": "2023-10-11T19:59:08Z"
        },
<SNIP>
    ]
}

```


Let's check `v7`
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::794929857501:policy/dev01 --version-id v7
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
                        "iam:ListPolicyVersions",
                        "iam:GetUserPolicy",
                        "iam:ListGroupsForUser",
                        "iam:ListAttachedUserPolicies",
                        "iam:ListUserPolicies",
                        "iam:GetUser",
                        "iam:ListAttachedRolePolicies",
                        "iam:GetRolePolicy"
                    ],
                    "Resource": [
                        "arn:aws:iam::794929857501:user/dev01",
                        "arn:aws:iam::794929857501:role/BackendDev",
                        "arn:aws:iam::794929857501:policy/BackendDevPolicy",
                        "arn:aws:iam::794929857501:policy/dev01",
                        "arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess"
                    ]
                }
            ]
        },
        "VersionId": "v7",
        "IsDefaultVersion": true,
        "CreateDate": "2023-10-11T19:59:08Z"
    }
}

```

We can map the actions to resources

| Action                         | Description                                   | Targeted Resource(s)                                                              |
| ------------------------------ | --------------------------------------------- | --------------------------------------------------------------------------------- |
| `iam:GetRole`                  | View details of the IAM role                  | `role/BackendDev`                                                                 |
| `iam:ListAttachedRolePolicies` | List managed policies attached to the role    | `role/BackendDev`                                                                 |
| `iam:GetRolePolicy`            | View inline policies attached to a role       | `role/BackendDev`                                                                 |
| `iam:GetPolicy`                | Retrieve metadata about a managed policy      | `policy/BackendDevPolicy`, `policy/dev01`, `policy/AmazonGuardDutyReadOnlyAccess` |
| `iam:GetPolicyVersion`         | View specific versions of IAM policies        | `policy/BackendDevPolicy`, `policy/dev01`, `policy/AmazonGuardDutyReadOnlyAccess` |
| `iam:ListPolicyVersions`       | List versions of a managed policy             | `policy/BackendDevPolicy`, `policy/dev01`, `policy/AmazonGuardDutyReadOnlyAccess` |
| `iam:GetUser`                  | View user metadata                            | `user/dev01`                                                                      |
| `iam:GetUserPolicy`            | View inline policies attached to the user     | `user/dev01`                                                                      |
| `iam:ListUserPolicies`         | List all inline policies attached to the user | `user/dev01`                                                                      |
| `iam:ListGroupsForUser`        | List all groups the user is a member of       | `user/dev01`                                                                      |
| `iam:ListAttachedUserPolicies` | List managed policies attached to the user    | `user/dev01`                                                                      |

The customer managed policy `dev01` gives visibility to
  - The IAM user `dev01` and their policies, groups, and attached permissions.
  - The IAM role `BackendDev`, its attached managed and inline policies.
  - Three IAM managed policies: `BackendDevPolicy`, `dev01`, and `AmazonGuardDutyReadOnlyAccess`

Let's examine newly found `BackendDev` role
```
└─$ aws iam get-role --role-name BackendDev
{
    "Role": {
        "Path": "/",
        "RoleName": "BackendDev",
        "RoleId": "AROA3SFMDAPO2RZ36QVN6",
        "Arn": "arn:aws:iam::794929857501:role/BackendDev",
        "CreateDate": "2023-09-29T12:30:29Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::794929857501:user/dev01"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        },
        "Description": "Grant permissions to backend developers",
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {
            "LastUsedDate": "2025-08-03T21:08:07Z",
            "Region": "us-west-1"
        }
    }
}

```


Seems like the purpose of the role is to allow developers to assume it. Assuming a role can be thought of as a bit like the `sudo` command on Linux, which grants temporary access to the permissions attached to the role. Currently only the IAM user `dev01` is allowed to assume the `BackendDev` role.

Let's continue investigation and enumerate the `BackendDevPolicy` policy
```
└─$ aws iam list-attached-role-policies --role-name BackendDev
{
    "AttachedPolicies": [
        {
            "PolicyName": "BackendDevPolicy",
            "PolicyArn": "arn:aws:iam::794929857501:policy/BackendDevPolicy"
        }
    ]
}

```
```
└─$ aws iam get-policy --policy-arn arn:aws:iam::794929857501:policy/BackendDevPolicy
{
    "Policy": {
        "PolicyName": "BackendDevPolicy",
        "PolicyId": "ANPA3SFMDAPO7OINIQIRR",
        "Arn": "arn:aws:iam::794929857501:policy/BackendDevPolicy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "Policy defining permissions for backend developers",
        "CreateDate": "2023-09-29T12:44:09Z",
        "UpdateDate": "2023-09-29T12:44:09Z",
        "Tags": []
    }
}

```
There's only one version of the policy, let's retrieve it
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::794929857501:policy/BackendDevPolicy --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "secretsmanager:ListSecrets"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret"
                    ],
                    "Resource": "arn:aws:secretsmanager:us-east-1:794929857501:secret:prod/Customers-QUhpZf"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2023-09-29T12:44:09Z"
    }
}

```

Seems like policy allows to retrieve information about all EC2 instances in the AWS account and list all the secrets currently stored in `SecretsManager`. We will also be able to get information about (describe) and retrieve the secret value of `prod/Customers`

Let's also check inline `dev01`'s policies that were found previously
```
└─$ aws iam get-user-policy --user-name dev01 --policy-name S3_Access
{
    "UserName": "dev01",
    "PolicyName": "S3_Access",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket",
                    "s3:GetObject"
                ],
                "Resource": [
                    "arn:aws:s3:::hl-dev-artifacts",
                    "arn:aws:s3:::hl-dev-artifacts/*"
                ]
            }
        ]
    }
}
```

We can retrieve contents of S3 bucket named `hl-dev-artifacts`
```
└─$ aws s3 ls hl-dev-artifacts    
2023-10-02 02:39:53       1235 android-kotlin-extensions-tooling-232.9921.47.pom
2023-10-02 02:39:53     214036 android-project-system-gradle-models-232.9921.47-sources.jar
2023-10-02 02:38:05         32 flag.txt

```

We can retrieve the flag
```
└─$ aws s3 cp s3://hl-dev-artifacts/flag.txt -  
d8ae4495888545df0c904551935c7514
```

Let's assume `BackendDev` role
```
└─$ aws sts assume-role  --role-arn arn:aws:iam::794929857501:role/BackendDev --role-session-name backend-dev-session
{
    "Credentials": {
        "AccessKeyId": "<REDACTED>",
        "SecretAccessKey": "<REDACTED>",
        "SessionToken": "IQoJb3JpZ2luX<SNIP>nwpoj3l65/",
        "Expiration": "2025-08-05T21:03:18Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3SFMDAPO2RZ36QVN6:backend-dev-session",
        "Arn": "arn:aws:sts::794929857501:assumed-role/BackendDev/backend-dev-session"
    }
}

```
Export temprorary credentials 
```
└─$ export AWS_ACCESS_KEY_ID="<REDACTED>"                        
```
```
└─$ export AWS_SECRET_ACCESS_KEY="<REDACTED>"
```
```                                                                                                                                                                                                             
└─$ export AWS_SESSION_TOKEN="IQoJb3JpZ2luX<SNIP>nwpoj3l65/"
```

We can test if we successfully assumed the role. Seems like it worked, we can list EC2 instances and secrets
```
└─$ aws ec2 describe-instances
{
    "Reservations": [
        {
            "ReservationId": "r-047e8213e6ead5f6b",
            "OwnerId": "794929857501",
            "Groups": [],
            "Instances": [
                {
                    "Architecture": "x86_64",
<SNIP>
```
```
└─$ aws secretsmanager list-secrets --region us-east-1
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:794929857501:secret:prod/Customers-QUhpZf",
            "Name": "prod/Customers",
            "Description": "Access to the MySQL prod database containing customer data",
            "LastChangedDate": 1695991078.584,
            "LastAccessedDate": 1754352000.0,
            "Tags": [],
            "SecretVersionsToStages": {
                "bf175f57-7e29-4fd1-881f-76e78fdd7320": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": 1695991078.328
        }
    ]
}
```

We found secrets in `us-east-1` region, let's retrieve them since we had permissions to access them 
```
└─$ aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:us-east-1:794929857501:secret:prod/Customers-QUhpZf --region us-east-1
{
    "ARN": "arn:aws:secretsmanager:us-east-1:794929857501:secret:prod/Customers-QUhpZf",
    "Name": "prod/Customers",
    "VersionId": "bf175f57-7e29-4fd1-881f-76e78fdd7320",
    "SecretString": "{\"username\":\"root\",\"password\":\"<REDACTED>\",\"engine\":\"mariadb\",\"host\":\"10.10.14.15\",\"port\":\"3306\",\"dbname\":\"customers\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1695991078.579
}
```