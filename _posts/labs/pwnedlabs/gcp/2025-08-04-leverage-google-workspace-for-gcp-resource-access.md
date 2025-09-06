---
title: Leverage Google Workspace for GCP Resource Access 
description: Leverage Google Workspace for GCP Resource Access
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
During a red team engagement against shopgigantic.com, your colleague successfully phished an employee and gained credentials to access their Windows jumpbox. From this initial foothold, your objective is to pivot further into the organization's infrastructure and demonstrate impact by gaining access to sensitive resources 

# Walkthrough
We are given credentials and IP address. Let's log into machine via RDP
```
└─$ xfreerdp /v:10.1.20.162 /u:jasonw /p:'<REDACTED>'
```

![](leverage-google-workspace-for-gcp-resource-access-1.png)

Next, let's search for credentials. We can use the following [script](https://github.com/hac01/red-team-scripts/blob/main/windows/credential-enumeration/cred-enum.ps1) for enumeration. We could also use [LaZagne](https://github.com/AlessandroZ/LaZagne) to automate credential extraction from browsers, mail clients, and more.

![](leverage-google-workspace-for-gcp-resource-access-2.png)

There are credentials stored in browsers. Let's start with Microsoft Edge. We found password by navigating to `Settings` -> `Wallet` -> `Passwords`

![](leverage-google-workspace-for-gcp-resource-access-3.png)

Credentials can be used to access user’s Google Workspace (GWS) account for further enumeration. We can find user's email by checking the Chrome.

![](leverage-google-workspace-for-gcp-resource-access-5.png)

Login as `jason` to GWS

![](leverage-google-workspace-for-gcp-resource-access-4.png)

We find interesting files in Google Drive

![](leverage-google-workspace-for-gcp-resource-access-6.png)

We find interesting archive `service-acct-keyfile (1).zip`, which may contain a service account key file based on the name. The archive is password protected

```
└─$ unzip service-acct-keyfile\ \(1\).zip 
Archive:  service-acct-keyfile (1).zip
   skipping: service-account-keyfile/development-459721-af932469c4ac.json  need PK compat. v5.1 (can do v4.6)
   creating: service-account-keyfile/
```

We can search through different services and documents for additional info, but we find the password for archive in Notes

![](leverage-google-workspace-for-gcp-resource-access-7.png)

Extract the archive
```
└─$ 7z x service-acct-keyfile\ \(1\).zip 

7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-08-11
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:65535

Scanning the drive for archives:
1 file, 2242 bytes (3 KiB)

Extracting archive: service-acct-keyfile (1).zip
--
Path = service-acct-keyfile (1).zip
Type = zip
Physical Size = 2242

    
Enter password (will not be echoed):
Everything is Ok

Folders: 1
Files: 1
Size:       2360
Compressed: 2242

```

We can authenticate to GCP using the following command
```
└─$ gcloud auth activate-service-account --key-file=./development-459721-af932469c4ac.json 
Activated service account credentials for: [pubsub@development-459721.iam.gserviceaccount.com]
```

Based on service account name, we can assume it has permissions related to Cloud Pub/Sub, more specifically for publishing messages (we also saw this in `Cloud Infrastructure Audit System` document)

![](leverage-google-workspace-for-gcp-resource-access-8.png)

We can try running the command and we successfully publish message. But nothing more
```
└─$ gcloud pubsub topics publish internal-alerts --message '{"type":"audit","id":"admin-check"}' --project="development-459721"
messageIds:
- '15729089610497421'
```

Let's continue with enumeration and check the `Cloud Infrastructure Audit System` document


![](leverage-google-workspace-for-gcp-resource-access-9.png)

We have some information regarding storage: `Audit results are stored in randomly-named buckets with the prefix pattern for security` and that they can be accessed by authorized personnel. Service account doesn't have those permissions, but luckily `jasonw` has, so navigate to `https://console.cloud.google.com`


![](leverage-google-workspace-for-gcp-resource-access-10.png)

`jasonw` has access to bucket which was mentioned the document, which stores logs and audit data. 

![](leverage-google-workspace-for-gcp-resource-access-11.png)

![](leverage-google-workspace-for-gcp-resource-access-12.png)

In the logs we found:
- A Cloud Run URL: `https://inven-mang-app-930345098808.us-central1.run.app/login.html`
- A Firebase project ID and name: `development-1729b` and `firebase-db-inven-portal`

Let's navigate to `https://inven-mang-app-930345098808.us-central1.run.app/login.html` 

![](leverage-google-workspace-for-gcp-resource-access-13.png)

The application has login page that requires 16-digit account number. We can't bruteforce it, so let's check Firebase since we know the project name, collection name and ID. If it's Firebase Realtime Database or Firestore instance is misconfigured, we might:
- Read sensitive data (like user credentials or tokens)
- Modify existing entries (auth bypass or account takeover)
- Discover endpoints, roles, or internal secrets

We can check if Firebase has public access by curling it
```
└─$ curl "https://firestore.googleapis.com/v1/projects/development-1729b/databases/(default)/documents/users"
{
  "documents": [
    {
      "name": "projects/development-1729b/databases/(default)/documents/users/1026263884676647",
      "fields": {
        "role": {
          "stringValue": "user"
        }
      },
      "createTime": "2025-05-30T04:02:11.873754Z",
      "updateTime": "2025-05-30T04:02:11.873754Z"
    },
    {
      "name": "projects/development-1729b/databases/(default)/documents/users/3165016191009864",
      "fields": {
        "role": {
          "stringValue": "user"
        }
      },
      "createTime": "2025-05-30T04:02:26.673556Z",
      "updateTime": "2025-05-30T04:02:26.673556Z"
    },
    {
      "name": "projects/development-1729b/databases/(default)/documents/users/4911319021132923",
      "fields": {
        "role": {
          "stringValue": "admin"
        }
      },
      "createTime": "2025-05-30T04:02:41.363550Z",
      "updateTime": "2025-05-30T04:02:41.363550Z"
    },
    {
      "name": "projects/development-1729b/databases/(default)/documents/users/7892073607105996",
      "fields": {
        "role": {
          "stringValue": "user"
        }
      },
      "createTime": "2025-05-30T04:02:57.672430Z",
      "updateTime": "2025-05-30T04:02:57.672430Z"
    }
  ]
}

```

We're able to access the misconfigured Firebase database and extract the 16-digit account number associated with the admin user. Now  let’s proceed to log in to the Cloud Run application

![](leverage-google-workspace-for-gcp-resource-access-14.png)

# Defense
Based on lab's [Defense](https://pwnedlabs.io/labs/leverage-google-workspace-for-gcp-resource-access) section.


Google Workspace admins can view the third-party apps that users have accessed and the permissions that they have. 
It can be viewed:
-  `Security → Access and data control → API Controls → Manage third-party app access → View list (Accessed Apps)`. The
-  URL is: `https://admin.google.com/u/1/ac/owl/list?tab=apps`. 

![](leverage-google-workspace-for-gcp-resource-access-15.png)

Alerting should be put in place to notify admins of any changes.

The app control policy in this lab's case is very permissive. All users in the workspace are allowed to access third-party apps.

![](leverage-google-workspace-for-gcp-resource-access-16.png)

Workspace admins can also report on the number of apps that can been granted access to a Google service, as well as the number of the number of users that have allowed access to a Google service.


![](leverage-google-workspace-for-gcp-resource-access-17.png)


Workspace admins should also check and alert on the `OAuth Token Audit` to see which `OAuth` clients their users have approved.


![](leverage-google-workspace-for-gcp-resource-access-18.png)

To reduce risk:
- Restrict browser password storage via enterprise policies and enforce MFA for all cloud logins. 
- Regularly audit Google Drive for exposed service account keys and educate users against storing sensitive passwords in personal apps like Google Keep. 
- Implement DLP policies to catch these before attackers do.
  
This lab also had a misconfigured Firebase database to access sensitive admin information. Identical to `CVE-2024-45489`, a real bug in the Arc browser, where insecure Firebase rules let attackers change Boost ownership and execute malicious JS in other users' browsers.

# google-workspace-enum
The labs was completed manually, but we can leverage automation like [google-workspace-enum](https://github.com/pwnedlabs/google-workspace-enum)

The tool helps automate the enumeration of various Google Workspace services, such as Drive, Keep, Docs, Sheets, and more giving us broader visibility with less manual effort.

Prerequisites:
- You must use your own Google Cloud project (something you own and control).
- Enable all the APIs mentioned on [the official GitHub setup page](https://github.com/pwnedlabs/google-workspace-enum/tree/main#-setup).

## Step 1: Create OAuth credentials
- Log in to your Google Cloud console and navigate to the Credentials page.
- Click on the Create Credentials button.

![](leverage-google-workspace-for-gcp-resource-access-19.png)

## Step 2: Choose OAuth client type
- From the menu, select OAuth client ID.

![](leverage-google-workspace-for-gcp-resource-access-20.png)

## Step 3: Configure the OAuth client

- Choose Desktop app.

![](leverage-google-workspace-for-gcp-resource-access-21.png)

## Step 4: Download client secrets

- After creation, download the client secrets JSON file and save it into your `google-workspace-enum` folder.
- Name it something easy to reference (e.g., `client_secrets.json`).

![](leverage-google-workspace-for-gcp-resource-access-22.png)
## Step 5: Add test users

- Go to the Audience page and click on Add user.
- Enter the email address of the Google Workspace user you want to test.

![](leverage-google-workspace-for-gcp-resource-access-23.png)

Now you can run `gws-enum` to start your enumeration.

![](leverage-google-workspace-for-gcp-resource-access-24.png)

Once enumeration completes, explore the `./loo`t directory where the tool stores all downloaded artifacts. It includes emails, Google Drive files, Docs, Sheets, and other accessible Workspace data