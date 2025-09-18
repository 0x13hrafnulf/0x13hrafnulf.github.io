---
title: Bypass Azure Web App Authentication with Path Traversal
description: Bypass Azure Web App Authentication with Path Traversal
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
On an engagement for our client Mega Big Tech, we used a custom phishlet and successfully performed an Evilginx man-in-the-middle attack to gain valid company credentials. You are tasked with demonstrating the impact of the breach and gaining access to business critical information.

Mega Big Tech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).

# Walkthrough
Let's enumerate resources that our user has access to
```
└─PS> Get-AzResource

Name              : megabigtech-dev
ResourceGroupName : megabigtech-dev_group
ResourceType      : Microsoft.Web/sites
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/megabigtech-dev_group/providers/Microsoft.Web/sites/megabigtech-dev
Tags              : 
```

We see Azure Web App named `megabigtech-dev` in the resource group `megabigtech-dev_group`. Let's get enabled hostnames
```
└─PS> (Get-AzWebApp -ResourceGroupName "megabigtech-dev_group" -Name "megabigtech-dev").EnabledHostNames                                                                                                                                    
megabigtech-dev.azurewebsites.net
megabigtech-dev.scm.azurewebsites.net
```

When an app is created, App Service creates a `Kudu` companion app for it that allows us to manage the app instance, including getting terminal access. The location of this app can vary depending on the configuration. The `Website Contributor` role must be assigned first in order to access Kudu instance.

- `https://<app-name>.scm.azurewebsites.net` (if the app isn't in an isolation tier)
- `https://<app-name>.scm.<ase-name>.p.azurewebsites.net` (if the app is internet-facing and in an isolated tier)
- `https://<app-name>.scm.<ase-name>.appserviceenvironment.net` (if the app is internal and in an isolated tier)

We see the dev instance of the Mega Big Tech homepage

![](bypass-azure-web-app-authentication-with-path-traversal-1.png)

The `Status` page shows the status of various AI models. 

![](bypass-azure-web-app-authentication-with-path-traversal-2.png)

The URL contains `/status.aspx?status=latest`, so depending on implementation, this could be vulnerable to a range of vulnerability classes, such as command injection, SSRF, LFI and path traversal. Playing around with the `status` parameter value we see the error `File not found`. This indicates that it is trying to include the contents of a file 

![](bypass-azure-web-app-authentication-with-path-traversal-3.png)

By plaing around with `status` parameter, we successfully retrieve file `status.aspx` and `status.aspx.cs` (referenced in `status.aspx` file), which was located in upper directory. 

![](bypass-azure-web-app-authentication-with-path-traversal-4.png)

![](bypass-azure-web-app-authentication-with-path-traversal-5.png)

No success in retrieving `web.config`, therefore let's try fuzzing directories
```
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -X GET -u 'https://megabigtech-dev.azurewebsites.net/FUZZ' -r -H 'Cookie: <REDACTED>'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://megabigtech-dev.azurewebsites.net/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Header           : Cookie: <REDACTED>
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

<SNIP>
admin                 [Status: 403, Size: 58, Words: 11, Lines: 1, Duration: 260ms]
<SNIP>
```

We find `admin` directory, but we have no access. Let's fuzz files inside `admin` directory
```
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt -X GET -u 'https://megabigtech-dev.azurewebsites.net/admin/FUZZ.aspx' -r -H 'Cookie: <REDACTED>'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://megabigtech-dev.azurewebsites.net/admin/FUZZ.aspx
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
 :: Header           : Cookie: <REDACTED>
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

<SNIP>
login                   [Status: 200, Size: 2383, Words: 642, Lines: 70, Duration: 420ms]
admin                   [Status: 200, Size: 2383, Words: 642, Lines: 70, Duration: 354ms]
<SNIP>
```

We found `login.aspx` and `admin.aspx` files. By retrieving `login.aspx`, we see that the codebase is stored in `login.aspx.cs`, thus after retrieving it, we see the hardcoded admin credentials 

![](bypass-azure-web-app-authentication-with-path-traversal-6.png)

Navigate to `https://megabigtech-dev.azurewebsites.net/admin/login.aspx` and authenticate using found credentials

![](bypass-azure-web-app-authentication-with-path-traversal-7.png)

We gain access to admin portal

![](bypass-azure-web-app-authentication-with-path-traversal-9.png)

# Attack Path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](bypass-azure-web-app-authentication-with-path-traversal-8.png)

