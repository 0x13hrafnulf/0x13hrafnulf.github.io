---
title: Identify IAM Breaches with CloudTrail and Athena
description: Identify IAM Breaches with CloudTrail and Athena
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
As part of our proactive monitoring of the web for our client, the multinational shipping company Huge Logistics, we found authentication details for their internal tracking database leaked on Pastebin (https://pastebin.com/raw/Kzs3vpHK). It lists usernames and unencrypted passwords for the application, and the client is worried that attackers may be able to use this information to gain access to their cloud environment. You have been tasked with identifying any malicious IAM activity and any compromised IAM accounts. The tools to be used for this engagement are AWS CloudTrail and Amazon Athena.

# Walkthrough
## Querying Athena using the AWS CLI
Authenticate using given credentials
```
└─$ aws sts get-caller-identity
{
    "UserId": "AIDARQVIRZ4UP6UGDSKDZ",
    "Account": "104506445608",
    "Arn": "arn:aws:iam::104506445608:user/athena-user"
}

```

Use the `start-query-execution` action with the SQL to identify users that successfully logged in during the time period.
```
└─$ aws athena start-query-execution --query-string "SELECT useridentity, sourceipaddress FROM cloudtrail_logs_aws_cloudtrail_logs_104506445608_4e45885e WHERE eventname = 'ConsoleLogin' AND eventTime LIKE '%2023-08-30%' AND responseelements LIKE '%Success%'" --result-configuration OutputLocation="s3://aws-athena-query-results-104506445608-us-east-1/Unsaved/"
{
    "QueryExecutionId": "eba87119-2e8e-4f72-ac25-aa7bb1f46b24"
}

```

This will start the job. We receive `QueryExecutionId` as output. Next, copy the GUID (required for `--query-execution-id`) and run the command below which will write the output to file
```
└─$ aws athena get-query-results --query-execution-id eba87119-2e8e-4f72-ac25-aa7bb1f46b24 --query 'ResultSet.Rows[].Data[].VarCharValue' --output text > results.txt
   
```

By using the AWK, we can find the compromised IAM user and the IP address that the request originated from. It creates headers for "Username" and "IP Address". As it processes each line from the "results.txt" file, it searches for patterns matching usernames and IP addresses. For each unique combination of username and IP found, it prints them and ensures that no duplicate pairs are displayed.
```
└─$ awk '
BEGIN {
    printf "%-12s\t%-15s\n", "Username", "IP Address"
}
{
    line = $0
    while (line ~ /username=/) {
        sub(/.*username=/, "", line)
        if (index(line, ",") > 0) {
            username = substr(line, 1, index(line, ",") - 1)
            sub(/[^,]*,/, "", line)
        } else {
            username = line
            line = ""
        }
        if (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
            ip = substr(line, RSTART, RLENGTH)
        } else {
            ip = ""
        }
        uniqueKey = username ":" ip
        if (!(uniqueKey in seen)) {
            printf "%-12s\t%-15s\n", username, ip
            seen[uniqueKey] = 1
        }
    }
}
' results.txt
Username        IP Address     
pfisher         195.70.73.130
```

Now, let's look for a list of the unique IP addresses and user agent key pairs from that time period
```
└─$ aws athena start-query-execution --query-string "SELECT sourceipaddress, useragent FROM cloudtrail_logs_aws_cloudtrail_logs_104506445608_4e45885e WHERE eventname = 'ConsoleLogin' AND eventTime LIKE '%2023-08-30%'" --result-configuration OutputLocation="s3://aws-athena-query-results-104506445608-us-east-1/Unsaved/"
{
    "QueryExecutionId": "5be513f5-6290-4248-b7ce-7f0864a312f9"
}

```

Export the results
```
└─$ aws athena get-query-results --query-execution-id 5be513f5-6290-4248-b7ce-7f0864a312f9 --query 'ResultSet.Rows[].Data[].VarCharValue' --output text > results.txt
     
```

Now parse the results
```
└─$ awk '
BEGIN { 
  print " IP Address\t User Agent"
} 
{
  user_agent = "";
  for (i=3; i<=NF; i++) {
    # Check if the field is an IP address using regex.
    if ($i ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/) {
      if (user_agent != "") {
        uniqueKey = ip " " user_agent;
        if (!(uniqueKey in seen)) {
          print " "ip "\t " user_agent;
          seen[uniqueKey] = 1;
        }
        user_agent = "";
      }
      ip = $i;
    } else {
      if (user_agent != "") {
        user_agent = user_agent " " $i;
      } else {
        user_agent = $i;
      }
    }
  }
  if (ip && user_agent) {
    uniqueKey = ip " " user_agent;
    if (!(uniqueKey in seen)) {
      print " "ip "\t " user_agent;
      seen[uniqueKey] = 1;
    }
  }
}' results.txt
 IP Address      User Agent
 195.70.73.130   Go-http-client/1.1
 195.70.73.130   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
```

To get the flag
```
└─$ aws athena start-query-execution --query-string "SELECT sourceipaddress, useragent FROM cloudtrail_logs_aws_cloudtrail_logs_104506445608_4e45885e WHERE eventname = 'ConsoleLogin' AND eventTime LIKE '%2023-09-%'" --result-configuration OutputLocation="s3://aws-athena-query-results-104506445608-us-east-1/Unsaved/" 
{
    "QueryExecutionId": "20ea9f7c-8863-4100-9e13-d5c264991fce"
}
```
```
└─$ aws athena get-query-results --query-execution-id 20ea9f7c-8863-4100-9e13-d5c264991fce --query 'ResultSet.Rows[].Data[].VarCharValue' --output text > results.txt
```
```
└─$ awk '
BEGIN {                                                                          
  print " IP Address\t User Agent"
} 
{
  user_agent = "";
  for (i=3; i<=NF; i++) {
    # Check if the field is an IP address using regex.
    if ($i ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}$/) {
      if (user_agent != "") {
        uniqueKey = ip " " user_agent;
        if (!(uniqueKey in seen)) {
          print " "ip "\t " user_agent;
          seen[uniqueKey] = 1;
        }
        user_agent = "";
      }
      ip = $i;
    } else {
      if (user_agent != "") {
        user_agent = user_agent " " $i;
      } else {
        user_agent = $i;
      }
    }
  }
  if (ip && user_agent) {
    uniqueKey = ip " " user_agent;
    if (!(uniqueKey in seen)) {
      print " "ip "\t " user_agent;
      seen[uniqueKey] = 1;
    }
  }
}' results.txt
 IP Address      User Agent
 195.70.73.130   <REDACTED>
```

## Querying Athena using the AWS Console
We can do the same using AWS Console. Login using given credentials. Then navigate to `Athena`. Paste the query below, which identifies the successful console logins during that period of time.
```
SELECT * 
FROM cloudtrail_logs_aws_cloudtrail_logs_104506445608_4e45885e
WHERE eventname = 'ConsoleLogin'
AND eventTime LIKE '%2023-08-30%'
AND responseelements LIKE '%Success%'
```

![](identify-iam-breaches-with-cloudtrail-and-athena-1.png)

Run the query. The query reveals a successful login for the IAM user `pfisher`.

![](identify-iam-breaches-with-cloudtrail-and-athena-2.png)

We can also check the total number of AWS console login attempts on this date
```
SELECT count(*)
FROM cloudtrail_logs_aws_cloudtrail_logs_104506445608_4e45885e
WHERE eventname = 'ConsoleLogin'
AND eventTime LIKE '%2023-08-30%'
```

![](identify-iam-breaches-with-cloudtrail-and-athena-3.png)

Let's also retrieve the user agent and IP address key pairs. But it should be noted that, automated tools allow attackers to specify a custom user agent in an attempt to blend in with legitimate traffic.
```
SELECT DISTINCT sourceipaddress, useragent
FROM cloudtrail_logs_aws_cloudtrail_logs_104506445608_4e45885e
WHERE eventname = 'ConsoleLogin'
AND eventTime LIKE '%2023-08-30%'
```

![](identify-iam-breaches-with-cloudtrail-and-athena-4.png)

Since, we are confident that `phisher` was compromised (we can also confirm it by checking last login/active time in IAM), we just have to follow the playbook to remediate.