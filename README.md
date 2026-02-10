**Microsoft 365 BEC Investigation – DFIR Walkthrough**
**Scenario Overview**

This investigation focused on a suspected Business Email Compromise (BEC) within a Microsoft 365 tenant.

**Available artefacts included:**

azure-export-audit-dfir.csv (Unified Audit Log export)

Suspicious emails (.eml files)

Exchange Online activity logs

Inbox rule activity

Folder creation and rename events

**The objective was to determine:**

The two IPv4 addresses used by the Threat Actor (TA)

The name of the inbox folder created during the compromise

The malicious inbox rule behaviour

Indicators of attacker tradecraft (Living Off the Land, log evasion, etc.)

**Investigation Process**

**Initial Log Triage**

The primary artefact was:

azure-export-audit-dfir.csv


This contained:

Operation,
CreationDate,
UserId,
AuditData (JSON blob)

The AuditData field required parsing to extract:

ClientIP,
FolderPath,
Rule parameters,
Login activity

**PowerShell Challenges & Lessons Learned**

**Common Issues Encountered**

**1. Wildcard path errors**

Import-Csv .\*.csv


Error:

Cannot perform operation because the wildcard path did not resolve to a file


Root cause: No CSV files in working directory.

Fix:

Import-Csv .\azure-export-audit-dfir.csv

**2. JSON parsing failures**

Many attempts failed due to:

Incorrect brace closure

Nested JSON inside CSV quotes

Improper use of try/catch

Correct pattern used:

Import-Csv .\azure-export-audit-dfir.csv |
ForEach-Object {
    try {
        $j = $_.AuditData | ConvertFrom-Json
        $j.ClientIP
    } catch {}
}

**3. Regex escaping issues**

Incorrect:

-match "\d+.\d+.\d+.\d+"


Correct:

-match '^\d{1,3}(\.\d{1,3}){3}$'


**Lesson:**

Use single quotes for regex

Escape dots properly

Anchor IPv4 patterns

**Identifying Threat Actor IP Addresses**

**Step 1: Search for Login & Inbox Rule activity**

Select-String -Path .\azure-export-audit-dfir.csv -Pattern "UserLoggedIn|InboxRule"

**Step 2: Extract IPv4 addresses only**

Select-String -Path .\azure-export-audit-dfir.csv -Pattern '\b\d{1,3}(\.\d{1,3}){3}\b' -AllMatches |
ForEach-Object { $_.Matches.Value } |
Sort-Object -Unique

**Step 3: Filter out Microsoft infrastructure IPs**

Microsoft IP ranges observed:

109.175.196.x
147.243.x.x


These belonged to:

Microsoft OWA

SharePoint

Exchange Online back-end

Final Attacker IPs Identified

**Due to BTLO policy I can't put the IP's here**

These were: 

External

Associated with login + inbox rule creation

Not part of Microsoft cloud ranges

Folder Creation During Compromise

Initial assumption:

Folder created via New-MailboxFolder

No such event found.

Correct approach:
Search for:

Operation = FolderCreated
Operation = FolderRenamed


Example log:

Operation: FolderCreated
User: becky.lorray@tempestasenergy.com


The folder path was located within:

"FolderPath"


or

"DestinationRelativeUrl"

Final Folder Name Identified

**Due to BTLO policy I cannot put the names here**

**Malicious Inbox Rule Analysis**

Log evidence:

Operation: New-InboxRule


AuditData parameters showed:

"BodyContainsWords": "Confirmation"
"SubjectOrBodyContainsWords": "Withdrawal"
"DeleteMessage": "True"
"StopProcessingRules": "True"

**Impact**

The rule:

Monitored keywords related to financial transactions

Automatically deleted emails

Prevented user visibility

Enabled silent transaction fraud

This is classic BEC tradecraft.

**Living Off the Land (LOTL)**

The attacker did NOT:

Deploy malware

Drop binaries

Use exploit kits

Instead they leveraged:

Exchange Online

Inbox Rules

Native Microsoft 365 authentication

OWA

SharePoint

This is Living Off the Land within SaaS.

**Why it matters:**

Minimal detection footprint

Uses legitimate infrastructure

Blends into audit logs

**Email Source Analysis**

Viewing “Message Source” revealed:

Received: from CWXP123MB3304.GBRP123.PROD.OUTLOOK.COM


These were Microsoft internal mail servers.

**Key takeaway:**

Header analysis confirmed routing but did NOT expose attacker IP — login IP must be pulled from Unified Audit Logs instead.

**Importance of Meticulous Note Taking**

Critical investigative habits:

✔ Track timestamps precisely

✔ Correlate login → inbox rule → folder activity

✔ Distinguish system actions (NT AUTHORITY) from user actions

✔ Separate Microsoft cloud IPs from external IPs

✔ Record every failed PowerShell attempt

Why?

Because DFIR is iterative.

You will:

Break commands

Misinterpret logs

Chase false positives

Documentation ensures:

Repeatability

Defensibility

Clear reporting

Clean executive summaries

**Final Findings Summary**

Finding	Result

Compromise Type	Business Email Compromise (BEC)

Initial Access	External login to M365

Attacker Technique	Inbox rule creation

Persistence	Folder creation & email deletion

Infrastructure Used	Microsoft 365 (LOTL)

Attacker IPs	

Folder Created	

**Key Lessons**

Microsoft infrastructure IPs can mislead investigations

Inbox rules are a primary BEC persistence mechanism

JSON inside CSV requires careful parsing

Regex in PowerShell is unforgiving

DFIR requires patience more than speed

**Suggested Improvements**

Enable mailbox auditing alerts

Enforce MFA with conditional access

Disable legacy authentication

Alert on inbox rule creation

Monitor impossible travel
