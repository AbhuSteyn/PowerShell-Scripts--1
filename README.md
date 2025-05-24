Below is the consolidated collection of all 10 advanced PowerShell scripts we discussed. You may save each script with its suggested filename. Each script is self-contained and includes detailed inline comments to explain its functionality, authentication method (typically Managed Identity), and key operational steps.

---

## 1. Deploy-ContainerAppFromTemplate.ps1

This script deploys a containerized application using an ARM template. It handles resource group creation, deployment via the ARM template, and then performs a health check against the application's public endpoint.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploys a containerized application using an ARM template.

.DESCRIPTION
    This script deploys a container app (for example, an Azure Container Instance) into a specified 
    resource group using an ARM template and a parameters file. It uses Managed Identity (via 
    Connect-AzAccount -Identity) so that no local credentials are required. Following deployment, a 
    health check is performed against the container’s public endpoint.

.PARAMETER ResourceGroupName
    The name of the resource group where the container app will be deployed.

.PARAMETER Location
    The Azure region for the resource group.

.PARAMETER DeploymentName
    A unique name for the deployment.

.PARAMETER TemplateFile
    The path to the ARM template JSON file.

.PARAMETER ParametersFile
    The path to the ARM template parameters JSON file.

.PARAMETER HealthEndpointPath
    (Optional) The relative path on the container app endpoint for health checks (default is "/").

.EXAMPLE
    .\Deploy-ContainerAppFromTemplate.ps1 -ResourceGroupName "ContAppRG" -Location "eastus" `
        -DeploymentName "ContAppDeploy01" -TemplateFile ".\containerTemplate.json" `
        -ParametersFile ".\containerParameters.json" -HealthEndpointPath "/health"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string]$Location,

    [Parameter(Mandatory=$true)]
    [string]$DeploymentName,

    [Parameter(Mandatory=$true)]
    [string]$TemplateFile,

    [Parameter(Mandatory=$true)]
    [string]$ParametersFile,

    [Parameter(Mandatory=$false)]
    [string]$HealthEndpointPath = "/"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Output "Resource Group '$ResourceGroupName' not found. Creating in $Location..."
    New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
} else {
    Write-Output "Resource Group '$ResourceGroupName' exists."
}

Write-Output "Starting deployment '$DeploymentName'..."
$deployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $DeploymentName `
    -TemplateFile $TemplateFile -TemplateParameterFile $ParametersFile -Verbose

if ($deployment.ProvisioningState -ne "Succeeded") {
    Write-Error "Deployment failed with state: $($deployment.ProvisioningState)"
    exit 1
} else {
    Write-Output "Deployment succeeded."
}

$endpoint = $deployment.Outputs.endpoint.value
if (-not $endpoint) {
    Write-Error "Deployment did not return an 'endpoint' output."
    exit 1
}

Write-Output "Deployed container app endpoint: $endpoint"
$healthUrl = "$endpoint$HealthEndpointPath"
Write-Output "Performing health check on $healthUrl..."

$maxRetries = 5
$retryDelay = 10
$healthy = $false

for ($i=1; $i -le $maxRetries; $i++) {
    try {
        $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Output "Health check succeeded."
            $healthy = $true
            break
        }
    } catch {
        Write-Output "Attempt $i: Health check failed. Retrying in $retryDelay seconds..."
        Start-Sleep -Seconds $retryDelay
    }
}

if (-not $healthy) {
    Write-Error "Health check failed after $maxRetries attempts."
    # Integration point: Add notifications here.
} else {
    Write-Output "Containerized application is healthy."
}

Disconnect-AzAccount
```

---

## 2. Automate-AzureDevOpsPipelineTrigger.ps1

This script triggers an Azure DevOps pipeline using the REST API. It retrieves a Personal Access Token (PAT) from Azure Key Vault and then queues a pipeline run securely.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Triggers an Azure DevOps pipeline via REST API.

.DESCRIPTION
    This script automates the triggering of an Azure DevOps build/release pipeline.
    It retrieves a PAT stored securely in Azure Key Vault and uses it to authenticate to
    the Azure DevOps REST API to queue a pipeline run.

.PARAMETER Organization
    The URL/name of the Azure DevOps organization, e.g. "dev.azure.com/YourOrg".

.PARAMETER Project
    The Azure DevOps project name.

.PARAMETER PipelineId
    The ID of the pipeline to trigger.

.PARAMETER VaultName
    The Azure Key Vault name where the PAT is stored.

.PARAMETER PatSecretName
    The name of the Key Vault secret containing the PAT.

.EXAMPLE
    .\Automate-AzureDevOpsPipelineTrigger.ps1 -Organization "dev.azure.com/YourOrg" `
        -Project "MyProject" -PipelineId 42 -VaultName "MyKeyVault" -PatSecretName "AzureDevOpsPAT"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Organization,

    [Parameter(Mandatory=$true)]
    [string]$Project,

    [Parameter(Mandatory=$true)]
    [int]$PipelineId,

    [Parameter(Mandatory=$true)]
    [string]$VaultName,

    [Parameter(Mandatory=$true)]
    [string]$PatSecretName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

Import-Module Az.KeyVault -ErrorAction Stop
$pat = (Get-AzKeyVaultSecret -VaultName $VaultName -Name $PatSecretName).SecretValueText
if (-not $pat) {
    Write-Error "Failed to retrieve PAT from Key Vault."
    exit 1
}

$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$pat"))
$uri = "https://dev.azure.com/$Organization/$Project/_apis/pipelines/$PipelineId/runs?api-version=6.0-preview.1"

Write-Output "Triggering Azure DevOps pipeline (ID $PipelineId)..."
$body = @{ resources = @{ repositories = @{ self = @{ refName = "refs/heads/main" } } } } | ConvertTo-Json
$headers = @{
    Authorization = "Basic $base64AuthInfo"
    "Content-Type" = "application/json"
}
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body

if ($response.id) {
    Write-Output "Pipeline triggered successfully. Run ID: $($response.id)"
} else {
    Write-Error "Failed to trigger the pipeline. Response: $response"
}

Disconnect-AzAccount
```

---

## 3. Deploy-AzureFunctionAppWithSlotSwap.ps1

This script deploys a new version of an Azure Function App to a staging slot, performs a health check on the staging environment, and then swaps the slot with production for zero-downtime deployment.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploys a Function App update to a staging slot and swaps it into production.

.DESCRIPTION
    The script deploys a deployment package (ZIP file) to a specified Function App slot (staging),
    performs a health check against the staging endpoint, and if healthy, swaps the staging slot 
    with production.

.PARAMETER ResourceGroupName
    The resource group containing the Function App.

.PARAMETER FunctionAppName
    The name of the Function App.

.PARAMETER PackagePath
    The local path to the deployment package (ZIP file).

.PARAMETER StagingSlotName
    The name of the staging slot (e.g., "staging").

.PARAMETER HealthCheckUrl
    The full URL used to check health on the staging slot.

.EXAMPLE
    .\Deploy-AzureFunctionAppWithSlotSwap.ps1 -ResourceGroupName "FuncRG" -FunctionAppName "MyFuncApp" `
        -PackagePath "C:\Deployments\MyFuncApp.zip" -StagingSlotName "staging" -HealthCheckUrl "https://myfuncapp-staging.azurewebsites.net/health"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory=$true)]
    [string]$PackagePath,

    [Parameter(Mandatory=$true)]
    [string]$StagingSlotName,

    [Parameter(Mandatory=$true)]
    [string]$HealthCheckUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

Write-Output "Deploying package to Function App slot '$StagingSlotName'..."
Publish-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -Slot $StagingSlotName -ArchivePath $PackagePath -Force

Write-Output "Waiting for deployment propagation..."
Start-Sleep -Seconds 20

Write-Output "Performing health check on $HealthCheckUrl..."
$maxRetries = 5
$retryDelay = 10
$healthy = $false

for ($i=1; $i -le $maxRetries; $i++) {
    try {
        $response = Invoke-WebRequest -Uri $HealthCheckUrl -UseBasicParsing -TimeoutSec 10
        if ($response.StatusCode -eq 200) {
            Write-Output "Health check succeeded."
            $healthy = $true
            break
        }
    } catch {
        Write-Output "Attempt $i: Health check failed. Retrying in $retryDelay seconds..."
        Start-Sleep -Seconds $retryDelay
    }
}

if (-not $healthy) {
    Write-Error "Health check failed after $maxRetries attempts. Aborting slot swap."
    exit 1
}

Write-Output "Health check passed. Initiating slot swap..."
Switch-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -SwapWithProduction -SourceSlotName $StagingSlotName
Write-Output "Slot swap completed successfully."

Disconnect-AzAccount
```

---

## 4. Monitor-AzureResourceHealthAndAutoRemediate.ps1

This script monitors Azure resource health via the Resource Health API and attempts auto-remediation actions (such as restarting a VM or web app) if a resource is found to be unhealthy.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Monitors Azure resource health and auto-remediates unhealthy resources.

.DESCRIPTION
    The script uses Managed Identity to authenticate and sets the subscription context. It then 
    retrieves resources of the specified type and checks their health. For unhealthy resources, it 
    attempts remedial actions—such as restarting a VM or a web app—based on resource type.

.PARAMETER SubscriptionId
    The Azure Subscription ID.

.PARAMETER ResourceType
    The resource type to monitor (e.g., "Microsoft.Compute/virtualMachines" or "Microsoft.Web/sites").

.EXAMPLE
    .\Monitor-AzureResourceHealthAndAutoRemediate.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ResourceType "Microsoft.Compute/virtualMachines"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$true)]
    [string]$ResourceType
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

Write-Output "Setting context to subscription: $SubscriptionId"
Set-AzContext -SubscriptionId $SubscriptionId

Write-Output "Retrieving resources of type '$ResourceType'..."
$resources = Get-AzResource -ResourceType $ResourceType
if (-not $resources) {
    Write-Output "No resources of type '$ResourceType' found."
    Disconnect-AzAccount
    exit 0
}

foreach ($resource in $resources) {
    Write-Output "Checking health for resource: $($resource.Name) in $($resource.ResourceGroupName)"
    try {
        $health = Get-AzResourceHealth -ResourceId $resource.ResourceId
    } catch {
        Write-Output "Could not determine health for resource: $($resource.Name)."
        continue
    }

    if ($health.AvailabilityStatus -ne "Available") {
        Write-Output "Resource '$($resource.Name)' is unhealthy (Status: $($health.AvailabilityStatus))."
        if ($ResourceType -eq "Microsoft.Compute/virtualMachines") {
            Write-Output "Restarting virtual machine '$($resource.Name)'."
            Restart-AzVM -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -Force
        } elseif ($ResourceType -eq "Microsoft.Web/sites") {
            Write-Output "Restarting web app '$($resource.Name)'."
            Restart-AzWebApp -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name
        }
    } else {
        Write-Output "Resource '$($resource.Name)' is healthy."
    }
}

Disconnect-AzAccount
```

---

## 5. Backup-And-Restore-AzureSQLDatabase.ps1

This script exports an Azure SQL Database to a BACPAC file stored in Blob Storage and optionally restores it to create a new database. It uses Managed Identity for secure authentication.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Back up an Azure SQL Database to a BACPAC file and optionally restore it.

.DESCRIPTION
    The script exports an Azure SQL Database to a BACPAC file stored in a specified Blob container.
    Optionally, if a restore database name is provided, the script will import the BACPAC to create 
    a new database instance.

.PARAMETER ResourceGroupName
    The name of the resource group containing the SQL Server.

.PARAMETER ServerName
    The name of the Azure SQL Server.

.PARAMETER DatabaseName
    The name of the source database to back up.

.PARAMETER StorageAccountName
    The storage account used to hold the BACPAC file.

.PARAMETER ContainerName
    The Blob container name for the backup file.

.PARAMETER BacpacFileName
    The desired name of the BACPAC file.

.PARAMETER RestoreDatabaseName
    (Optional) If provided, triggers a restore operation to create a new database with this name.

.EXAMPLE
    .\Backup-And-Restore-AzureSQLDatabase.ps1 -ResourceGroupName "SQLRG" -ServerName "myserver" `
        -DatabaseName "MyDatabase" -StorageAccountName "mystorageacct" -ContainerName "backups" `
        -BacpacFileName "MyDBBackup.bacpac" -RestoreDatabaseName "MyDatabaseRestore"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string]$ServerName,

    [Parameter(Mandatory=$true)]
    [string]$DatabaseName,

    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory=$true)]
    [string]$ContainerName,

    [Parameter(Mandatory=$true)]
    [string]$BacpacFileName,

    [Parameter(Mandatory=$false)]
    [string]$RestoreDatabaseName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

Write-Output "Creating storage context for '$StorageAccountName'..."
$storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -UseManagedIdentity

$container = Get-AzStorageContainer -Context $storageContext -Name $ContainerName -ErrorAction SilentlyContinue
if (-not $container) {
    Write-Output "Container '$ContainerName' not found. Creating..."
    New-AzStorageContainer -Context $storageContext -Name $ContainerName | Out-Null
}

$containerUri = (Get-AzStorageContainer -Context $storageContext -Name $ContainerName).CloudBlobContainer.Uri.AbsoluteUri.TrimEnd("/")
$bacpacUri = "$containerUri/$BacpacFileName"

Write-Output "Exporting database '$DatabaseName' to BACPAC at $bacpacUri..."
Export-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName -DatabaseName $DatabaseName `
    -StorageKeyType "ManagedIdentity" -StorageUri $bacpacUri -StorageAccountName $StorageAccountName

Write-Output "Database export completed."

if ($PSBoundParameters.ContainsKey("RestoreDatabaseName")) {
    Write-Output "Restoring database to create '$RestoreDatabaseName'..."
    Import-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $ServerName `
        -DatabaseName $RestoreDatabaseName -Edition "Standard" -ServiceObjectiveName "S0" `
        -StorageKeyType "ManagedIdentity" -StorageUri $bacpacUri -StorageAccountName $StorageAccountName
    Write-Output "Database restoration completed."
}

Disconnect-AzAccount
```

---

## 6. Get-AzureADUserDetailsGraphAPI.ps1

This script retrieves detailed information about an Azure AD user via Microsoft Graph API. It acquires an access token using Managed Identity.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
   Retrieves Azure AD user details using Microsoft Graph API.

.DESCRIPTION
   Authenticates using Managed Identity and obtains an access token for the Microsoft Graph API.
   The script retrieves detailed information about a user based on their User Principal Name (UPN).

.PARAMETER UserPrincipalName
   The UPN (or email) of the Azure AD user to query.

.EXAMPLE
   .\Get-AzureADUserDetailsGraphAPI.ps1 -UserPrincipalName "user@contoso.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

$graphToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
if (-not $graphToken) {
    Write-Error "Unable to retrieve access token for Microsoft Graph."
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $graphToken"
    "Content-Type"  = "application/json"
}
$uri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

Write-Output "User Details:"
$response | ConvertTo-Json -Depth 5

Disconnect-AzAccount
```

---

## 7. Query-AzureResourceGraph.ps1

This script runs a custom query against Azure resources using the Resource Graph module. The query syntax is KQL-like.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
   Executes an Azure Resource Graph query.

.DESCRIPTION
   Authenticates using Managed Identity and uses the Az.ResourceGraph module to run
   a custom query against your Azure resources. The query must be provided in KQL-like syntax.

.PARAMETER Query
   The Resource Graph query string.

.EXAMPLE
   .\Query-AzureResourceGraph.ps1 -Query "Resources | where type=='microsoft.compute/virtualmachines' | project name, location, properties.hardwareProfile.vmSize"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Query
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity
Import-Module Az.ResourceGraph -ErrorAction Stop

Write-Output "Executing Resource Graph query..."
$results = Search-AzGraph -Query $Query
Write-Output "Query Results:"
$results.Data | ConvertTo-Json -Depth 5

Disconnect-AzAccount
```

---

## 8. Query-LogAnalyticsKusto.ps1

This script executes a Kusto Query Language (KQL) query against an Azure Log Analytics workspace.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
   Executes a KQL query against a Log Analytics workspace.

.DESCRIPTION
   Authenticates using Managed Identity and runs a Kusto Query Language (KQL) query using the 
   Az.OperationalInsights module. Results are returned in JSON format.

.PARAMETER WorkspaceId
   The ID of the Log Analytics workspace.

.PARAMETER Query
   The KQL query string to execute.

.EXAMPLE
   .\Query-LogAnalyticsKusto.ps1 -WorkspaceId "your-workspace-id" -Query "Heartbeat | summarize count() by Computer"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory=$true)]
    [string]$Query
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity
Import-Module Az.OperationalInsights -ErrorAction Stop

Write-Output "Executing query against workspace $WorkspaceId..."
$result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -ErrorAction Stop
Write-Output "Query Results:"
$result.Results | ConvertTo-Json -Depth 5

Disconnect-AzAccount
```

---

## 9. Query-AzureADGroupMembersGraphAPI.ps1

This script retrieves the members of a specified Azure AD group using Microsoft Graph API.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
   Retrieves members of a specified Azure AD group using Microsoft Graph API.

.DESCRIPTION
   This script uses Managed Identity to obtain an access token for Microsoft Graph API.
   It then queries the endpoint for the members of the specified Azure AD group and outputs
   their display names and email addresses.

.PARAMETER GroupId
   The unique identifier (objectId) of the Azure AD group.

.EXAMPLE
   .\Query-AzureADGroupMembersGraphAPI.ps1 -GroupId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GroupId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

$graphToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
if (-not $graphToken) {
    Write-Error "Unable to retrieve access token for Microsoft Graph."
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $graphToken"
    "Content-Type"  = "application/json"
}
$uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members"
Write-Output "Querying members of group ID $GroupId..."
$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

if ($response.value -and $response.value.Count -gt 0) {
    Write-Output "Members of Group:"
    foreach ($member in $response.value) {
        Write-Output " - Display Name: $($member.displayName), Email: $($member.mail)"
    }
} else {
    Write-Output "No members found or group is empty."
}

Disconnect-AzAccount
```

---

## 10. Update-AzureADUserGraphAPI.ps1

This script updates properties of an Azure AD user (e.g., the display name) via Microsoft Graph API using a PATCH request.

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Updates properties of an Azure AD user using Microsoft Graph API.

.DESCRIPTION
    This script updates an Azure AD user’s details (for example, their displayName) via
    Microsoft Graph API. It uses Managed Identity to obtain an access token and sends a PATCH
    request to update the user. This is useful when automating user property changes in your
    organization.

.PARAMETER UserPrincipalName
    The User Principal Name (email) of the Azure AD user to update.

.PARAMETER NewDisplayName
    The new display name to set for the user.

.EXAMPLE
    .\Update-AzureADUserGraphAPI.ps1 -UserPrincipalName "user@contoso.com" -NewDisplayName "John Doe Updated"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true)]
    [string]$NewDisplayName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Output "Authenticating using Managed Identity..."
Connect-AzAccount -Identity

$graphToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
if (-not $graphToken) {
    Write-Error "Unable to retrieve access token for Microsoft Graph."
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $graphToken"
    "Content-Type"  = "application/json"
}

$uri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName"
$body = @{
    "displayName" = $NewDisplayName
} | ConvertTo-Json

try {
    Write-Output "Updating user '$UserPrincipalName' with new display name '$NewDisplayName'..."
    Invoke-RestMethod -Uri $uri -Headers $headers -Method Patch -Body $body
    Write-Output "User updated successfully."
} catch {
    Write-Error "Failed to update user. $_"
}

Disconnect-AzAccount
```

---

Each of these scripts can be saved individually (with the provided filename suggestions) and used as part of your advanced Azure cloud automation and DevOps toolkit. For detailed usage instructions, refer to the consolidated README provided earlier. Enjoy automating your cloud operations!
