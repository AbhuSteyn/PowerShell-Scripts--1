
# Advanced Azure Cloud Automation & DevOps PowerShell Scripts

This repository contains **10 advanced PowerShell scripts** that implement genuine cloud automation and DevOps scenarios in Azure. These scripts cover real-world use cases such as:

1. **Deploying a Containerized Application**  
   - **Deploy-ContainerAppFromTemplate.ps1**  
     Deploys containerized workloads via an ARM template and performs a post-deployment health check.

2. **Triggering Azure DevOps Pipelines**  
   - **Automate-AzureDevOpsPipelineTrigger.ps1**  
     Securely triggers a CI/CD pipeline in Azure DevOps by retrieving a PAT from Azure Key Vault.

3. **Zero-Downtime Function App Deployment**  
   - **Deploy-AzureFunctionAppWithSlotSwap.ps1**  
     Deploys an updated package to a staging slot, verifies application health, and executes a slot swap.

4. **Resource Health Monitoring and Auto-Remediation**  
   - **Monitor-AzureResourceHealthAndAutoRemediate.ps1**  
     Continuously monitors your Azure resources (e.g., virtual machines or web apps) and auto-remediates issues.

5. **Azure SQL Database Backup and Restore**  
   - **Backup-And-Restore-AzureSQLDatabase.ps1**  
     Exports an Azure SQL Database to a BACPAC file in Blob Storage and optionally restores it.

6. **Retrieving Azure AD User Details via Microsoft Graph API**  
   - **Get-AzureADUserDetailsGraphAPI.ps1**  
     Uses Managed Identity to obtain an access token and query Microsoft Graph for detailed user information.

7. **Querying Azure Resources with Resource Graph**  
   - **Query-AzureResourceGraph.ps1**  
     Uses the Az.ResourceGraph module to run custom queries (with KQL-like syntax) against your resource inventory.

8. **Log Analytics Querying using Kusto Query Language**  
   - **Query-LogAnalyticsKusto.ps1**  
     Executes KQL queries against a Log Analytics workspace via the Az.OperationalInsights module.

9. **Querying Azure AD Group Members using Graph API**  
   - **Query-AzureADGroupMembersGraphAPI.ps1**  
     Retrieves members of a specified Azure AD group by querying Microsoft Graph API.

10. **Updating Azure AD User Properties using Graph API**  
    - **Update-AzureADUserGraphAPI.ps1**  
      Updates properties (for example, the display name) of a specified Azure AD user via Microsoft Graph API.

## Prerequisites

- **Azure PowerShell Modules:**  
  Install the following modules if not already installed:
  ```powershell
  Install-Module Az.Accounts
  Install-Module Az.Resources
  Install-Module Az.Storage
  Install-Module Az.KeyVault
  Install-Module Az.Websites
  Install-Module Az.Sql
  Install-Module Az.ResourceGraph
  Install-Module Az.OperationalInsights
  ```
- **Managed Identity:**  
  For most scripts, it is recommended to run on an Azure resource (e.g., VM, App Service, or Function App) with Managed Identity enabled. This allows secure authentication without local credential storage.
- **Azure Key Vault:**  
  For scripts accessing secrets (e.g., the Azure DevOps PAT), ensure your Key Vault is configured with the required secrets.
- **Azure DevOps Setup:**  
  For pipeline triggering, ensure your organization and project are correctly configured in Azure DevOps, with your PAT stored securely in Key Vault.

## How to Run

1. **Open a PowerShell session** (with appropriate privileges) and navigate to the repository folder.

2. **Execute the desired script with necessary parameters.** For example:

   - **Deploy a containerized app:**
     ```powershell
     .\Deploy-ContainerAppFromTemplate.ps1 -ResourceGroupName "ContAppRG" -Location "eastus" `
         -DeploymentName "ContAppDeploy01" -TemplateFile ".\containerTemplate.json" `
         -ParametersFile ".\containerParameters.json" -HealthEndpointPath "/health"
     ```

   - **Trigger an Azure DevOps pipeline:**
     ```powershell
     .\Automate-AzureDevOpsPipelineTrigger.ps1 -Organization "dev.azure.com/YourOrg" `
         -Project "MyProject" -PipelineId 42 -VaultName "MyKeyVault" -PatSecretName "AzureDevOpsPAT"
     ```

   - **Deploy and swap a Function App slot:**
     ```powershell
     .\Deploy-AzureFunctionAppWithSlotSwap.ps1 -ResourceGroupName "FuncRG" -FunctionAppName "MyFuncApp" `
         -PackagePath "C:\Deployments\MyFuncApp.zip" -StagingSlotName "staging" `
         -HealthCheckUrl "https://myfuncapp-staging.azurewebsites.net/health"
     ```

   - **Monitor and auto-remediate resource health:**
     ```powershell
     .\Monitor-AzureResourceHealthAndAutoRemediate.ps1 -SubscriptionId "your-subscription-id" `
         -ResourceType "Microsoft.Compute/virtualMachines"
     ```

   - **Backup and optionally restore an Azure SQL Database:**
     ```powershell
     .\Backup-And-Restore-AzureSQLDatabase.ps1 -ResourceGroupName "SQLRG" -ServerName "myserver" `
         -DatabaseName "MyDatabase" -StorageAccountName "mystorageacct" -ContainerName "backups" `
         -BacpacFileName "MyDBBackup.bacpac" -RestoreDatabaseName "MyDatabaseRestore"
     ```

   - **Retrieve detailed Azure AD user information:**
     ```powershell
     .\Get-AzureADUserDetailsGraphAPI.ps1 -UserPrincipalName "user@contoso.com"
     ```

   - **Query Azure resources with Resource Graph:**
     ```powershell
     .\Query-AzureResourceGraph.ps1 -Query "Resources | where type=='microsoft.compute/virtualmachines' | project name, location, properties.hardwareProfile.vmSize"
     ```

   - **Query Log Analytics workspace data:**
     ```powershell
     .\Query-LogAnalyticsKusto.ps1 -WorkspaceId "your-workspace-id" -Query "Heartbeat | summarize count() by Computer"
     ```

   - **Query Azure AD group members:**
     ```powershell
     .\Query-AzureADGroupMembersGraphAPI.ps1 -GroupId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
     ```

   - **Update Azure AD user properties:**
     ```powershell
     .\Update-AzureADUserGraphAPI.ps1 -UserPrincipalName "user@contoso.com" -NewDisplayName "John Doe Updated"
     ```

## Contributing

Contributions are welcome. Please feel free to fork this repository and submit pull requests for improvements or additional use cases. Your feedback is highly appreciated!

## License

This project is licensed under the MIT License.
```

---

This README outlines each of the 10 scripts along with their prerequisites and usage examples. Enjoy automating and streamlining your Azure cloud operations and DevOps workflows!
