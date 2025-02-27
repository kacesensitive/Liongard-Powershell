![LiongardPowershell logo](https://github.com/kacesensitive/Liongard-Powershell/blob/main/Liongard-Powershell.png)
# Liongard Powershell

A PowerShell module to interact with [the Liongard Public API](https://docs.liongard.com/reference#developer-guide). This module supports both v1 and v2 of the Liongard API.

## Features
- Complete environment management (create, read, update, delete)
- Agent management and installation
- Metrics management and evaluation
- System information retrieval
- Launchpoint management
- Detection and alert monitoring
- Comprehensive logging and error handling
- Support for both PowerShell Desktop and Core editions

## Installing this module
```powershell
Install-Module -Name Liongard-Powershell -AllowPrerelease
```

## Getting Started
Before using the module, you'll need to obtain API credentials from your Liongard instance:

1. Log into your Liongard instance (xxx.app.liongard.com)
2. Navigate to Settings > API Tokens
3. Create a new Access Key and Secret (save these securely - they won't be shown again!)

Then, in your PowerShell session:
```powershell
# Set your API credentials
Set-LiongardKeys -AccessKey "your_access_key" -AccessSecret "your_access_secret" -Instance "your_instance"
```

## Environment Management
```powershell
# Get all environments
Get-LiongardEnvironments

# Get environment count
Get-LiongardEnvironmentCount

# Get specific environment
Get-LiongardEnvironmentById -EnvironmentID 123

# Create new environment
New-LiongardEnvironment -Name "New Environment" -Description "Test Environment"

# Update environment
$updateData = @{
    "Description" = "Updated description"
}
Update-LiongardEnvironment -EnvironmentID 123 -UpdateData $updateData

# Remove environment
Remove-LiongardEnvironment -EnvironmentID 123
```

## Agent Management
```powershell
# List all agents
Get-LiongardAgents

# Get specific agent
Get-LiongardAgents -AgentID 123

# Install new agent
Install-LiongardAgent -EnvironmentName "My Environment" -AgentName "Custom Agent Name"

# Install agent with direct credentials (no need to run Set-LiongardKeys first)
Install-LiongardAgent -EnvironmentName "My Environment" `
                     -AccessKey "your_access_key" `
                     -AccessSecret "your_access_secret" `
                     -Instance "your_instance"

# Install agent with custom path and all options
Install-LiongardAgent -EnvironmentName "My Environment" `
                     -AgentName "Custom Agent Name" `
                     -InstallPath "D:\Liongard" `
                     -AccessKey "your_access_key" `
                     -AccessSecret "your_access_secret" `
                     -Instance "your_instance"

# Uninstall agent
Uninstall-LiongardAgent                     # Remove agent and clean up all files
Uninstall-LiongardAgent -KeepLogs          # Remove agent but keep log files
Uninstall-LiongardAgent -LogPath "C:\Logs\uninstall.log"  # Specify custom log location

# Collect agent logs
Get-AgentLogs -LogLevel Information -OutputPath "C:\Logs"
```
