![LiongardPowershell logo](https://github.com/kacesensitive/Liongard-Powershell/blob/main/Liongard-Powershell.png)
# Liongard Powershell

A PowerShell module to interact with [the Liongard Public API](https://docs.liongard.com/reference#developer-guide).  

## Installing this module
This module will hopefully be available in [PowerShell Gallery](https://www.powershellgallery.com/packages/) soon!:

So for now download it from here and save all of the files somewhere in your `$PSModulePath`.

## Before you start
To get started with this module, you will need to log into your instance and create an Access Key and Secret (xxx.app.liongard.com/settings#tokens).  Write down the access key and secret.  You will not see them again!

Then, in your PowerShell session, teach it your secrets with `Set-LiongardKeys`.
```powershell
PS C:\> Set-LiongardKeys -AccessKey "blah" -AccessSecret "blah" -Instance "xxx"
```
You will need to do this every time you start a new PowerShell session;  this module does *not* store your keys for you!  For long-term storage, consider using a password manager, sticking the keys in your `$Profile` file, or using the [SecretManagement module](https://github.com/powershell/secretmanagement).  How you do this is an exercise left to the reader.

## Using this module
Now that that's been done, start using the Liongard API!

### Environments
You can look up Environments with the `Get-LiongardEnvironments` cmdlet.  With no arguments, it returns all of the environments.  You can also use the -EnvironmentID parameter to fetch a specific Environment.  The Liongard API returns data as objects that you can parse with other PowerShell cmdlets like `Format-List` and `Select-Object` (and, of course, everyone's favorite, `Out-GridView`!).
```powershell
PS C:\> Get-LiongardEnvironments -EnvironmentID 11 | Format-List
```
## Similar Logic For Below

### Agents
```powershell
PS C:\> Get-LiongardAgents -AgentID 35
```

### Launchpoints
```powershell
PS C:\> Get-LiongardLaunchpoints -LaunchpointID 3067
```

### Systems
```powershell
PS C:\>  Get-LiongardSystems -SystemID 307
```

### Change Detections
```powershell
PS C:\>  Get-LiongardDetections -DetectionID 3033
```

### Alerts
You can also pull back a list of all the current alerts in your instance.
```powershell
PS C:\>  Get-LiongardAlerts
```

### Metrics
You can also pull back a list of all the metrics created in your instance.
```powershell
PS C:\>  Get-LiongardMetrics
```

### Metric Value
You can even fetch Metric values for one or more systems.
```powershell
PS C:\>  Get-LiongardMetricValue -SystemIDs @(1,2,3,4) -MetricIDs @(1,2,3,4)
```

## After you're done
When you are finished, it is best practice to remove your API key from memory:
```powershell
PS C:\> Reset-LiongardKeys
```

## Legal Notices
This is not the official Liongard Powershell Module and is very much still 
in the development phase. Please use this module at your own risk.  I am 
not responsible if running Liongard Powershell commands somehow breaks
your Liongard deployment.
