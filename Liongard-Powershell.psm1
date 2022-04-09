# This function sets the LG keys in the environment variables
Function Set-LiongardKeys {
	[OutputType('void')]
	Param(
		[AllowNull()]
		[String] $AccessKey,

		[AllowNull()]
		[String] $AccessSecret,

		[AllowNull()]
		[String] $Instance
	)

	$env:LGAccessKey    = $AccessKey
	$env:LGAccessSecret = $AccessSecret
    $env:LGInstance     = $Instance
}

# This function clears the LG keys from the environment variables
Function Reset-LiongardKeys {
	[Alias('Remove-LiongardKeys')]
	[OutputType('void')]
	Param()

	Remove-Variable -Name $env:LGAccessKey
	Remove-Variable -Name $env:LGAccessSecret
    Remove-Variable -Name $env:LGInstance
}

Function Send-LiongardRequest {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String] $RequestToSend,

		[ValidateSet('GET', 'PUT', 'POST', 'DELETE')]
		[String] $Method = 'GET',
		
		[Parameter(Mandatory=$false)][hashtable] $Body
	)

    

	# Stop if our secrets have not been learned.
	If ($null -eq $env:LGAccessKey) {
		Throw [Data.NoNullAllowedException]::new('No secret access key has been provided.  Please run Set-LiongardKeys.')
	}
	If ($null -eq $env:LGAccessSecret) {
		Throw [Data.NoNullAllowedException]::new('No access key secret has been provided.  Please run Set-LiongardKeys.')
	}
	If ($null -eq $env:LGInstance) {
		Throw [Data.NoNullAllowedException]::new('No instance has been provided.  Please run Set-LiongardKeys.')
	}
	# It may be disabled by default before PowerShell 6.
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

	# Some new versions of PowerShell also support TLS 1.3.  If that is a valid
	If ([Net.SecurityProtocolType].GetMembers() -Contains 'Tls13') {
		[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
	}
	$Bytes = [System.Text.Encoding]::UTF8.GetBytes("$($env:LGAccessKey):$($env:LGAccessSecret)")
	$EncodedText =[Convert]::ToBase64String($Bytes)
	if ($Method) {
		$Content = (Invoke-WebRequest -Uri https://"$($env:LGInstance)".app.liongard.com/api/"$($RequestToSend)" -Headers @{"X-ROAR-API-KEY"="$($EncodedText)"} -Method $Method -Body $Body)
        Return $Content.Content | ConvertFrom-Json
	}
	if (!($Method)) {
        $Content = (Invoke-WebRequest -Uri https://"$($env:LGInstance)".app.liongard.com/api/"$($RequestToSend)" -Headers @{"X-ROAR-API-KEY"="$($EncodedText)"})
	    Return $Content.Content | ConvertFrom-Json
    }
}


# This function gets a list of or a specific Liongard Environment
Function Get-LiongardEnvironments {
	[CmdletBinding(DefaultParameterSetName='AllEnvironments')]
	Param(
		[Parameter(ParameterSetName='OneEnvironment')]
		[uint32] $EnvironmentID
	)

	$Request = 'v1/environments'
	If ($PSCmdlet.ParameterSetName -eq 'OneEnvironment') {
		$Request += "/$EnvironmentID"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list of or a specific Liongard Agent
Function Get-LiongardAgents {
	[CmdletBinding(DefaultParameterSetName='AllAgents')]
	Param(
		[Parameter(ParameterSetName='OneAgent')]
		[uint32] $AgentID
	)

	$Request = 'v1/agents'
	If ($PSCmdlet.ParameterSetName -eq 'OneAgent') {
		$Request += "/$AgentID"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list of or a specific Liongard Launchpoint
Function Get-LiongardLaunchpoints {
	[CmdletBinding(DefaultParameterSetName='AllLaunchpoints')]
	Param(
		[Parameter(ParameterSetName='OneLaunchpoint')]
		[uint32] $LaunchpointID
	)

	$Request = 'v1/launchpoints'
	If ($PSCmdlet.ParameterSetName -eq 'OneLaunchpoint') {
		$Request += "/$LaunchpointID"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list of or a specific Liongard System
Function Get-LiongardSystems {
	[CmdletBinding(DefaultParameterSetName='AllSystems')]
	Param(
		[Parameter(ParameterSetName='OneSystem')]
		[uint32] $SystemID
	)

	$Request = 'v1/systems'
	If ($PSCmdlet.ParameterSetName -eq 'OneSystem') {
		$Request += "/$SystemID/view"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list of or a specific Liongard Detection
Function Get-LiongardDetections {
	[CmdletBinding(DefaultParameterSetName='AllDetections')]
	Param(
		[Parameter(ParameterSetName='OneDetection')]
		[uint32] $DetectionID
	)

	$Request = 'v1/detections'
	If ($PSCmdlet.ParameterSetName -eq 'OneDetection') {
		$Request += "/$DetectionID"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list Liongard Alerts that have been raised
Function Get-LiongardAlerts {
	$Request = 'v1/tasks'
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list of metrics that have been created
Function Get-LiongardMetrics {
	$Request = 'v1/metrics'
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function Fetches Metric values for one or more systems
Function Get-LiongardMetricValue {
	Param(
		[Parameter(Mandatory=$true)][int[]]$SystemIDs,
		[Parameter(Mandatory=$true)][int[]]$MetricIDs
	)
	$Request = "v1/metrics/bulk/?systems="+"$($SystemIDs)"+"&metrics="+"$($MetricIDs)"+"&includeNonVisible=true"
	
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function creates an environemt
Function New-LiongardEnvironment {
	Param(
		[Parameter(Mandatory=$true)][string]$Name,
		[Parameter(Mandatory=$false)][string]$Description,
		[Parameter(Mandatory=$false)][int]$Parent
	)
	$Request = "v1/environments"
	
	Return (Send-LiongardRequest -RequestToSend $Request -Body @{"Name"="$($Name)"} -Method 'POST')
}

# This function deletes an environemt
Function Remove-LiongardEnvironment {
	Param(
		[Parameter(Mandatory=$true)][int]$ID
	)
	$Request = "v1/environments/$ID"
	
	Return (Send-LiongardRequest -RequestToSend $Request -Method 'DELETE')
}

# This function deletes an agent
Function Remove-LiongardAgent {
	Param(
		[Parameter(Mandatory=$true)][int]$ID
	)
	$Request = "v1/agents/$ID"
	
	Return (Send-LiongardRequest -RequestToSend $Request -Method 'DELETE')
}

# This function flsuhes an agent's job queue
Function Flush-LiongardAgent {
	Param(
		[Parameter(Mandatory=$true)][int]$ID
	)
	$Request = "v1/agents/$ID/flush"
	
	Return (Send-LiongardRequest -RequestToSend $Request -Method 'POST')
}

# This function downloads the Liongard Agent
Function Get-AgentInstaller {
    $X64 = 64
    $X86 = 32
    $InstallerName = "LiongardAgent-lts.msi"
    # left out for now..
    $DownloadURL = ""
    $InstallerPath = Join-Path $Env:TMP $InstallerName
    $DebugLog = Join-Path $Env:TMP LiongardDebug.log
    $MsiLog = Join-Path $Env:TMP install.log
    $WebClient = New-Object System.Net.WebClient
    try {
        $WebClient.DownloadFile($DownloadURL, $InstallerPath)
    } catch {
        Add-Content $DebugLog "$(Get-TimeStamp) $_.Exception.Message"
    }
    If ( ! (Test-Path $InstallerPath)) {
        $DownloadError = "Failed to download the Liongard Agent Installer from $DownloadURL"
        Add-Content $DebugLog "$(Get-TimeStamp) $DownloadError"
        throw $DownloadError
    }
}

# This function installs a server agent
Function Install-LiongardServerAgent {
	Param(
		[Parameter(Mandatory=$true)][string]$LiongardAgentName,
        [Parameter(Mandatory=$true)][string]$LiongardAgentEnv
	)
    Get-AgentInstaller
    $InstallerName = "LiongardAgent-lts.msi"
    $InstallerPath = Join-Path $Env:TMP $InstallerName
    $MsiLog = Join-Path $Env:TMP install.log
	If ( ! (Test-Path $InstallerPath)) {
        $InstallerError = "The installer was unexpectedly removed from $InstallerPath"
        Add-Content $DebugLog "$InstallerError"
        throw $InstallerError
    }
    $LiongardArgs = "LiongardURL=" + "`"$Env:LGInstance.app.liongard.com`"" + " LiongardACCESSKEY=" + $env:LGAccessKey + " LiongardACCESSSECRET=" + $env:LGAccessSecret + " LiongardAGENTNAME=" + "`"$LiongardAgentName`""
    If ($LiongardAgentEnv.Length -gt 0) {
        $LiongardArgs += " LiongardENVIRONMENT=" + "`"$LiongardAgentEnv`""
    }
    $InstallArgs = @(
        "/i"
        "`"$InstallerPath`""
        $LiongardArgs
        "/qn"
        "/L*V"
        "`"$MsiLog`""
        "/norestart"
    )
    Start-Process msiexec.exe -ArgumentList $InstallArgs -Wait -PassThru
}

# This function installs an endpoint agent
Function Install-LiongardEndpointAgent {
	Param(
		[Parameter(Mandatory=$true)][string]$LiongardAgentName,
        [Parameter(Mandatory=$true)][string]$LiongardAgentEnv
	)
    Get-AgentInstaller
    $InstallerName = "LiongardAgent-lts.msi"
    $InstallerPath = Join-Path $Env:TMP $InstallerName
    $MsiLog = Join-Path $Env:TMP install.log
	If ( ! (Test-Path $InstallerPath)) {
        $InstallerError = "The installer was unexpectedly removed from $InstallerPath"
        Add-Content $DebugLog "$InstallerError"
        throw $InstallerError
    }
    $LiongardArgs = "LiongardURL=" + "`"$Env:LGInstance.app.liongard.com`"" + " LiongardACCESSKEY=" + $env:LGAccessKey + " LiongardACCESSSECRET=" + $env:LGAccessSecret + " LiongardAGENTNAME=" + "`"$LiongardAgentName`"" + " LiongardAGENTTYPE=" + "customer-endpoint"
    If ($LiongardAgentEnv.Length -gt 0) {
        $LiongardArgs += " LiongardENVIRONMENT=" + "`"$LiongardAgentEnv`""
    }
    $InstallArgs = @(
        "/i"
        "`"$InstallerPath`""
        $LiongardArgs
        "/qn"
        "/L*V"
        "`"$MsiLog`""
        "/norestart"
    )
    Start-Process msiexec.exe -ArgumentList $InstallArgs -Wait -PassThru
}

Function Get-AgentLogs {
	Param (
		[string]$InstallDir = "C:\"
	)

	Get-EventLog -LogName LiongardAgentLog | ConvertTo-Csv | Out-File -FilePath "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\events-1.csv"

	Get-Content -Path "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\debug.log" | Out-File -FilePath "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\debug-1.log"
	Get-Content -Path "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\error.log" | Out-File -FilePath "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\error-1.log"
	Get-Content -Path "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\heartbeat.log" | Out-File -FilePath "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\heartbeat-1.log"
	Get-Content -Path "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\janitor.log" | Out-File -FilePath "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\janitor-1.log"
	Get-Content -Path "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\jobs.log" | Out-File -FilePath "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\jobs-1.log"
	Get-Content -Path "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\sqs.log" | Out-File -FilePath "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\sqs-1.log"

	$compress = @{
		LiteralPath= "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\events-1.csv", "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\debug-1.log", "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\error-1.log", "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\heartbeat-1.log", "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\janitor-1.log", "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\jobs-1.log", "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\sqs-1.log"
		CompressionLevel = "Fastest"
		DestinationPath = "$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\bundledlogs.zip"
		}
	Compress-Archive @compress -Update

	Remove-Item -Path @(
		"$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\events-1.csv",
		"$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\debug-1.log",
		"$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\error-1.log",
		"$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\heartbeat-1.log",
		"$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\janitor-1.log",
		"$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\jobs-1.log",
		"$InstallDir\Program Files (x86)\LiongardInc\LiongardAgent\logs\sqs-1.log"
	)
}