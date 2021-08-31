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
		[String] $Method = 'GET'
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
	$Content = (Invoke-WebRequest -Uri https://"$($env:LGInstance)".app.liongard.com/api/"$($RequestToSend)" -Headers @{"X-ROAR-API-KEY"="$($EncodedText)"})
	Return $Content.Content | ConvertFrom-Json
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
	Write-Host $Request
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
	Write-Host $Request
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
	Write-Host $Request
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
	Write-Host $Request
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
	Write-Host $Request
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list Liongard Alerts that have been raised
Function Get-LiongardAlerts {
	$Request = 'v1/tasks'
	Write-Host $Request
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function gets a list of metrics that have been created
Function Get-LiongardMetrics {
	$Request = 'v1/metrics'
	Write-Host $Request
	Return (Send-LiongardRequest -RequestToSend $Request)
}

# This function Fetches Metric values for one or more systems
Function Get-LiongardMetricValue {
	Param(
		[Parameter(Mandatory=$true)][int[]]$SystemIDs,
		[Parameter(Mandatory=$true)][int[]]$MetricIDs
	)
	$Request = "/v1/metrics/bulk/?systems="+"$($SystemIDs)"+"&metrics="+"$($MetricIDs)"+"&includeNonVisible=true"
	Write-Host $Request
	Return (Send-LiongardRequest -RequestToSend $Request)
}
