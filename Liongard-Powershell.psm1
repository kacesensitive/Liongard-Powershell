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

	if ($env:LGAccessKey) {
		Remove-Item -Path "Env:LGAccessKey" -ErrorAction SilentlyContinue
	}
	if ($env:LGAccessSecret) {
		Remove-Item -Path "Env:LGAccessSecret" -ErrorAction SilentlyContinue
	}
	if ($env:LGInstance) {
		Remove-Item -Path "Env:LGInstance" -ErrorAction SilentlyContinue
	}
}

Function Send-LiongardRequest {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String] $RequestToSend,

		[ValidateSet('GET', 'PUT', 'POST', 'DELETE')]
		[String] $Method = 'GET',
		
		[Parameter(Mandatory=$false)][hashtable] $Body,

        [Parameter(Mandatory=$false)][string] $ApiVersion = 'v1'
	)

	# Stop if our secrets have not been learned.
	If ($null -eq $env:LGAccessKey) {
		Throw [Data.NoNullAllowedException]::new('No access key has been provided. Please run Set-LiongardKeys.')
	}
	If ($null -eq $env:LGAccessSecret) {
		Throw [Data.NoNullAllowedException]::new('No access secret has been provided. Please run Set-LiongardKeys.')
	}
	If ($null -eq $env:LGInstance) {
		Throw [Data.NoNullAllowedException]::new('No instance has been provided. Please run Set-LiongardKeys.')
	}

	# Enable TLS 1.2 and 1.3 if available
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
	If ([Net.SecurityProtocolType].GetMembers() -Contains 'Tls13') {
		[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
	}

	$Bytes = [System.Text.Encoding]::UTF8.GetBytes("$($env:LGAccessKey):$($env:LGAccessSecret)")
	$EncodedText = [Convert]::ToBase64String($Bytes)
	
	$Uri = "https://$($env:LGInstance).app.liongard.com/api/$ApiVersion/$($RequestToSend)"
	
	try {
		$params = @{
			Uri = $Uri
			Headers = @{"X-ROAR-API-KEY" = $EncodedText}
			Method = $Method
			ErrorAction = 'Stop'
		}
		
		if ($Body) {
			$params.Body = $Body | ConvertTo-Json -Depth 10
			$params.ContentType = 'application/json'
		}

		Write-Verbose "Sending $Method request to $Uri"
		$response = Invoke-WebRequest @params

		if ($response.Content) {
			return $response.Content | ConvertFrom-Json
		}
		return $null
	}
	catch {
		$statusCode = $_.Exception.Response.StatusCode.value__
		$statusDescription = $_.Exception.Response.StatusDescription
		
		Write-Verbose "Request failed with status code $statusCode : $statusDescription"
		Write-Verbose "URI: $Uri"
		
		if ($statusCode -eq 404) {
			Write-Warning "Endpoint not found. This might be a v1/v2 API version mismatch."
		}
		
		throw $_
	}
}

# Environment Management Functions

Function Get-LiongardEnvironmentCount {
    [CmdletBinding()]
    Param()
    
    Return (Send-LiongardRequest -RequestToSend "environments/count" -ApiVersion "v2")
}

Function Get-LiongardEnvironments {
	[CmdletBinding(DefaultParameterSetName='AllEnvironments')]
	Param(
		[Parameter(ParameterSetName='OneEnvironment')]
		[uint32] $EnvironmentID,

        [Parameter(Mandatory=$false)]
        [int] $Page,

        [Parameter(Mandatory=$false)]
        [int] $PageSize,

        [Parameter(Mandatory=$false)]
        [string] $OrderBy,

        [Parameter(Mandatory=$false)]
        [string[]] $Columns
	)

    $ApiVersion = "v2"
    $Request = "environments"

	If ($PSCmdlet.ParameterSetName -eq 'OneEnvironment') {
		$Request += "/$EnvironmentID"
	} else {
        $QueryParams = @()
        if ($Page) { $QueryParams += "page=$Page" }
        if ($PageSize) { $QueryParams += "pageSize=$PageSize" }
        if ($OrderBy) { $QueryParams += "orderBy=$OrderBy" }
        if ($Columns) { $QueryParams += "columns=$($Columns -join ',')" }
        
        if ($QueryParams.Count -gt 0) {
            $Request += "?" + ($QueryParams -join "&")
        }
    }
	
	Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion $ApiVersion)
}

Function Get-LiongardEnvironmentById {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [uint32] $EnvironmentID
    )
    
    Return (Send-LiongardRequest -RequestToSend "environments/$EnvironmentID" -ApiVersion "v2")
}

Function New-LiongardEnvironment {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string] $Name,
        
        [Parameter(Mandatory=$false)]
        [string] $Description,
        
        [Parameter(Mandatory=$false)]
        [int] $Parent,

        [Parameter(Mandatory=$false)]
        [string] $ShortName,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Core', 'Essentials')]
        [string] $Tier
    )

    try {
        Write-Verbose "Creating new environment with name: $Name"
        
        $Body = @{
            "Name" = $Name
        }
        if ($Description) { $Body["Description"] = $Description }
        if ($Parent) { $Body["Parent"] = $Parent }
        if ($ShortName) { $Body["ShortName"] = $ShortName }
        if ($Tier) { $Body["Tier"] = $Tier }

        Write-Verbose "Request body: $($Body | ConvertTo-Json)"
        
        $result = Send-LiongardRequest -RequestToSend "environments" -Method "POST" -Body $Body -ApiVersion "v2"
        
        if (-not $result) {
            throw "No response received from API"
        }

        if (-not $result.Success) {
            throw "API returned unsuccessful response: $($result.Message)"
        }

        if (-not $result.Data -or -not $result.Data.ID) {
            throw "Environment created but no ID returned in response. Full response: $($result | ConvertTo-Json)"
        }
        
        Write-Verbose "Environment created successfully with ID: $($result.Data.ID)"
        return $result.Data
    }
    catch {
        Write-Error "Failed to create environment: $_"
        throw
    }
}

Function New-LiongardEnvironmentBulk {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [array] $Environments
    )
    
    Return (Send-LiongardRequest -RequestToSend "environments/bulk" -Method "POST" -Body $Environments -ApiVersion "v2")
}

Function Update-LiongardEnvironment {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [uint32] $EnvironmentID,

        [Parameter(Mandatory)]
        [hashtable] $UpdateData
    )
    
    Return (Send-LiongardRequest -RequestToSend "environments/$EnvironmentID" -Method "PUT" -Body $UpdateData -ApiVersion "v2")
}

Function Update-LiongardEnvironmentBulk {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [array] $Updates
    )
    
    Return (Send-LiongardRequest -RequestToSend "environments" -Method "PUT" -Body $Updates -ApiVersion "v2")
}

Function Remove-LiongardEnvironment {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
        [uint32] $EnvironmentID,
        
        [Parameter(Mandatory=$false)]
        [bool] $DeleteRelatedEntities = $false
	)

    $Request = "environments/$EnvironmentID"
    if ($DeleteRelatedEntities) {
        $Request += "?relatedEntities=true"
    }
	
	Return (Send-LiongardRequest -RequestToSend $Request -Method "DELETE" -ApiVersion "v2")
}

Function Get-LiongardEnvironmentRelatedEntities {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [uint32] $EnvironmentID
    )
    
    Return (Send-LiongardRequest -RequestToSend "environments/$EnvironmentID/relatedEntities" -ApiVersion "v2")
}

# Metrics Management Functions

Function Get-LiongardMetrics {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [int] $Page,

        [Parameter(Mandatory=$false)]
        [int] $PageSize,

        [Parameter(Mandatory=$false)]
        [array] $Filters,

        [Parameter(Mandatory=$false)]
        [array] $Sorting
    )

    $Request = "metrics"
    $QueryParams = @()
    
    if ($Page) { $QueryParams += "Page=$Page" }
    if ($PageSize) { $QueryParams += "PageSize=$PageSize" }
    if ($Filters) { 
        foreach ($Filter in $Filters) {
            $QueryParams += "Filters[]=$($Filter | ConvertTo-Json)"
        }
    }
    if ($Sorting) {
        foreach ($Sort in $Sorting) {
            $QueryParams += "Sorting[]=$($Sort | ConvertTo-Json)"
        }
    }

    if ($QueryParams.Count -gt 0) {
        $Request += "?" + ($QueryParams -join "&")
    }

    Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion "v2")
}

Function Get-LiongardMetricValue {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
        [int[]] $SystemIDs,
        
		[Parameter(Mandatory)]
        [int[]] $MetricIDs,

        [Parameter(Mandatory=$false)]
        [bool] $IncludeNonVisible = $false
	)

    $Request = "metrics/evaluate"
    if ($IncludeNonVisible) {
        $Request += "?includeNonVisible=true"
    }

    $Body = @{
        "Metrics" = $MetricIDs
        "Systems" = $SystemIDs
        "Filters" = @()
        "Sorting" = @()
        "Pagination" = @{
            "Page" = 1
            "PageSize" = 25
        }
    }

	Return (Send-LiongardRequest -RequestToSend $Request -Method "POST" -Body $Body -ApiVersion "v2")
}

Function Invoke-LiongardMetricEvaluation {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [array] $Metrics,

        [Parameter(Mandatory=$false)]
        [array] $Filters = @(),

        [Parameter(Mandatory=$false)]
        [array] $Sorting = @(),

        [Parameter(Mandatory=$false)]
        [bool] $IncludeNonVisible = $false,

        [Parameter(Mandatory=$false)]
        [int] $Page = 1,

        [Parameter(Mandatory=$false)]
        [int] $PageSize = 25
    )

    $Request = "metrics/evaluate"
    if ($IncludeNonVisible) {
        $Request += "?includeNonVisible=true"
    }

    $Body = @{
        "Metrics" = $Metrics
        "Filters" = $Filters
        "Sorting" = $Sorting
        "Pagination" = @{
            "Page" = $Page
            "PageSize" = $PageSize
        }
    }

    Return (Send-LiongardRequest -RequestToSend $Request -Method "POST" -Body $Body -ApiVersion "v2")
}

Function Invoke-LiongardMetricEvaluationBySystem {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [array] $Systems,

        [Parameter(Mandatory=$false)]
        [array] $Filters = @(),

        [Parameter(Mandatory=$false)]
        [array] $Sorting = @(),

        [Parameter(Mandatory=$false)]
        [int] $Page = 1,

        [Parameter(Mandatory=$false)]
        [int] $PageSize = 25
    )

    $Body = @{
        "Systems" = $Systems
        "Filters" = $Filters
        "Sorting" = $Sorting
        "Pagination" = @{
            "Page" = $Page
            "PageSize" = $PageSize
        }
    }

    Return (Send-LiongardRequest -RequestToSend "metrics/evaluate/systems" -Method "POST" -Body $Body -ApiVersion "v2")
}

Function Get-LiongardMetricRelatedEnvironments {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [int] $MetricID
    )
    
    Return (Send-LiongardRequest -RequestToSend "metrics/$MetricID/relatedEnvironments" -ApiVersion "v2")
}

# Agent Management Functions

Function Get-LiongardAgents {
	[CmdletBinding(DefaultParameterSetName='AllAgents')]
	Param(
		[Parameter(ParameterSetName='OneAgent')]
		[uint32] $AgentID
	)

	$Request = 'agents'
	If ($PSCmdlet.ParameterSetName -eq 'OneAgent') {
		$Request += "/$AgentID"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion "v1")
}

Function Remove-LiongardAgent {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
        [int] $AgentID
	)

	Return (Send-LiongardRequest -RequestToSend "agents/$AgentID" -Method "DELETE" -ApiVersion "v1")
}

Function Clear-LiongardAgent {
	[Alias('Flush-LiongardAgent')]
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory)]
        [int] $AgentID
	)

	Return (Send-LiongardRequest -RequestToSend "agents/$AgentID/flush" -Method "POST" -ApiVersion "v1")
}

Function Install-LiongardAgent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string] $AgentName = $env:computername,
        
        [Parameter(Mandatory)]
        [string] $EnvironmentName,

        [Parameter(Mandatory=$false)]
        [string] $InstallPath = "C:\Liongard",

        [Parameter(Mandatory=$false)]
        [string] $InstallerUrl = "https://agents.static.liongard.com/LiongardAgent-lts.msi",

        [Parameter(Mandatory=$false)]
        [string] $AccessKey,

        [Parameter(Mandatory=$false)]
        [string] $AccessSecret,

        [Parameter(Mandatory=$false)]
        [string] $Instance
    )

    Begin {
        Write-Host "Starting Liongard Agent installation process..." -ForegroundColor Cyan
        # Enable TLS 1.2
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        # Check for existing installations
        Write-Host "Checking for existing Liongard Agent installations..." -ForegroundColor Gray
        $existingAgent = Get-WmiObject -Class Win32_Product -Filter "Name = 'Liongard Agent' OR Name = 'RoarAgent'"
        if ($existingAgent) {
            Write-Host "ERROR: A previous installation of the Liongard Agent was found!" -ForegroundColor Red
            throw "A previous installation of the Liongard Agent was found! Installation stopped."
        }
        Write-Host "No existing Liongard Agent installation found." -ForegroundColor Green

        # If credentials are provided directly, temporarily set them
        $originalAccessKey = $env:LGAccessKey
        $originalAccessSecret = $env:LGAccessSecret
        $originalInstance = $env:LGInstance

        if ($AccessKey) { $env:LGAccessKey = $AccessKey }
        if ($AccessSecret) { $env:LGAccessSecret = $AccessSecret }
        if ($Instance) { $env:LGInstance = $Instance }
    }

    Process {
        try {
            # Create installation directory if it doesn't exist
            Write-Host "Checking installation directory [$InstallPath]..." -ForegroundColor Gray
            if (-not (Test-Path -Path $InstallPath)) {
                Write-Host "Creating Liongard folder at $InstallPath" -ForegroundColor Gray
                New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
                
                if (-not (Test-Path -Path $InstallPath)) {
                    Write-Host "ERROR: Failed to create installation directory!" -ForegroundColor Red
                    throw "Failed to create installation directory: $InstallPath"
                }
            }
            Write-Host "Installation directory confirmed." -ForegroundColor Green

            # Download the installer
            $installerPath = Join-Path $InstallPath "LiongardAgent-lts.msi"
            $logPath = Join-Path $InstallPath "AgentInstall.log"

            Write-Host "Downloading Liongard Agent installer..." -ForegroundColor Gray
            try {
                Invoke-WebRequest -Uri $InstallerUrl -OutFile $installerPath
            }
            catch {
                Write-Host "ERROR: Failed to download installer!" -ForegroundColor Red
                throw "Failed to download installer: $_"
            }

            if (-not (Test-Path $installerPath)) {
                Write-Host "ERROR: Installer download failed - file not found!" -ForegroundColor Red
                throw "Installer download failed - file not found at $installerPath"
            }
            Write-Host "Installer downloaded successfully." -ForegroundColor Green

            # Verify required environment variables
            Write-Host "Verifying Liongard credentials..." -ForegroundColor Gray
            if (-not $env:LGInstance -or -not $env:LGAccessKey -or -not $env:LGAccessSecret) {
                Write-Host "ERROR: Missing required Liongard credentials!" -ForegroundColor Red
                throw "Missing required Liongard credentials. Please either run Set-LiongardKeys first or provide credentials as parameters."
            }
            Write-Host "Credentials verified." -ForegroundColor Green

            # Install the agent
            Write-Host "Installing Liongard Agent..." -ForegroundColor Cyan
            $installArgs = @(
                "/i",
                "`"$installerPath`"",
                "LIONGARDURL=`"$($env:LGInstance).app.liongard.com`"",
                "LIONGARDACCESSKEY=$($env:LGAccessKey)",
                "LIONGARDACCESSSECRET=$($env:LGAccessSecret)",
                "LIONGARDENVIRONMENT=`"$EnvironmentName`"",
                "LIONGARDAGENTNAME=`"$AgentName`"",
                "/qn",
                "/norestart",
                "/L*V",
                "`"$logPath`""
            )

            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -ne 0) {
                Write-Host "ERROR: Installation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
                Write-Host "Please check the log file at: $logPath" -ForegroundColor Yellow
                throw "Installation failed with exit code: $($process.ExitCode). Check the log file at $logPath"
            }
            Write-Host "Installation completed successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "ERROR: Agent installation failed: $_" -ForegroundColor Red
            throw
        }
        finally {
            # Restore original environment variables if they existed
            if ($AccessKey) {
                if ($originalAccessKey) {
                    $env:LGAccessKey = $originalAccessKey
                } else {
                    Remove-Item -Path "Env:LGAccessKey" -ErrorAction SilentlyContinue
                }
            }
            if ($AccessSecret) {
                if ($originalAccessSecret) {
                    $env:LGAccessSecret = $originalAccessSecret
                } else {
                    Remove-Item -Path "Env:LGAccessSecret" -ErrorAction SilentlyContinue
                }
            }
            if ($Instance) {
                if ($originalInstance) {
                    $env:LGInstance = $originalInstance
                } else {
                    Remove-Item -Path "Env:LGInstance" -ErrorAction SilentlyContinue
                }
            }
        }
    }

    End {
        Write-Host "Installation process completed. Log file available at: $logPath" -ForegroundColor Cyan
        Write-Host "Agent Name: $AgentName" -ForegroundColor Gray
        Write-Host "Environment: $EnvironmentName" -ForegroundColor Gray
        Write-Host "Install Path: $InstallPath" -ForegroundColor Gray
    }
}

Function Uninstall-LiongardAgent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch] $KeepLogs,

        [Parameter(Mandatory=$false)]
        [string] $LogPath = "C:\Liongard\AgentUninstall.log"
    )

    Begin {
        Write-Host "Starting Liongard Agent uninstallation process..." -ForegroundColor Cyan
        
        # Check for existing installation
        Write-Host "Checking for Liongard Agent installation..." -ForegroundColor Gray
        $agent = Get-WmiObject -Class Win32_Product -Filter "Name = 'Liongard Agent' OR Name = 'RoarAgent'"
        if (-not $agent) {
            Write-Host "No Liongard Agent installation found." -ForegroundColor Yellow
            return
        }
        Write-Host "Found Liongard Agent installation." -ForegroundColor Green
    }

    Process {
        try {
            # Ensure log directory exists
            $logDir = Split-Path -Parent $LogPath
            if (-not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }

            # Uninstall the agent
            Write-Host "Uninstalling Liongard Agent..." -ForegroundColor Cyan
            $uninstallArgs = @(
                "/x",
                $agent.IdentifyingNumber,
                "/qn",
                "/norestart",
                "/L*V",
                "`"$LogPath`""
            )

            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -PassThru -NoNewWindow

            if ($process.ExitCode -ne 0) {
                Write-Host "ERROR: Uninstallation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
                Write-Host "Please check the log file at: $LogPath" -ForegroundColor Yellow
                throw "Uninstallation failed with exit code: $($process.ExitCode). Check the log file at $LogPath"
            }
            Write-Host "Uninstallation completed successfully." -ForegroundColor Green

            # Clean up installation directory if specified
            if (-not $KeepLogs) {
                Write-Host "Cleaning up Liongard directories..." -ForegroundColor Gray
                $installDirs = @(
                    "C:\Liongard",
                    "${env:ProgramFiles(x86)}\LiongardInc",
                    "${env:ProgramFiles}\LiongardInc"
                )

                foreach ($dir in $installDirs) {
                    if (Test-Path $dir) {
                        Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed directory: $dir" -ForegroundColor Gray
                    }
                }
            }
        }
        catch {
            Write-Host "ERROR: Agent uninstallation failed: $_" -ForegroundColor Red
            throw
        }
    }

    End {
        Write-Host "Uninstallation process completed." -ForegroundColor Cyan
        if (-not $KeepLogs) {
            Write-Host "All Liongard files and directories have been removed." -ForegroundColor Gray
        } else {
            Write-Host "Uninstallation log file available at: $LogPath" -ForegroundColor Gray
            Write-Host "Note: Liongard directories were preserved as -KeepLogs was specified." -ForegroundColor Yellow
        }
    }
}

Function Get-AgentLogs {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        [string] $InstallDir = "C:\",

        [Parameter(Mandatory=$false)]
        [ValidateSet('Error', 'Warning', 'Information')]
        [string] $LogLevel = 'Information',

        [Parameter(Mandatory=$false)]
        [switch] $KeepOriginalLogs,

        [Parameter(Mandatory=$false)]
        [string] $OutputPath
    )

    Begin {
        # Setup logging
        if ($LogLevel -eq 'Information') {
            $VerbosePreference = 'Continue'
        } else {
            $VerbosePreference = 'SilentlyContinue'
        }
        
        if ($LogLevel -eq 'Warning') {
            $WarningPreference = 'Continue'
        } else {
            $WarningPreference = 'SilentlyContinue'
        }
        
        if ($LogLevel -eq 'Error') {
            $ErrorActionPreference = 'Stop'
        } else {
            $ErrorActionPreference = 'Continue'
        }

        # Define paths
        $AgentLogPath = Join-Path $InstallDir "Program Files (x86)\LiongardInc\LiongardAgent\logs"
        if (-not (Test-Path $AgentLogPath)) {
            throw "Agent log directory not found at: $AgentLogPath"
        }

        # If no output path specified, use the agent log path
        if (-not $OutputPath) {
            $OutputPath = $AgentLogPath
        }

        # Create timestamp for the archive
        $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $ArchiveName = "LiongardAgentLogs_$TimeStamp.zip"
        $ArchivePath = Join-Path $OutputPath $ArchiveName

        # Define log files to collect
        $LogFiles = @{
            'EventLog' = @{
                Source = 'LiongardAgentLog'
                Destination = Join-Path $AgentLogPath "events-$TimeStamp.csv"
            }
            'DebugLog' = @{
                Source = Join-Path $AgentLogPath "debug.log"
                Destination = Join-Path $AgentLogPath "debug-$TimeStamp.log"
            }
            'ErrorLog' = @{
                Source = Join-Path $AgentLogPath "error.log"
                Destination = Join-Path $AgentLogPath "error-$TimeStamp.log"
            }
            'HeartbeatLog' = @{
                Source = Join-Path $AgentLogPath "heartbeat.log"
                Destination = Join-Path $AgentLogPath "heartbeat-$TimeStamp.log"
            }
            'JanitorLog' = @{
                Source = Join-Path $AgentLogPath "janitor.log"
                Destination = Join-Path $AgentLogPath "janitor-$TimeStamp.log"
            }
            'JobsLog' = @{
                Source = Join-Path $AgentLogPath "jobs.log"
                Destination = Join-Path $AgentLogPath "jobs-$TimeStamp.log"
            }
            'SQSLog' = @{
                Source = Join-Path $AgentLogPath "sqs.log"
                Destination = Join-Path $AgentLogPath "sqs-$TimeStamp.log"
            }
        }
    }

    Process {
        try {
            Write-Verbose "Starting log collection process..."
            $CollectedFiles = @()

            # Collect Event Logs
            Write-Verbose "Collecting Windows Event Logs..."
            try {
                Get-EventLog -LogName $LogFiles.EventLog.Source | 
                    Select-Object TimeGenerated, EntryType, Source, Message |
                    Export-Csv -Path $LogFiles.EventLog.Destination -NoTypeInformation
                $CollectedFiles += $LogFiles.EventLog.Destination
                Write-Verbose "Successfully collected Event Logs"
            }
            catch {
                Write-Warning "Failed to collect Event Logs: $_"
            }

            # Collect Agent Log Files
            foreach ($LogType in $LogFiles.Keys | Where-Object { $_ -ne 'EventLog' }) {
                $LogInfo = $LogFiles[$LogType]
                
                if (Test-Path $LogInfo.Source) {
                    Write-Verbose "Collecting $LogType..."
                    try {
                        Copy-Item -Path $LogInfo.Source -Destination $LogInfo.Destination -Force
                        $CollectedFiles += $LogInfo.Destination
                        Write-Verbose "Successfully collected $LogType"
                    }
                    catch {
                        Write-Warning "Failed to collect $LogType`: $_"
                    }
                }
                else {
                    Write-Warning "Log file not found: $($LogInfo.Source)"
                }
            }

            # Create archive
            Write-Verbose "Creating log archive: $ArchivePath"
            if ($CollectedFiles.Count -gt 0) {
                $compress = @{
                    Path = $CollectedFiles
                    CompressionLevel = "Fastest"
                    DestinationPath = $ArchivePath
                }
                Compress-Archive @compress -Force
                Write-Verbose "Successfully created log archive"

                # Clean up temporary files unless KeepOriginalLogs is specified
                if (-not $KeepOriginalLogs) {
                    Write-Verbose "Cleaning up temporary files..."
                    foreach ($file in $CollectedFiles) {
                        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            else {
                Write-Warning "No log files were collected"
            }
        }
        catch {
            Write-Error "Failed to collect agent logs: $_"
            return
        }
    }

    End {
        if (Test-Path $ArchivePath) {
            Write-Verbose "Log collection completed successfully"
            Write-Verbose "Logs archived to: $ArchivePath"
            return $ArchivePath
        }
        else {
            Write-Error "Failed to create log archive"
        }
    }
}

# System Management Functions

Function Get-LiongardSystems {
	[CmdletBinding(DefaultParameterSetName='AllSystems')]
	Param(
		[Parameter(ParameterSetName='OneSystem')]
		[uint32] $SystemID
	)

	$Request = 'systems'
	If ($PSCmdlet.ParameterSetName -eq 'OneSystem') {
		$Request += "/$SystemID/view"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion "v1")
}

# Launchpoint Management Functions

Function Get-LiongardLaunchpoints {
	[CmdletBinding(DefaultParameterSetName='AllLaunchpoints')]
	Param(
		[Parameter(ParameterSetName='OneLaunchpoint')]
		[uint32] $LaunchpointID
	)

	$Request = 'launchpoints'
	If ($PSCmdlet.ParameterSetName -eq 'OneLaunchpoint') {
		$Request += "/$LaunchpointID"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion "v1")
}

# Detection Management Functions

Function Get-LiongardDetections {
	[CmdletBinding(DefaultParameterSetName='AllDetections')]
	Param(
		[Parameter(ParameterSetName='OneDetection')]
		[uint32] $DetectionID
	)

	$Request = 'detections'
	If ($PSCmdlet.ParameterSetName -eq 'OneDetection') {
		$Request += "/$DetectionID"
	}
	
	Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion "v1")
}

# Alert Management Functions

Function Get-LiongardAlerts {
	[CmdletBinding()]
	Param()

	Return (Send-LiongardRequest -RequestToSend 'tasks' -ApiVersion "v1")
}

# Add these functions after the existing Environment Management Functions

Function Search-LiongardEnvironments {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [int] $Page = 1,

        [Parameter(Mandatory=$false)]
        [int] $PageSize = 25,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Name', 'ID', 'CreatedOn', 'UpdatedOn')]
        [string] $OrderBy,

        [Parameter(Mandatory=$false)]
        [ValidateSet('ASC', 'DESC')]
        [string] $OrderDirection = 'ASC',

        [Parameter(Mandatory=$false)]
        [string] $NameFilter,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Core', 'Essentials')]
        [string] $TierFilter,

        [Parameter(Mandatory=$false)]
        [bool] $VisibleOnly
    )

    $QueryParams = @()
    if ($Page) { $QueryParams += "page=$Page" }
    if ($PageSize) { $QueryParams += "pageSize=$PageSize" }
    if ($OrderBy) { 
        $QueryParams += "orderBy=$OrderBy"
        $QueryParams += "orderDirection=$OrderDirection"
    }
    if ($NameFilter) { $QueryParams += "name=$NameFilter" }
    if ($TierFilter) { $QueryParams += "tier=$TierFilter" }
    if ($VisibleOnly) { $QueryParams += "visibleOnly=true" }

    $Request = "environments"
    if ($QueryParams.Count -gt 0) {
        $Request += "?" + ($QueryParams -join "&")
    }

    Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion "v2")
}

Function Search-LiongardMetrics {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [int] $Page = 1,

        [Parameter(Mandatory=$false)]
        [int] $PageSize = 25,

        [Parameter(Mandatory=$false)]
        [array] $Filters,

        [Parameter(Mandatory=$false)]
        [array] $Sorting
    )

    $QueryParams = @()
    if ($Page) { $QueryParams += "Page=$Page" }
    if ($PageSize) { $QueryParams += "PageSize=$PageSize" }
    
    if ($Filters) {
        foreach ($Filter in $Filters) {
            $FilterJson = $Filter | ConvertTo-Json -Compress
            $QueryParams += "Filters[]=$FilterJson"
        }
    }

    if ($Sorting) {
        foreach ($Sort in $Sorting) {
            $SortJson = $Sort | ConvertTo-Json -Compress
            $QueryParams += "Sorting[]=$SortJson"
        }
    }

    $Request = "metrics"
    if ($QueryParams.Count -gt 0) {
        $Request += "?" + ($QueryParams -join "&")
    }

    Return (Send-LiongardRequest -RequestToSend $Request -ApiVersion "v2")
}

Function Get-LiongardMetricsByFilter {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [ValidateSet('Name', 'UCK')]
        [string] $FilterBy,

        [Parameter(Mandatory=$false)]
        [ValidateSet('contains', 'does_not_contain', 'matches_exactly', 'starts_with', 'ends_with')]
        [string] $Operation,

        [Parameter(Mandatory=$false)]
        [string] $Value,

        [Parameter(Mandatory=$false)]
        [ValidateSet('ID', 'Name', 'UCK')]
        [string] $SortBy = 'ID',

        [Parameter(Mandatory=$false)]
        [ValidateSet('ASC', 'DESC')]
        [string] $Direction = 'ASC',

        [Parameter(Mandatory=$false)]
        [int] $Page = 1,

        [Parameter(Mandatory=$false)]
        [int] $PageSize = 25
    )

    $Filters = @()
    if ($FilterBy -and $Operation -and $Value) {
        $Filters += @{
            FilterBy = $FilterBy
            Op = $Operation
            Value = $Value
        }
    }

    $Sorting = @(@{
        SortBy = $SortBy
        Direction = $Direction
    })

    Return (Search-LiongardMetrics -Page $Page -PageSize $PageSize -Filters $Filters -Sorting $Sorting)
}