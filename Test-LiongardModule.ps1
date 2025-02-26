# Test script for Liongard-Powershell module
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AccessKey,
    
    [Parameter(Mandatory)]
    [string]$AccessSecret,
    
    [Parameter(Mandatory)]
    [string]$Instance,

    [Parameter()]
    [string]$TestEnvironmentName = "Test-Environment-$(Get-Random)",

    [Parameter()]
    [switch]$IncludeAgentInstall,

    [Parameter()]
    [ValidateSet('v1', 'v2')]
    [string]$ApiVersion = 'v2'
)

# Function to write test results
function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Success,
        [string]$ErrorMessage = "",
        [string]$WarningMessage = ""
    )
    
    $status = $Success ? "PASSED" : "FAILED"
    $color = $Success ? "Green" : "Red"
    
    Write-Host "[$status] $TestName" -ForegroundColor $color
    if (-not $Success -and $ErrorMessage) {
        Write-Host "  Error: $ErrorMessage" -ForegroundColor Yellow
    }
    if ($WarningMessage) {
        Write-Host "  Warning: $WarningMessage" -ForegroundColor Yellow
    }
}

# Function to run a test
function Invoke-Test {
    param(
        [string]$TestName,
        [scriptblock]$TestScript,
        [switch]$Optional
    )
    
    Write-Host "`nTesting: $TestName" -ForegroundColor Cyan
    try {
        & $TestScript
        Write-TestResult -TestName $TestName -Success $true
    }
    catch {
        if ($Optional) {
            Write-TestResult -TestName $TestName -Success $true -WarningMessage "Optional test failed: $_"
        }
        else {
            Write-TestResult -TestName $TestName -Success $false -ErrorMessage $_.Exception.Message
        }
    }
}

# Import the module
$moduleImported = $false
try {
    # Get the current script's directory
    $scriptPath = $PSScriptRoot
    if (-not $scriptPath) {
        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    
    # Construct the full path to the module
    $modulePath = Join-Path $scriptPath "Liongard-Powershell.psd1"
    
    # Verify the module file exists
    if (-not (Test-Path $modulePath)) {
        throw "Module manifest not found at: $modulePath"
    }
    
    # Remove the module if it's already loaded
    if (Get-Module 'Liongard-Powershell') {
        Remove-Module 'Liongard-Powershell' -Force
    }
    
    # Import the module
    Import-Module $modulePath -Force -Verbose
    $moduleImported = $true
    Write-Host "Module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "Failed to import module: $_" -ForegroundColor Red
    Write-Host "Module path attempted: $modulePath" -ForegroundColor Yellow
    exit 1
}

# Verify module functions are available
if ($moduleImported) {
    $requiredFunctions = @(
        'Set-LiongardKeys',
        'Get-LiongardEnvironments',
        'Get-LiongardEnvironmentCount'
    )
    
    $missingFunctions = $requiredFunctions | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
    if ($missingFunctions) {
        Write-Host "Module imported but missing required functions:" -ForegroundColor Red
        $missingFunctions | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        exit 1
    }
}

# Test Authentication Functions
Invoke-Test "Set-LiongardKeys" {
    Set-LiongardKeys -AccessKey $AccessKey -AccessSecret $AccessSecret -Instance $Instance
}

# Test Environment Management Functions
$environmentId = $null
$newEnvironment = $null

Invoke-Test "Get-LiongardEnvironmentCount" {
    $count = Get-LiongardEnvironmentCount
    if ($null -eq $count) { throw "No environment count returned" }
}

Invoke-Test "Get-LiongardEnvironments" {
    $environments = Get-LiongardEnvironments
    if ($null -eq $environments) { throw "No environments returned" }
}

Invoke-Test "New-LiongardEnvironment" {
    Write-Verbose "Attempting to create test environment: $TestEnvironmentName"
    try {
        $newEnvironment = New-LiongardEnvironment -Name $TestEnvironmentName -Description "Test environment created by automated testing" -Verbose
        if ($null -eq $newEnvironment) {
            throw "API returned null response"
        }
        $environmentId = $newEnvironment.ID
        if ($null -eq $environmentId) {
            throw "Environment created but no ID returned. Response: $($newEnvironment | ConvertTo-Json)"
        }
        Write-Verbose "Environment created successfully with ID: $environmentId"
    }
    catch {
        Write-Verbose "Full error details: $($_ | ConvertTo-Json)"
        throw "Failed to create environment: $($_.Exception.Message)"
    }
}

if ($environmentId) {
    Invoke-Test "Get-LiongardEnvironmentById" {
        $env = Get-LiongardEnvironmentById -EnvironmentID $environmentId
        if ($env.id -ne $environmentId) { throw "Environment ID mismatch" }
    }

    Invoke-Test "Update-LiongardEnvironment" {
        $updateData = @{
            "Description" = "Updated test environment description"
        }
        $result = Update-LiongardEnvironment -EnvironmentID $environmentId -UpdateData $updateData
        if ($null -eq $result) { throw "Failed to update environment" }
    }

    Invoke-Test "Get-LiongardEnvironmentRelatedEntities" {
        $entities = Get-LiongardEnvironmentRelatedEntities -EnvironmentID $environmentId
        if ($null -eq $entities) { throw "Failed to get related entities" }
    }
}

Invoke-Test "Search-LiongardEnvironments" {
    $result = Search-LiongardEnvironments -PageSize 10 -OrderBy "Name" -OrderDirection "ASC"
    if ($null -eq $result) { throw "No environments returned from search" }
    if ($null -eq $result.Data) { throw "No data property in search response" }
}

Invoke-Test "Search-LiongardEnvironments with Filters" {
    $result = Search-LiongardEnvironments -NameFilter "Test" -TierFilter "Core" -VisibleOnly $true
    if ($null -eq $result) { throw "No environments returned from filtered search" }
}

# Test Metrics Management Functions
Invoke-Test "Get-LiongardMetrics" {
    $metrics = Get-LiongardMetrics
    if ($null -eq $metrics) { throw "No metrics returned" }
}

Invoke-Test "Search-LiongardMetrics" {
    $result = Search-LiongardMetrics -PageSize 10
    if ($null -eq $result) { throw "No metrics returned from search" }
    if ($null -eq $result.Data) { throw "No data property in search response" }
}

Invoke-Test "Search-LiongardMetrics with Filters" {
    $filters = @(
        @{
            FilterBy = "Name"
            Op = "contains"
            Value = "Active Directory"
        }
    )
    $sorting = @(
        @{
            SortBy = "Name"
            Direction = "ASC"
        }
    )
    $result = Search-LiongardMetrics -Filters $filters -Sorting $sorting
    if ($null -eq $result) { throw "No metrics returned from filtered search" }
}

Invoke-Test "Get-LiongardMetricsByFilter" {
    $result = Get-LiongardMetricsByFilter -FilterBy "Name" -Operation "contains" -Value "Active Directory"
    if ($null -eq $result) { throw "No metrics returned from filter helper" }
}

# Test System Management Functions (Optional - may not be available in all instances)
Invoke-Test "Get-LiongardSystems" -Optional {
    $systems = Get-LiongardSystems
    if ($null -eq $systems) { throw "No systems returned" }
}

# Test Launchpoint Management Functions (Optional - may not be available in all instances)
Invoke-Test "Get-LiongardLaunchpoints" -Optional {
    $launchpoints = Get-LiongardLaunchpoints
    if ($null -eq $launchpoints) { throw "No launchpoints returned" }
}

# Test Detection Management Functions (Optional - may not be available in all instances)
Invoke-Test "Get-LiongardDetections" -Optional {
    $detections = Get-LiongardDetections
    if ($null -eq $detections) { throw "No detections returned" }
}

# Test Alert Management Functions (Optional - may not be available in all instances)
Invoke-Test "Get-LiongardAlerts" -Optional {
    $alerts = Get-LiongardAlerts
    if ($null -eq $alerts) { throw "No alerts returned" }
}

# Test Agent Management Functions (Optional - may not be available in all instances)
Invoke-Test "Get-LiongardAgents" -Optional {
    $agents = Get-LiongardAgents
    if ($null -eq $agents) { throw "No agents returned" }
}

# Only run agent installation test if specifically requested
if ($IncludeAgentInstall) {
    Invoke-Test "Install-LiongardAgent" {
        Install-LiongardAgent -EnvironmentName $TestEnvironmentName -Verbose
    }

    Invoke-Test "Get-AgentLogs" {
        $logPath = Get-AgentLogs -Verbose
        if (-not $logPath -or -not (Test-Path $logPath)) { throw "Failed to collect agent logs" }
    }
}

# Clean up test environment if it was created
if ($environmentId) {
    Invoke-Test "Remove-LiongardEnvironment" {
        Remove-LiongardEnvironment -EnvironmentID $environmentId
    }
}

# Test Reset-LiongardKeys (do this last)
Invoke-Test "Reset-LiongardKeys" {
    Reset-LiongardKeys
    if ($env:LGAccessKey -or $env:LGAccessSecret -or $env:LGInstance) {
        throw "Environment variables not properly cleared"
    }
}

Write-Host "`nTest suite completed!" -ForegroundColor Cyan 