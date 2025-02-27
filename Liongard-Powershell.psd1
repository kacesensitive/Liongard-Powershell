@{
	RootModule = 'Liongard-Powershell.psm1'
	ModuleVersion = '0.0.2'
	CompatiblePSEditions = @('Desktop', 'Core')
	PowerShellVersion = '5.1'
	GUID = '7114b5ab-2431-4f4f-9f33-45c5faf1ccb7'
	Author = 'Kacey Haley'
	Copyright = '(c) 2021-2025 Liongard. All rights reserved. Licensed under the AGPL version 3.'
	Description = 'A PowerShell module to interact with the Liongard API (v1 and v2).'
	FunctionsToExport = @(
		# Environment Management
		'Get-LiongardEnvironments',
		'Get-LiongardEnvironmentCount',
		'Get-LiongardEnvironmentById',
		'New-LiongardEnvironment',
		'New-LiongardEnvironmentBulk',
		'Remove-LiongardEnvironment',
		'Update-LiongardEnvironment',
		'Update-LiongardEnvironmentBulk',
		'Get-LiongardEnvironmentRelatedEntities',
		'Search-LiongardEnvironments',

		# Metrics Management
		'Get-LiongardMetrics',
		'Get-LiongardMetricValue',
		'Invoke-LiongardMetricEvaluation',
		'Invoke-LiongardMetricEvaluationBySystem',
		'Get-LiongardMetricRelatedEnvironments',
		'Search-LiongardMetrics',
		'Get-LiongardMetricsByFilter',

		# Agent Management
		'Get-LiongardAgents',
		'Remove-LiongardAgent',
		'Clear-LiongardAgent',
		'Install-LiongardAgent',
		'Uninstall-LiongardAgent',
		'Get-AgentLogs',

		# System Management
		'Get-LiongardSystems',

		# Launchpoint Management
		'Get-LiongardLaunchpoints',

		# Detection Management
		'Get-LiongardDetections',

		# Alert Management
		'Get-LiongardAlerts',

		# Authentication & Core
		'Set-LiongardKeys',
		'Reset-LiongardKeys',
		'Send-LiongardRequest'
	)
	CmdletsToExport = @()
	VariablesToExport = ''
	AliasesToExport = @(
		'Remove-LiongardKeys',
		'Flush-LiongardAgent'
	)
	FileList = @(
		'Liongard-Powershell.png',
		'Liongard-Powershell.psd1',
		'Liongard-Powershell.psm1',
		'README.md'
	)
	PrivateData = @{
		PSData = @{
			Tags = @('Liongard', 'Roar', 'PowerShell', 'API', 'computers', 'devices', 'alerts', 'customers', 'REST', 'Windows', 'cloud', 'network', 'macOS', 'v1', 'v2')
			LicenseUri = 'https://github.com/kacesensitive/Liongard-Powershell/blob/main/LICENSE'
			ProjectUri = 'https://github.com/kacesensitive/Liongard-Powershell'
			IconUri = 'https://github.com/kacesensitive/Liongard-Powershell/blob/main/Liongard-Powershell.png'
			ReleaseNotes = 'https://github.com/kacesensitive/Liongard-Powershell/blob/main/NEWS.MD'
			Prerelease = 'beta'
			RequireLicenseAcceptance = $false
		}
	}
}