@{
	RootModule = 'Liongard-Powershell.psm1'
	ModuleVersion = '0.0.1'
	CompatiblePSEditions = @('Desktop', 'Core')
	PowerShellVersion = '5.1'
	GUID = 'aaf4b5ab-2431-3f4f-3fgg-45ksfrafrcb8'
	Author = 'Kacey Haley'
	Copyright = '(c) 2021-2022 Kacey Haley. All rights reserved. Licensed under the AGPL version 3.'
	Description = 'An unofficial PowerShell module to interact with the Liongard public API.'
	FunctionsToExport = @(
		'Get-LiongardMetricValue',
		'Get-LiongardMetrics',
		'Get-LiongardAlerts',
		'Get-LiongardDetections',
		'Get-LiongardSystems',
		'Get-LiongardLaunchpoints',
		'Get-LiongardAgents',
        'Get-LiongardEnvironments',
        'Send-LiongardRequest',
        'Reset-LiongardKeys',
        'Set-LiongardKeys'
	)
	CmdletsToExport = @()
	VariablesToExport = ''
	AliasesToExport = @(
		'Remove-LiongardKeys'
	)
	FileList = @(
		'Liongard-Powershell.png',
		'Liongard-Powershell.psd1',
		'Liongard-Powershell.psm1',
		'README.md'
	)
	PrivateData = @{
		PSData = @{
			Tags = @('Lionagrd', 'Roar', 'Powershell', 'API', 'computers', 'devices', 'alerts', 'customers', 'REST', 'Windows', 'cloud', 'network', 'macOS')
			LicenseUri = 'https://github.com/kacesensitive/Liongard-Powershell/blob/main/LICENSE'
			ProjectUri = 'https://github.com/kacesensitive/Liongard-Powershell'
			IconUri = 'https://github.com/kacesensitive/Liongard-Powershell/blob/main/Liongard-Powershell.png'
			ReleaseNotes = 'https://github.com/kacesensitive/Liongard-Powershell/blob/main/NEWS.MD'
			Prerelease = 'This module is a prerelease version.'
			RequireLicenseAcceptance = $false
		}
	}
}