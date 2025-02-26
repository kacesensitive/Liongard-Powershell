# Version 0.0.2
Version 0.0.2 of the Liongard-Powershell module includes the following improvements:

## New Features
- Added support for Liongard API v2 endpoints
- Consolidated agent installation functions into a single `Install-LiongardAgent` function
- Added comprehensive test suite (`Test-LiongardModule.ps1`)
- Added new environment management functions:
  - `Get-LiongardEnvironmentCount`
  - `Get-LiongardEnvironmentById`
  - `New-LiongardEnvironmentBulk`
  - `Update-LiongardEnvironmentBulk`
  - `Get-LiongardEnvironmentRelatedEntities`
- Added new metrics management functions:
  - `Get-LiongardMetrics`
  - `Invoke-LiongardMetricEvaluation`
  - `Invoke-LiongardMetricEvaluationBySystem`
  - `Get-LiongardMetricRelatedEnvironments`
- Enhanced `Get-AgentLogs` function with better logging and error handling

## Improvements
- Improved error handling across all functions
- Added verbose logging support
- Enhanced parameter validation
- Updated documentation and examples
- Added support for both PowerShell Desktop and Core editions

# Version 0.0.1
Version 0.0.1 of the Liongard-Powershell module has not been released to the public.
