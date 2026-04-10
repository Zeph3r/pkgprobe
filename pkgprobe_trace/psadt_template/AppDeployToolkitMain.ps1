<#
.SYNOPSIS
    PSADT main bootstrap for pkgprobe auto-wrap packages.
.DESCRIPTION
    Sources the toolkit function library (AppDeployToolkit.ps1) and
    extensions (AppDeployToolkitExtensions.ps1) before Deploy-Application.ps1
    calls any toolkit functions.

    This is invoked by dot-sourcing from Deploy-Application.ps1:
      . "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
.NOTES
    Minimal implementation for pkgprobe Intune packaging.
    Based on PowerShell App Deployment Toolkit (Apache License 2.0).
#>

[CmdletBinding()]
param()

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path $scriptDirectory 'AppDeployToolkit.ps1')

$extPath = Join-Path $scriptDirectory 'AppDeployToolkitExtensions.ps1'
if (Test-Path $extPath) { . $extPath }
