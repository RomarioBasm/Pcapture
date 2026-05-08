#Requires -Version 5.1
<#
.SYNOPSIS
  Configure, build, and test Pcapture on Windows.

.PARAMETER Config
  Build configuration: Release (default) or Debug.

.PARAMETER Clean
  Wipe the build/ directory before configuring. Use after changing the
  generator, toolchain, or top-level CMake options.

.PARAMETER NoTest
  Build only; skip ctest.

.EXAMPLE
  .\scripts\build.ps1
  .\scripts\build.ps1 -Clean
  .\scripts\build.ps1 -Config Debug -NoTest
#>
[CmdletBinding()]
param(
  [ValidateSet("Release", "Debug")]
  [string]$Config = "Release",
  [switch]$Clean,
  [switch]$NoTest
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Write-Stage([string]$msg) {
  Write-Host ""
  Write-Host "==> $msg" -ForegroundColor Cyan
}

# Locate cmake (handles shells where PATH wasn't refreshed after install).
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
  $fallback = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
  if (Test-Path "$fallback\cmake.exe") {
    $env:Path = "$env:Path;$fallback"
  } else {
    throw "cmake not found on PATH and not at $fallback. Install Build Tools or fix PATH."
  }
}

if (-not (Test-Path "CMakeUserPresets.json")) {
  throw "CMakeUserPresets.json missing. Create it (see CLAUDE.md / earlier setup)."
}

if ($Clean -and (Test-Path "build")) {
  Write-Stage "Cleaning build/"
  Remove-Item -Recurse -Force build
}

Write-Stage "Configure (preset: win)"
cmake --preset win

Write-Stage "Build ($Config)"
$buildPreset = if ($Config -eq "Debug") { "win-debug" } else { "win-release" }
cmake --build --preset $buildPreset

if (-not $NoTest) {
  Write-Stage "Test ($Config)"
  ctest --preset win-release --build-config $Config
}

Write-Stage "Done."
Write-Host "Binary: $repoRoot\build\$Config\pcapture.exe"
