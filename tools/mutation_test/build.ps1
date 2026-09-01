# Build script for adam_mutation_test.exe
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$distDir = Join-Path $scriptDir "dist"
if (-not (Test-Path $distDir)) {
    New-Item -Path $distDir -ItemType Directory -Force | Out-Null
}

$outputExe = Join-Path $distDir "adam_mutation_test.exe"
$sourceFile = Join-Path $scriptDir "Program.cs"
$cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if (-not (Test-Path $cscPath)) {
    $cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
}

if (-not (Test-Path $cscPath)) {
    Write-Error "Could not find csc.exe compiler."
    exit 1
}

Write-Host "Compiling $sourceFile to $outputExe using $cscPath ..."
& $cscPath /target:exe /out:$outputExe /nologo /optimize+ $sourceFile

if (Test-Path $outputExe) {
    $fileSize = (Get-Item $outputExe).Length
    Write-Host "Build successful: $outputExe ($fileSize bytes)"
} else {
    Write-Error "Build failed: Output binary not found."
    exit 1
}
