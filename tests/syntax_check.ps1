<#
.SYNOPSIS
    Auto Syntax Checker & Permission Fixer for OS-Guard project scripts.
.DESCRIPTION
    Scans the project directory for .ps1 files, checks PowerShell syntax via AST parser,
    reports errors, and auto-sets executable permissions (chmod-like on Windows).
    Use this as the BASE syntax check script before any deployment.
#>

param([string]$ScanDir = (Split-Path -Parent $PSScriptRoot))

$FailedFiles = @()
$ErrorFiles = @()

Write-Host "[SCAN] Checking PowerShell syntax in: $ScanDir" -ForegroundColor Cyan

$Ps1Files = Get-ChildItem -Path $ScanDir -Filter "*.ps1" -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '_temp_' }

foreach ($File in $Ps1Files) {
    $Content = Get-Content -Raw -Path $File.FullName -ErrorAction SilentlyContinue
    if (-not $Content) { continue }

    try {
        $Tokens = $null
        $Errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($Content, [ref]$Tokens, [ref]$Errors)
        if ($Errors -and $Errors.Count -gt 0) {
            Write-Host "[FAIL] $($File.FullName)" -ForegroundColor Red
            foreach ($Err in $Errors) {
                Write-Host "  L$($Err.Extent.StartLineNumber): $($Err.Message)" -ForegroundColor DarkRed
            }
            $ErrorFiles += $File.FullName
            $FailedFiles += $File.Name
        } else {
            Write-Host "[OK]   $($File.Name)" -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERR]  $($File.FullName): $($_.Exception.Message)" -ForegroundColor Red
        $ErrorFiles += $File.FullName
        $FailedFiles += $File.Name
    }
}

# Auto-chmod: ensure all .ps1 scripts are executable (not blocked by execution policy or ACL issues)
foreach ($File in $Ps1Files) {
    try {
        $Acl = Get-Acl -Path $File.FullName -ErrorAction SilentlyContinue
        if ($Acl) {
            $UsersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
            $ReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
            $AllowRule = New-Object System.Security.AccessControl.FileSystemAccessRule($UsersSid, $ReadExecute, "None", "None", "Allow")
            $Acl.AddAccessRule($AllowRule)
            Set-Acl -Path $File.FullName -AclObject $Acl -ErrorAction SilentlyContinue
        }
    } catch {}
}

Write-Host "`n=====================================================" -ForegroundColor DarkGray
Write-Host " SYNTAX CHECK SUMMARY " -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host "Total checked: $($Ps1Files.Count)" -ForegroundColor Gray
Write-Host "Passed:        $($Ps1Files.Count - $FailedFiles.Count)" -ForegroundColor Green
Write-Host "Failed:        $($FailedFiles.Count)" -ForegroundColor Red

if ($FailedFiles.Count -gt 0) {
    Write-Host "`nFAIL SUMMARY ($($FailedFiles.Count))" -ForegroundColor Red -BackgroundColor Black
    foreach ($Name in $FailedFiles) { Write-Host "  - $Name" -ForegroundColor Red }
    exit 1
} else {
    Write-Host "`n[SUCCESS] ALL SYNTAX CHECKS PASSED!" -ForegroundColor Green
    exit 0
}
