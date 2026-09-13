<#
.SYNOPSIS
    Installs or upgrades organiser-agent (the Windows PC agent for
    server-mcp-claude) from a GitHub Release: downloads the build,
    verifies its SHA-256 checksum, installs it, registers/refreshes the
    Scheduled Task that runs it, and verifies it actually responds
    afterward.

.DESCRIPTION
    Does, in one step, what BUILD_AND_SETUP.md's manual §1/§1a/§3 do by
    hand. See BUILD_AND_SETUP.md for what each step means and how to do
    it manually if you'd rather not run a script from the internet, or
    if this script fails and you need to see why.

    Idempotent / upgrade-safe: if organiser-agent is already installed,
    re-running this without -Secret/-Port reuses the previously-recorded
    values instead of asking you to retype them (stored in
    C:\ProgramData\OrganiserAgent\config.json -- plaintext, same trust
    level as the existing Scheduled-Task-argument approach this project
    already uses; this is personal single-user infrastructure, not a
    hardened secrets store).

    NOTE for future maintainers: coordination/tasks/pc-agent.md (see
    BROADCAST entry 0006) calls for moving this PC-side config into
    organiser-agent.exe itself (a built-in local dashboard/config UI)
    instead of external env vars + a config.json this script manages.
    Once that lands, large parts of this script (the config.json
    preserve-on-upgrade logic, the Scheduled Task env var wiring) should
    be revisited -- the agent may end up owning its own config storage
    and this script would just need to hand it the values once.

.PARAMETER Version
    Release tag to install, e.g. "v1.2.0". Defaults to "latest".

.PARAMETER Secret
    This PC's ORGANISER_SECRET -- must match the `secret` you put in
    this PC's entry in the Render-side PCS registry. Required on first
    install; optional on upgrade (reuses the stored value if omitted).

.PARAMETER Port
    This PC's ORGANISER_PORT -- must match the `port` in this PC's PCS
    entry and its pc-tunnel@<name>.conf on the Linux server. Defaults to
    7842 on first install; reuses the stored value on upgrade if omitted.

.PARAMETER Owner
    GitHub repo owner. Defaults to the value baked in below -- override
    if you've forked this repo.

.PARAMETER Repo
    GitHub repo name. Defaults to the value baked in below.

.PARAMETER GitHubToken
    A GitHub PAT with at least read access to Releases. REQUIRED if this
    repo is private (release assets on a private repo aren't fetchable
    via a plain unauthenticated URL). Not needed for a public repo,
    though an unauthenticated request is still subject to GitHub's
    anonymous API rate limit.

.PARAMETER InstallDir
    Where to install the exe. Defaults to
    "C:\Program Files\OrganiserAgent".

.PARAMETER TaskName
    Scheduled Task name. Defaults to "OrganiserAgent".

.PARAMETER Uninstall
    Stop and remove the Scheduled Task and the installed exe (leaves
    config.json in place unless -RemoveConfig is also passed, so a
    reinstall later can still reuse the secret/port).

.PARAMETER RemoveConfig
    Combined with -Uninstall, also deletes the stored config.json.

.EXAMPLE
    # First install, elevated PowerShell:
    .\install-organiser-agent.ps1 -Secret "correct-horse-battery-staple" -Port 7842

.EXAMPLE
    # Upgrade to a specific tag, reusing the existing secret/port:
    .\install-organiser-agent.ps1 -Version v1.3.0

.EXAMPLE
    # Private repo:
    .\install-organiser-agent.ps1 -Secret "..." -GitHubToken $env:GH_TOKEN

.EXAMPLE
    .\install-organiser-agent.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [string]$Version = "latest",
    [string]$Secret,
    [int]$Port,
    [string]$Owner = "mienkek13-netizen",
    [string]$Repo = "server-mcp-claude",
    [string]$GitHubToken,
    [string]$InstallDir = "C:\Program Files\OrganiserAgent",
    [string]$TaskName = "OrganiserAgent",
    [switch]$Uninstall,
    [switch]$RemoveConfig
)

$ErrorActionPreference = "Stop"
$ExeName = "organiser-agent.exe"
$ExePath = Join-Path $InstallDir $ExeName
$ConfigDir = Join-Path $env:ProgramData "OrganiserAgent"
$ConfigPath = Join-Path $ConfigDir "config.json"

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator (installing to Program Files and registering a Scheduled Task both require it). Re-launch PowerShell elevated and try again."
    }
}

function Get-StoredConfig {
    if (Test-Path $ConfigPath) {
        try { return Get-Content $ConfigPath -Raw | ConvertFrom-Json }
        catch { Write-Warning "Existing config.json at '$ConfigPath' is unreadable/corrupt -- ignoring it."; return $null }
    }
    return $null
}

function Save-Config([string]$secretValue, [int]$portValue) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    @{ secret = $secretValue; port = $portValue } | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8
    # Best-effort lock down to Administrators + SYSTEM only -- this holds
    # a shared secret, even though it's the same trust model as the
    # existing scheduled-task-argument approach elsewhere in this project.
    try {
        icacls $ConfigPath /inheritance:r /grant:r "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
    } catch {
        Write-Warning "Could not restrict permissions on '$ConfigPath': $_"
    }
}

function Invoke-GitHubApi([string]$Uri) {
    $headers = @{ "Accept" = "application/vnd.github+json"; "X-GitHub-Api-Version" = "2022-11-28" }
    if ($GitHubToken) { $headers["Authorization"] = "Bearer $GitHubToken" }
    return Invoke-RestMethod -Uri $Uri -Headers $headers
}

function Get-ReleaseAssetBytes([string]$AssetApiUrl, [string]$OutFile) {
    $headers = @{ "Accept" = "application/octet-stream" }
    if ($GitHubToken) { $headers["Authorization"] = "Bearer $GitHubToken" }
    Invoke-WebRequest -Uri $AssetApiUrl -Headers $headers -OutFile $OutFile
}

function Stop-AgentIfRunning {
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        }
    } catch {}
    # Belt-and-suspenders in case it was started outside the task (e.g.
    # manually for testing) and would otherwise hold the exe file locked.
    Get-Process -Name "organiser-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

function Register-AgentTask([string]$secretValue, [int]$portValue) {
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit 0 `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal `
        -UserId "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType Interactive `
        -RunLevel Limited
    $action = New-ScheduledTaskAction `
        -Execute "cmd.exe" `
        -Argument "/c `"set ORGANISER_SECRET=$secretValue && set ORGANISER_PORT=$portValue && `"$ExePath`"`""

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Force | Out-Null
}

function Test-AgentResponds([int]$portValue, [int]$RetrySeconds = 15) {
    $deadline = (Get-Date).AddSeconds($RetrySeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$portValue/status" -TimeoutSec 3
            return $resp
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    return $null
}

# --- Uninstall path ---------------------------------------------------------

if ($Uninstall) {
    Assert-Admin
    Write-Host "Stopping and removing Scheduled Task '$TaskName'..."
    Stop-AgentIfRunning
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    if (Test-Path $ExePath) {
        Write-Host "Removing '$ExePath'..."
        Remove-Item $ExePath -Force
    }
    if ($RemoveConfig -and (Test-Path $ConfigPath)) {
        Write-Host "Removing stored config '$ConfigPath'..."
        Remove-Item $ConfigPath -Force
    }
    Write-Host "Uninstalled. (Config preserved at '$ConfigPath' unless -RemoveConfig was passed.)"
    return
}

# --- Install / upgrade path --------------------------------------------------

Assert-Admin

$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") {
    Write-Warning "Detected architecture '$arch' -- only an x64 (AMD64) build of organiser-agent.exe is currently published. It may not run here."
}

$existing = Get-StoredConfig
if (-not $Secret) {
    if ($existing -and $existing.secret) {
        $Secret = $existing.secret
        Write-Host "Reusing previously-configured secret from '$ConfigPath'."
    } else {
        throw "-Secret is required on first install (no existing config found at '$ConfigPath'). This must match the 'secret' you set for this PC's entry in the Render-side PCS registry."
    }
}
if (-not $Port) {
    if ($existing -and $existing.port) {
        $Port = [int]$existing.port
        Write-Host "Reusing previously-configured port ($Port) from '$ConfigPath'."
    } else {
        $Port = 7842
        Write-Host "No -Port given and no existing config -- defaulting to 7842. Make sure this matches the 'port' in this PC's PCS entry and pc-tunnel@<name>.conf on the server."
    }
}

Write-Host "Resolving release '$Version' for $Owner/$Repo..."
$releaseUri = if ($Version -eq "latest") {
    "https://api.github.com/repos/$Owner/$Repo/releases/latest"
} else {
    "https://api.github.com/repos/$Owner/$Repo/releases/tags/$Version"
}
$release = Invoke-GitHubApi -Uri $releaseUri
Write-Host "Found release: $($release.tag_name)"

$exeAsset = $release.assets | Where-Object { $_.name -eq "organiser-agent.exe" } | Select-Object -First 1
$shaAsset  = $release.assets | Where-Object { $_.name -eq "organiser-agent.exe.sha256" } | Select-Object -First 1
if (-not $exeAsset) {
    throw "Release '$($release.tag_name)' has no 'organiser-agent.exe' asset. If this repo is private, did you pass -GitHubToken?"
}

$tempDir = Join-Path $env:TEMP "organiser-agent-install"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
$downloadedExe = Join-Path $tempDir "organiser-agent.exe"

Write-Host "Downloading organiser-agent.exe ($([math]::Round($exeAsset.size / 1KB)) KB)..."
Get-ReleaseAssetBytes -AssetApiUrl $exeAsset.url -OutFile $downloadedExe

if ($shaAsset) {
    Write-Host "Verifying checksum..."
    $downloadedSha = Join-Path $tempDir "organiser-agent.exe.sha256"
    Get-ReleaseAssetBytes -AssetApiUrl $shaAsset.url -OutFile $downloadedSha
    # sha256sum format: "<hex>  organiser-agent.exe" (or "<hex> *organiser-agent.exe")
    $expectedHash = ((Get-Content $downloadedSha -Raw) -split '\s+')[0].Trim().ToLower()
    $actualHash = (Get-FileHash -Path $downloadedExe -Algorithm SHA256).Hash.ToLower()
    if ($expectedHash -ne $actualHash) {
        throw "Checksum mismatch! Expected $expectedHash, got $actualHash. Refusing to install a build that doesn't match its published checksum -- this could mean a corrupted download or something worse. Nothing was installed."
    }
    Write-Host "Checksum verified: $actualHash"
} else {
    Write-Warning "Release has no .sha256 asset to verify against -- installing without integrity verification. (Older releases built before this installer existed may not have one.)"
}

Write-Host "Stopping any running instance before overwriting the binary..."
Stop-AgentIfRunning

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path $downloadedExe -Destination $ExePath -Force
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Save-Config -secretValue $Secret -portValue $Port

Write-Host "Registering Scheduled Task '$TaskName' (runs at logon, restarts on failure)..."
Register-AgentTask -secretValue $Secret -portValue $Port

Write-Host "Starting the agent now to verify it..."
Start-ScheduledTask -TaskName $TaskName

$status = Test-AgentResponds -portValue $Port -RetrySeconds 15
if ($status) {
    Write-Host ""
    Write-Host "Installed and verified:" -ForegroundColor Green
    Write-Host "  Version  : $($status.version)"
    Write-Host "  Platform : $($status.platform)"
    Write-Host "  Port     : $Port"
    Write-Host ""
    Write-Host "Next: make sure this PC's entry exists in the Render-side PCS" -ForegroundColor Yellow
    Write-Host "registry with a MATCHING port and secret, and that a" -ForegroundColor Yellow
    Write-Host "pc-tunnel@<name>.service instance for this PC is running on the" -ForegroundColor Yellow
    Write-Host "Linux server. See BUILD_AND_SETUP.md sections 4-5." -ForegroundColor Yellow
} else {
    Write-Warning "Installed, but the agent did not respond on http://127.0.0.1:$Port/status within 15 seconds."
    Write-Warning "Checklist:"
    Write-Warning "  1. Get-ScheduledTask -TaskName '$TaskName' | Select State"
    Write-Warning "  2. Check Task Scheduler's history for '$TaskName' for a launch error"
    Write-Warning "  3. Try running '$ExePath' directly in a terminal to see any error output"
    Write-Warning "  4. Confirm nothing else is already bound to port $Port"
    exit 1
}
