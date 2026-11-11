[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9_.:-]{1,100}$')]
    [string]$WorkerId = 'windows-local-01',
    [switch]$EnableExecution,
    [switch]$Once,
    [string[]]$TrustedRepository = @()
)

$ErrorActionPreference = 'Stop'
$project = [System.IO.Path]::GetFullPath($PSScriptRoot)
$credentialFile = Join-Path $env:LOCALAPPDATA 'DCP\runner-tokens.json'
$python = Get-Command py.exe -ErrorAction SilentlyContinue
if (-not $python) { throw 'Python Launcher (py.exe) was not found. Run Setup-DCP-Local.cmd first.' }
if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) {
    throw 'Local Runner credentials are missing. Run Setup-DCP-Local-Runner.ps1 first.'
}
$item = Get-Item -LiteralPath $credentialFile -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 65536) {
    throw 'Local Runner credential file is unsafe or exceeds 64 KiB.'
}
try { $credentialMap = Get-Content -LiteralPath $credentialFile -Raw | ConvertFrom-Json }
catch { throw 'Local Runner credential file is invalid JSON.' }
if ($null -eq $credentialMap -or $credentialMap -isnot [pscustomobject]) {
    throw 'Local Runner credential file must be a JSON object.'
}
$property = $credentialMap.PSObject.Properties[$WorkerId]
if ($null -eq $property -or $property.Value -isnot [string] -or $property.Value.Length -lt 32) {
    throw "Worker '$WorkerId' is not configured. Run Setup-DCP-Local-Runner.ps1."
}
if ($Once -and -not $EnableExecution) {
    throw '-Once requires -EnableExecution.'
}
if ($EnableExecution) {
    if ($TrustedRepository.Count -lt 1) {
        throw 'Execution requires at least one explicit -TrustedRepository owner/repository.'
    }
    $gatewaySettingsFile = Join-Path $env:LOCALAPPDATA 'DCP\gateway-local-settings.json'
    if (-not (Test-Path -LiteralPath $gatewaySettingsFile -PathType Leaf)) {
        throw 'Gateway repository allowlist is missing. Run Setup-DCP-Local-Runner.ps1 -TrustedRepository owner/repository, then restart DCP.'
    }
    try { $gatewaySettings = Get-Content -LiteralPath $gatewaySettingsFile -Raw | ConvertFrom-Json }
    catch { throw 'Gateway repository allowlist file is invalid.' }
    $gatewayAllowed = @($gatewaySettings.allowed_repositories)
    foreach ($repository in $TrustedRepository) {
        if ($repository -notmatch '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$') {
            throw "Invalid trusted repository name: $repository"
        }
    }
    if (@($TrustedRepository | Select-Object -Unique).Count -ne $TrustedRepository.Count) {
        throw 'Trusted repositories must be unique.'
    }
    foreach ($repository in $TrustedRepository) {
        if ($gatewayAllowed -cnotcontains $repository) {
            throw "Repository '$repository' is not in the Gateway allowlist. Run Setup-DCP-Local-Runner.ps1 -TrustedRepository '$repository' and restart DCP."
        }
    }
} elseif ($TrustedRepository.Count -gt 0) {
    throw '-TrustedRepository is only accepted together with -EnableExecution.'
}

try {
    $health = Invoke-RestMethod -Uri 'http://127.0.0.1:18790/healthz' -TimeoutSec 3
} catch {
    throw 'DCP Gateway is not reachable. Start the DCP local stack and retry.'
}
if ($health.status -ne 'ok' -or $health.provisioning_enabled -ne $false) {
    throw 'DCP Gateway health/safe-default check failed.'
}

$names = @('DCP_GATEWAY_URL','DCP_RUNNER_ID','DCP_RUNNER_TOKEN',
           'DCP_RUNNER_EXECUTION_ENABLED','DCP_RUNNER_TRUSTED_REPOSITORIES')
$previous = @{}
foreach ($name in $names) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

try {
    $env:DCP_GATEWAY_URL = 'http://127.0.0.1:18790'
    $env:DCP_RUNNER_ID = $WorkerId
    $env:DCP_RUNNER_TOKEN = $property.Value
    if ($EnableExecution) {
        $env:DCP_RUNNER_EXECUTION_ENABLED = 'true'
        $env:DCP_RUNNER_TRUSTED_REPOSITORIES = ConvertTo-Json -InputObject ([string[]]$TrustedRepository) -Compress
        Write-Host "Starting Runner '$WorkerId' with execution enabled for the explicitly trusted repository list."
    } else {
        Remove-Item Env:DCP_RUNNER_EXECUTION_ENABLED -ErrorAction SilentlyContinue
        Remove-Item Env:DCP_RUNNER_TRUSTED_REPOSITORIES -ErrorAction SilentlyContinue
        Write-Host "Enrolling Runner '$WorkerId' offline. No jobs will be claimed or executed."
    }

    $runnerArgs = @()
    if (-not $EnableExecution) { $runnerArgs = @('--enroll-only') }
    elseif ($Once) { $runnerArgs = @('--once') }

    Push-Location $project
    try {
        & $python.Source -3 -m tools.runner_agent.agent @runnerArgs
        if ($LASTEXITCODE -ne 0) { throw "DCP Runner exited with code $LASTEXITCODE." }
    } finally {
        Pop-Location
    }
} finally {
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
}
