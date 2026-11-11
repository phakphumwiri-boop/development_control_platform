[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9_.:-]{1,100}$')]
    [string]$WorkerId = 'windows-local-01',
    [string[]]$TrustedRepository = @()
)

$ErrorActionPreference = 'Stop'
if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA is not available for this Windows account.'
}

function Write-ProtectedJsonFile {
    param([string]$Path, [object]$Value)
    $temp = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = ConvertTo-Json -InputObject $Value -Compress -Depth 5
        [IO.File]::WriteAllText($temp, $json, [Text.UTF8Encoding]::new($false))
        & icacls.exe $temp /inheritance:r /grant:r "$($script:identity):(R,W)" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not protect the temporary local DCP settings ACL.'
        }
        Move-Item -LiteralPath $temp -Destination $Path -Force
        & icacls.exe $Path /inheritance:r /grant:r "$($script:identity):(R,W)" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not verify the local DCP settings ACL.'
        }
    } finally {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Force
        }
    }
}

$dataDir = Join-Path $env:LOCALAPPDATA 'DCP'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$credentialFile = Join-Path $dataDir 'runner-tokens.json'
$settingsFile = Join-Path $dataDir 'gateway-local-settings.json'
$workerPattern = '^[a-z0-9_.:-]{1,100}$'
$repositoryPattern = '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$'
$tokenMap = @{}
$allowedRepositoryMap = @{}
$settingsFileExists = $false

$existingItem = Get-Item -LiteralPath $credentialFile -Force -ErrorAction SilentlyContinue
if ($null -ne $existingItem) {
    if ((($existingItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $existingItem.PSIsContainer) {
        throw 'Existing Runner credential path is not a regular file.'
    }
    if ($existingItem.Length -gt 65536) {
        throw 'Existing Runner credential file exceeds 64 KiB.'
    }
    try {
        $existing = Get-Content -LiteralPath $credentialFile -Raw | ConvertFrom-Json
    } catch {
        throw 'Existing Runner credential file is invalid JSON; it was not changed.'
    }
    if ($null -eq $existing -or $existing -isnot [pscustomobject]) {
        throw 'Existing Runner credential file must be a JSON object.'
    }
    $seenTokens = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($property in $existing.PSObject.Properties) {
        if ($property.Name -notmatch $workerPattern -or
            $property.Value -isnot [string] -or
            $property.Value.Length -lt 32 -or
            $property.Value.Length -gt 256) {
            throw 'Existing Runner credential file contains an invalid entry; it was not changed.'
        }
        if ($tokenMap.ContainsKey($property.Name) -or -not $seenTokens.Add($property.Value)) {
            throw 'Existing Runner credential file contains duplicate worker credentials.'
        }
        $tokenMap[$property.Name] = $property.Value
    }
}

$existingSettingsItem = Get-Item -LiteralPath $settingsFile -Force -ErrorAction SilentlyContinue
if ($null -ne $existingSettingsItem) {
    if ((($existingSettingsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $existingSettingsItem.PSIsContainer) {
        throw 'Existing local Gateway settings path is not a regular file.'
    }
    if ($existingSettingsItem.Length -gt 16384) {
        throw 'Existing local Gateway settings file exceeds 16 KiB.'
    }
    try {
        $existingSettings = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
    } catch {
        throw 'Existing local Gateway settings file is invalid JSON; it was not changed.'
    }
    if ($null -eq $existingSettings -or $existingSettings -isnot [pscustomobject] -or
        @($existingSettings.PSObject.Properties).Count -ne 1 -or
        $null -eq $existingSettings.PSObject.Properties['allowed_repositories']) {
        throw 'Existing local Gateway settings file has an invalid schema.'
    }
    $settingsFileExists = $true
    foreach ($repository in @($existingSettings.allowed_repositories)) {
        if ($repository -isnot [string] -or $repository -notmatch $repositoryPattern) {
            throw 'Existing local Gateway allowlist contains an invalid repository.'
        }
        if ($allowedRepositoryMap.ContainsKey($repository)) {
            throw 'Existing local Gateway allowlist contains duplicate repository names.'
        }
        $allowedRepositoryMap[$repository] = $repository
    }
}

foreach ($repository in $TrustedRepository) {
    if ($repository -notmatch $repositoryPattern) {
        throw "Invalid trusted repository name: $repository"
    }
    $matchingKey = @($allowedRepositoryMap.Keys | Where-Object { $_ -ieq $repository })
    if ($matchingKey.Count -gt 0 -and $matchingKey[0] -cne $repository) {
        throw 'Trusted repository name casing must match the existing Gateway allowlist exactly.'
    }
    $allowedRepositoryMap[$repository] = $repository
}
if ($allowedRepositoryMap.Count -gt 20) {
    throw 'The local Gateway repository allowlist is limited to 20 repositories.'
}

if (-not $tokenMap.ContainsKey($WorkerId)) {
    if ($tokenMap.Count -ge 16) {
        throw 'The local Runner credential file already contains 16 workers.'
    }
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $tokenMap[$WorkerId] = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$script:identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$orderedTokens = [ordered]@{}
foreach ($key in ($tokenMap.Keys | Sort-Object)) { $orderedTokens[$key] = $tokenMap[$key] }
Write-ProtectedJsonFile -Path $credentialFile -Value $orderedTokens

if ($settingsFileExists -or $allowedRepositoryMap.Count -gt 0) {
    $orderedRepositories = @($allowedRepositoryMap.Keys | Sort-Object)
    $settings = [ordered]@{ allowed_repositories = $orderedRepositories }
    Write-ProtectedJsonFile -Path $settingsFile -Value $settings
}

Write-Host "Local Runner credential prepared for worker '$WorkerId'."
Write-Host "Credential file: $credentialFile"
Write-Host 'The token is stored with a restricted Windows ACL and was not displayed.'
if ($allowedRepositoryMap.Count -gt 0) {
    Write-Host ("Approved public repositories: " + (($allowedRepositoryMap.Keys | Sort-Object) -join ', '))
}
Write-Host 'Restart the DCP local stack so the Gateway loads the Runner credentials and repository allowlist.'
