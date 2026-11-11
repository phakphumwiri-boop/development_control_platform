[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9_.:-]{1,100}$')]
    [string]$WorkerId = 'windows-local-01'
)

$ErrorActionPreference = 'Stop'
if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA is not available for this Windows account.'
}

$dataDir = Join-Path $env:LOCALAPPDATA 'DCP'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$credentialFile = Join-Path $dataDir 'runner-tokens.json'
$tokenMap = @{}
$workerPattern = '^[a-z0-9_.:-]{1,100}$'

if (Test-Path -LiteralPath $credentialFile) {
    $existingItem = Get-Item -LiteralPath $credentialFile -Force
    $isReparsePoint = (($existingItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($isReparsePoint -or $existingItem.PSIsContainer) {
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
        if ($tokenMap.ContainsKey($property.Name)) {
            throw 'Duplicate Runner ID in credential file.'
        }
        if (-not $seenTokens.Add($property.Value)) {
            throw 'Runner credentials must be unique per worker.'
        }
        $tokenMap[$property.Name] = $property.Value
    }
}

if (-not $tokenMap.ContainsKey($WorkerId)) {
    if ($tokenMap.Count -ge 16) {
        throw 'The local Runner credential file already contains 16 workers.'
    }
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $tokenMap[$WorkerId] = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$tempFile = $credentialFile + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
try {
    $ordered = [ordered]@{}
    foreach ($key in ($tokenMap.Keys | Sort-Object)) {
        $ordered[$key] = $tokenMap[$key]
    }
    $json = ConvertTo-Json -InputObject $ordered -Compress -Depth 4
    [IO.File]::WriteAllText($tempFile, $json, [Text.UTF8Encoding]::new($false))

    & icacls.exe $tempFile /inheritance:r /grant:r "$($identity):(R,W)" 'SYSTEM:(F)' 'BUILTIN\Administrators:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not protect the temporary Runner credential file ACL.'
    }

    Move-Item -LiteralPath $tempFile -Destination $credentialFile -Force
    & icacls.exe $credentialFile /inheritance:r /grant:r "$($identity):(R,W)" 'SYSTEM:(F)' 'BUILTIN\Administrators:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not verify the Runner credential file ACL.'
    }
} finally {
    if (Test-Path -LiteralPath $tempFile) {
        Remove-Item -LiteralPath $tempFile -Force
    }
}

Write-Host "Local Runner credential prepared for worker '$WorkerId'."
Write-Host "Credential file: $credentialFile"
Write-Host 'The token is stored with a restricted Windows ACL and was not displayed.'
Write-Host 'Restart the DCP local stack so the Gateway loads the new Runner credential map.'
