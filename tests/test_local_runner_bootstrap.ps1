$ErrorActionPreference = 'Stop'
$project = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$setup = Join-Path $project 'Setup-DCP-Local-Runner.ps1'
$testRoot = Join-Path $env:RUNNER_TEMP 'dcp-local-runner-credential-test'
$previousLocalAppData = $env:LOCALAPPDATA

if (Test-Path -LiteralPath $testRoot) {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$env:LOCALAPPDATA = $testRoot

try {
    & $setup -WorkerId 'ci-runner-01'
    if (-not $?) { throw 'Local Runner credential setup failed on first run.' }
    $credentialFile = Join-Path $testRoot 'DCP\runner-tokens.json'
    if (-not (Test-Path -LiteralPath $credentialFile -PathType Leaf)) {
        throw 'Local Runner credential file was not created.'
    }
    $firstMap = Get-Content -LiteralPath $credentialFile -Raw | ConvertFrom-Json
    $firstToken = $firstMap.'ci-runner-01'
    if ($firstToken -isnot [string] -or $firstToken.Length -lt 32) {
        throw 'Generated Runner token is missing or too short.'
    }

    & $setup -WorkerId 'ci-runner-01'
    if (-not $?) { throw 'Local Runner credential setup failed on idempotent run.' }
    $secondMap = Get-Content -LiteralPath $credentialFile -Raw | ConvertFrom-Json
    if ($secondMap.'ci-runner-01' -cne $firstToken) {
        throw 'Setup rotated an existing Runner token unexpectedly.'
    }

    & $setup -WorkerId 'ci-runner-02'
    if (-not $?) { throw 'Local Runner second-worker setup failed.' }
    $thirdMap = Get-Content -LiteralPath $credentialFile -Raw | ConvertFrom-Json
    if (@($thirdMap.PSObject.Properties).Count -ne 2) {
        throw 'Expected exactly two configured Runner workers.'
    }
    if ($thirdMap.'ci-runner-02' -ceq $firstToken) {
        throw 'Runner workers must receive unique tokens.'
    }

    $acl = (& icacls.exe $credentialFile) -join [Environment]::NewLine
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect Runner credential ACL.' }
    if ($acl -match 'Everyone|Authenticated Users|BUILTIN\\Users') {
        throw 'Runner credential ACL grants access to a broad user group.'
    }

    Write-Host 'Local Runner credential bootstrap tests passed.'
} finally {
    $env:LOCALAPPDATA = $previousLocalAppData
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
