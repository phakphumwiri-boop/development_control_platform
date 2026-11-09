$ErrorActionPreference = "Stop"
Import-Module Hyper-V

$name = $env:DCP_VM_NAME
$image = $env:DCP_VM_IMAGE
$disk = $env:DCP_VM_DISK
$switchName = $env:DCP_VM_SWITCH
$memoryBytes = [long]$env:DCP_VM_MEMORY_MB * 1MB
$cpuCount = [int]$env:DCP_VM_CPU

if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
    throw "A VM with this name already exists."
}
if (-not (Test-Path -LiteralPath $image -PathType Leaf)) {
    throw "The registered base image is missing."
}
if (-not (Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)) {
    throw "The configured Hyper-V virtual switch is unavailable."
}
New-VHD -Path $disk -ParentPath $image -Differencing | Out-Null
New-VM -Name $name -Generation 2 -MemoryStartupBytes $memoryBytes -VHDPath $disk -SwitchName $switchName | Out-Null
Set-VMProcessor -VMName $name -Count $cpuCount
Set-VMMemory -VMName $name -DynamicMemoryEnabled $false -StartupBytes $memoryBytes
(Get-VM -Name $name).Id.ToString()
