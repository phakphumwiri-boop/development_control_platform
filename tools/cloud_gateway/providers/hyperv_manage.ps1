$ErrorActionPreference = "Stop"
Import-Module Hyper-V

$name = $env:DCP_VM_NAME
$action = $env:DCP_VM_ACTION
$disk = $env:DCP_VM_DISK

switch ($action) {
    "start" {
        Start-VM -Name $name | Out-Null
    }
    "stop" {
        $vm = Get-VM -Name $name -ErrorAction Stop
        if ($vm.State -eq "Running") {
            Stop-VM -Name $name -TurnOff -Force
        }
    }
    "delete" {
        $vm = Get-VM -Name $name -ErrorAction SilentlyContinue
        if ($vm) {
            if ($vm.State -eq "Running") {
                Stop-VM -Name $name -TurnOff -Force
            }
            Remove-VM -Name $name -Force
        }
        if (Test-Path -LiteralPath $disk -PathType Leaf) {
            Remove-Item -LiteralPath $disk -Force
        }
    }
    default {
        throw "Unsupported VM lifecycle action."
    }
}
"ok"
