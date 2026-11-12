"""Build protected Azure VM extension payloads for ephemeral GitHub runners.

The GitHub registration token is embedded only in Azure protectedSettings.
No live Azure request is made by this module; AzureVMProvider owns deployment.
"""
from __future__ import annotations

import base64
import re
import shlex
from typing import Callable


class RunnerBootstrapError(RuntimeError):
    pass


class AzureRunnerBootstrapFactory:
    """Create OS-specific protected bootstrap extensions with pinned artifacts."""

    def __init__(
        self,
        github_app,
        runner_version: str,
        linux_sha256: str,
        windows_sha256: str,
        os_profile_factory: Callable,
    ):
        if not isinstance(runner_version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", runner_version):
            raise ValueError("Runner version must be an explicit x.y.z release")
        for checksum in (linux_sha256, windows_sha256):
            if not isinstance(checksum, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", checksum):
                raise ValueError("Runner archive SHA-256 must be pinned")
        if not callable(os_profile_factory):
            raise ValueError("An OS profile factory is required")
        self.github_app = github_app
        self.runner_version = runner_version
        self.checksums = {"linux": linux_sha256.lower(), "windows": windows_sha256.lower()}
        self.os_profile_factory = os_profile_factory

    @staticmethod
    def _validate_payload(vm_name: str, os_name: str, payload: dict) -> tuple[str, list[str]]:
        if not isinstance(vm_name, str) or not re.fullmatch(r"dcp-[0-9]+-[a-f0-9]{8}", vm_name):
            raise RunnerBootstrapError("Invalid DCP runner name")
        if os_name not in ("linux", "windows"):
            raise RunnerBootstrapError("Azure bootstrap supports only approved Linux or Windows")
        if not isinstance(payload, dict) or payload.get("target_os") != os_name:
            raise RunnerBootstrapError("Runner target OS does not match the Azure profile")
        if payload.get("ephemeral") is not True or payload.get("network_policy") != "restricted-egress":
            raise RunnerBootstrapError("Runner must be ephemeral with restricted egress")
        repository = payload.get("repository")
        if not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
        ):
            raise RunnerBootstrapError("Invalid runner repository")
        labels = payload.get("labels")
        if not isinstance(labels, list) or not labels or any(
            not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label)
            for label in labels
        ):
            raise RunnerBootstrapError("Invalid runner labels")
        return repository, labels

    def _linux_script(self, vm_name: str, repository: str, labels: list[str], token: str) -> str:
        version = self.runner_version
        archive = f"actions-runner-linux-x64-{version}.tar.gz"
        url = f"https://github.com/actions/runner/releases/download/v{version}/{archive}"
        label_arg = ",".join(labels)
        return "\n".join([
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "umask 077",
            "id dcp-runner >/dev/null 2>&1 || useradd --system --create-home --shell /bin/bash dcp-runner",
            "install -d -o dcp-runner -g dcp-runner -m 0750 /opt/dcp-actions-runner",
            "cd /opt/dcp-actions-runner",
            f"curl --fail --location --silent --show-error {shlex.quote(url)} --output {shlex.quote(archive)}",
            f"echo {shlex.quote(self.checksums['linux'] + '  ' + archive)} | sha256sum --check --status",
            f"tar -xzf {shlex.quote(archive)}",
            "chown -R dcp-runner:dcp-runner /opt/dcp-actions-runner",
            "runuser -u dcp-runner -- ./config.sh "
            f"--unattended --url {shlex.quote('https://github.com/' + repository)} "
            f"--token {shlex.quote(token)} --name {shlex.quote(vm_name)} "
            f"--labels {shlex.quote(label_arg)} --ephemeral --disableupdate",
            "./svc.sh install dcp-runner",
            "./svc.sh start",
            f"rm -f -- {shlex.quote(archive)}",
            "",
        ])

    def _windows_script(self, vm_name: str, repository: str, labels: list[str], token: str) -> str:
        version = self.runner_version
        archive = f"actions-runner-win-x64-{version}.zip"
        url = f"https://github.com/actions/runner/releases/download/v{version}/{archive}"
        def ps(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"
        return "\r\n".join([
            "$ErrorActionPreference = 'Stop'",
            "$ProgressPreference = 'SilentlyContinue'",
            "$root = 'C:\\actions-runner'",
            "New-Item -ItemType Directory -Force -Path $root | Out-Null",
            f"$archive = Join-Path $root {ps(archive)}",
            f"Invoke-WebRequest -Uri {ps(url)} -OutFile $archive",
            f"if ((Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant() -ne {ps(self.checksums['windows'])}) {{ throw 'Runner archive checksum mismatch' }}",
            "Expand-Archive -LiteralPath $archive -DestinationPath $root -Force",
            "Set-Location $root",
            f".\\config.cmd --unattended --url {ps('https://github.com/' + repository)} "
            f"--token {ps(token)} --name {ps(vm_name)} --labels {ps(','.join(labels))} "
            "--ephemeral --disableupdate",
            "$taskScript = Join-Path $root 'start-runner.ps1'",
            "@'\nSet-Location -LiteralPath $PSScriptRoot\n& .\\run.cmd\nexit $LASTEXITCODE\n'@ | Set-Content -LiteralPath $taskScript -Encoding UTF8",
            "& icacls.exe $root /inheritance:r /grant 'SYSTEM:(OI)(CI)F' 'BUILTIN\\Administrators:(OI)(CI)F' 'NT AUTHORITY\\NETWORK SERVICE:(OI)(CI)M' | Out-Null",
            "if ($LASTEXITCODE -ne 0) { throw 'Could not restrict runner directory ACL' }",
            "$taskCommand = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"' + $taskScript + '\"'",
            "& schtasks.exe /Create /SC ONSTART /TN 'DCP-Ephemeral-Runner' /TR $taskCommand /RU 'NT AUTHORITY\\NETWORK SERVICE' /RL LIMITED /F",
            "if ($LASTEXITCODE -ne 0) { throw 'Could not create least-privilege runner task' }",
            "& schtasks.exe /Run /TN 'DCP-Ephemeral-Runner'",
            "if ($LASTEXITCODE -ne 0) { throw 'Could not start least-privilege runner task' }",
            "Remove-Item -LiteralPath $archive -Force",
            "",
        ])

    @staticmethod
    def _validate_os_profile(vm_name: str, os_name: str, profile: dict) -> None:
        """Reject incomplete or unsafe Azure guest-login profiles before minting a token."""
        if not isinstance(profile, dict):
            raise RunnerBootstrapError("Azure guest login profile is invalid")

        computer_name = profile.get("computerName")
        admin_username = profile.get("adminUsername")
        if not isinstance(computer_name, str) or not computer_name:
            raise RunnerBootstrapError("Azure guest computer name is required")
        max_name_length = 15 if os_name == "windows" else 64
        if len(computer_name) > max_name_length or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", computer_name
        ):
            raise RunnerBootstrapError("Azure guest computer name is invalid for the target OS")
        if not isinstance(admin_username, str) or not re.fullmatch(
            r"[a-z_][a-z0-9_-]{0,31}", admin_username
        ) or admin_username.lower() in {"root", "admin", "administrator", "guest"}:
            raise RunnerBootstrapError("Azure guest administrator username is invalid")

        if os_name == "linux":
            if "adminPassword" in profile:
                raise RunnerBootstrapError("Linux guest login must not use an administrator password")
            linux = profile.get("linuxConfiguration")
            if not isinstance(linux, dict) or linux.get("disablePasswordAuthentication") is not True:
                raise RunnerBootstrapError("Linux password authentication must be disabled")
            ssh = linux.get("ssh")
            public_keys = ssh.get("publicKeys") if isinstance(ssh, dict) else None
            if not isinstance(public_keys, list) or not public_keys:
                raise RunnerBootstrapError("Linux guest login requires an SSH public key")
            for entry in public_keys:
                if not isinstance(entry, dict) or entry.get("path") != (
                    "/home/" + admin_username + "/.ssh/authorized_keys"
                ):
                    raise RunnerBootstrapError("Linux SSH key path must target the configured administrator")
                key_data = entry.get("keyData")
                parts = key_data.split() if isinstance(key_data, str) else []
                if len(parts) < 2 or parts[0] not in (
                    "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                    "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                ):
                    raise RunnerBootstrapError("Linux SSH public key format is invalid")
                try:
                    decoded = base64.b64decode(parts[1], validate=True)
                except (ValueError, base64.binascii.Error) as exc:
                    raise RunnerBootstrapError("Linux SSH public key encoding is invalid") from exc
                if not decoded:
                    raise RunnerBootstrapError("Linux SSH public key is empty")
        elif os_name == "windows":
            if "linuxConfiguration" in profile:
                raise RunnerBootstrapError("Windows guest profile must not contain Linux login settings")
            password = profile.get("adminPassword")
            if not isinstance(password, str) or not 12 <= len(password) <= 123:
                raise RunnerBootstrapError("Windows guest administrator password length is invalid")
            if admin_username.lower() in password.lower():
                raise RunnerBootstrapError("Windows guest password must not contain the administrator username")
            classes = sum(bool(re.search(pattern, password)) for pattern in (
                r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"
            ))
            if classes < 3:
                raise RunnerBootstrapError("Windows guest administrator password does not meet complexity requirements")
        else:
            raise RunnerBootstrapError("Unsupported Azure guest operating system")

    def __call__(self, vm_name: str, os_name: str, payload: dict) -> dict:
        repository, labels = self._validate_payload(vm_name, os_name, payload)
        os_profile = self.os_profile_factory(vm_name, os_name, payload)
        self._validate_os_profile(vm_name, os_name, os_profile)
        credential = self.github_app.create_registration_token(repository)
        token = getattr(credential, "token", None)
        if not isinstance(token, str) or not token or any(ch.isspace() for ch in token):
            raise RunnerBootstrapError("GitHub runner registration credential is invalid")
        if os_name == "linux":
            script = self._linux_script(vm_name, repository, labels, token)
            extension = {
                "name": "dcp-runner-bootstrap",
                "properties": {
                    "publisher": "Microsoft.Azure.Extensions",
                    "type": "CustomScript",
                    "typeHandlerVersion": "2.1",
                    "settings": {},
                    "protectedSettings": {
                        "script": base64.b64encode(script.encode("utf-8")).decode("ascii")
                    },
                },
            }
        else:
            script = self._windows_script(vm_name, repository, labels, token)
            encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
            extension = {
                "name": "dcp-runner-bootstrap",
                "properties": {
                    "publisher": "Microsoft.Compute",
                    "type": "CustomScriptExtension",
                    "typeHandlerVersion": "1.10",
                    "settings": {},
                    "protectedSettings": {
                        "commandToExecute": "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
                    },
                },
            }
        return {"os_profile": os_profile, "extension": extension}
