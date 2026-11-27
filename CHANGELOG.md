# Changelog

## 1.2.1

- `Get-HardeningStatus` now shows the Windows edition, version and build (for example "Windows 11 Pro, version 25H2, build 26200.7171"), checks whether that Windows 11 version still gets security updates, and warns when installed updates are waiting for a restart.

## 1.2.0

Brings over what the Windows XP edition (NetSecToolkitXP 0.3 to 0.5) added, rebuilt for Windows 10 and 11.

- **Findings.** The audit commands now report findings (`OK`, `Info`, `Warn`, `Risk`) with an area, a message and the fix. `-PassThru` returns them as objects.
- New `Get-HardeningStatus`: read-only check of the hardening baseline (firewall, Remote Desktop and NLA, Remote Assistance, risky services, SMBv1, NetBIOS, Guest, anonymous access, LM hashes, NTLMv2, password and lockout policy, UAC, DEP, Windows update age, listening ports).
- New `Set-HardeningBaseline`: applies that baseline in 14 steps, each reporting Applied, N/A, Skipped or Failed. Supports `-WhatIf`, `-Confirm` and `-Skip`.
- New `Get-AccountAudit`: local accounts, administrators, blank-password accounts, automatic logon and plain-text `DefaultPassword`, screen lock.
- New `Get-FirewallLog`: the firewall-log summary as its own command, now with port-scan detection and a split between internet and private sources. Reads `pfirewall.log.old` after a rollover.
- New `Get-USBHistory`: the USB storage history as its own command, with serial numbers.
- New `Get-ThreatExposure`: rates the PC as Protected, Partly or Exposed against seven threats, with the reason and the fix.
- New `Find-MalwareIndicator`: startup entries, Winlogon/AppInit/IFEO hijacks, services, running programs and scheduled tasks in suspicious places, hosts file, autorun.inf, recent programs in Temp, antivirus state and Defender exclusions. Exports SHA-256 hashes, signer and VirusTotal links.
- New `Invoke-NetSecAssistant` (alias `nsai`): explains findings, answers questions from built-in notes and gives a fix order. Optional Claude mode calls the Claude API with a key read from `ANTHROPIC_API_KEY`; the key is never stored or shown, and MAC addresses, the PC name and the user name are masked first.
- New `Start-NetSecToolkit` menu and `NetSecToolkit.cmd` launcher. Hardening from the menu always previews first and applies only after typing YES.
- `Invoke-DailySecurityCheck` now runs all of the above, prints a summary with a fix order, and also saves `Report_*.html` and `Hashes_*.csv`. New `-NoRouter` and `-NoReport` switches. It reuses the other commands instead of repeating their code, and one failing section no longer stops the rest. Devices seen on earlier runs stay in the baseline, so an idle phone is not reported as new. Existing snapshots still compare.
- `Test-RouterExposure`: adds the TR-069 port (7547), a UPnP (SSDP) discovery check, findings, and `-NoUpnp` / `-NoPublicIp`.
- `Get-NetAdapterHealth` ends with a summary of findings; `Get-FirewallAudit -PassThru` also returns findings.
- Tests for the new parsing, rating, assistant and report logic. The module test now confirms the two `Set-` commands are the only ones that can change settings.

Changed behavior to know about: `Invoke-DailySecurityCheck -PassThru` still returns warning text, now one line per Risk or Warn finding in the form `Area: message`.

## 1.1.0

- New `Set-FirewallBaseline` command: applies the fixes `Get-FirewallAudit` recommends
  (logging of blocked connections for every profile, larger log size, Remote Assistance rules disabled).
  Changes only non-compliant settings and supports `-WhatIf` and `-Confirm`.
- `Get-FirewallAudit` now points to `Set-FirewallBaseline` when it finds those issues.
- Tests confirm `Set-FirewallBaseline` is the only command that can change settings.

## 1.0.0

Turned the six standalone scripts into the `NetSecToolkit` module.

- Six exported commands: `Invoke-DailySecurityCheck`, `Get-FirewallAudit`, `Get-NetAdapterHealth`,
  `Find-NetworkDevice`, `Test-RouterExposure`, `Test-NetworkSpeed`
- Comment-based help and examples for every command
- `-PassThru` on every command to return results as objects
- Shared helpers and parsers moved to `Private/`, removing duplicated code
- Pester unit tests for the parsing logic (Wi-Fi 7 MLO netsh output, firewall log lines,
  subnet math, risky-port matching, speed test math) and the module itself
- GitHub Actions CI: PSScriptAnalyzer lint and Pester tests on every push
- The daily check now always stops its transcript, even if a section fails
