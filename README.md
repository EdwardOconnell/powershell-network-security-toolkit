<p align="center">
  <img src="assets/eds-logo.png" alt="Edward O'Connell, Cyber Security Professional" width="560">
</p>

# NetSecToolkit

![CI](https://github.com/EdwardOconnell/powershell-network-security-toolkit/actions/workflows/ci.yml/badge.svg)

A PowerShell 7 module for auditing and hardening a Windows PC and the network it's connected to: firewall configuration, a hardening baseline, local accounts, the firewall log, devices on the local network, router exposure, USB history, threat exposure, signs of malware, and connection speed. Every audit command is **read-only**. Two commands change settings, `Set-HardeningBaseline` and `Set-FirewallBaseline`, and both support `-WhatIf` to preview first. A built-in assistant explains the findings and says what to fix first.

Built and tested on real home and small-office networks (ASUS routers, mixed Wi-Fi 5/6/7 clients, Windows 11).

## Commands

| Command | What it does | Admin? |
|---|---|---|
| `Invoke-DailySecurityCheck` | All-in-one check: runs every audit below, flags **new devices and USB drives** since the last run, prints a summary and a fix order, and saves an HTML report, a transcript, program hashes and a snapshot. | Yes |
| `Get-HardeningStatus` | Checks the hardening baseline: firewall, Remote Desktop and Remote Assistance, risky services, SMBv1, NetBIOS, Guest, anonymous access, LM/NTLM settings, password and lockout policy, UAC, DEP, Windows update age, and listening ports. | Best elevated |
| `Set-HardeningBaseline` | Applies that baseline in one run. Each step reports Applied, N/A, Skipped or Failed. `-Skip` leaves steps alone (for example `-Skip RemoteDesktop`). Supports `-WhatIf` and `-Confirm`. | Yes |
| `Get-AccountAudit` | Local accounts and administrators, accounts allowed a blank password, an enabled built-in Administrator, automatic logon and plain-text `DefaultPassword`, screen lock. | No |
| `Get-FirewallAudit` | Audits Windows Defender Firewall: profiles, default actions, logging, inbound rules exposing risky ports (RDP, SMB, WinRM, etc.), and allowed programs in user-writable folders. | Yes |
| `Set-FirewallBaseline` | Applies the fixes `Get-FirewallAudit` recommends: turns on logging of blocked connections for every profile and disables the Remote Assistance rules. Changes only what isn't already compliant. Supports `-WhatIf` and `-Confirm`. | Yes |
| `Get-FirewallLog` | Summarizes what the firewall blocked: sources that tried to reach this PC, likely port scans, and blocked traffic from the internet or from outside your subnet. | Yes |
| `Get-NetAdapterHealth` | Checks every adapter: link state, IP, APIPA detection, gateway reachability, driver health, packet errors, internet and DNS. | Yes |
| `Find-NetworkDevice` | Lists devices on the local subnet using a parallel ping sweep plus the ARP table, with hostnames and randomized-MAC detection. `-Passive` sends no traffic. | No |
| `Test-RouterExposure` | Checks which services the router exposes on the LAN and whether it answers UPnP, shows your public IP for an outside test, and can dump the router's iptables rules over SSH. | No |
| `Get-USBHistory` | Lists every USB storage device ever connected, with serial numbers, and whether USB storage is blocked. | No |
| `Get-ThreatExposure` | Rates this PC as Protected, Partly or Exposed against SMB worms, Remote Desktop attacks, USB worms, password guessing, password theft, ransomware and malware, and unpatched Windows flaws, with the reason and the fix. | Best elevated |
| `Find-MalwareIndicator` | Looks where malware starts and hides: startup entries, Winlogon and IFEO hijacks, services, running programs and scheduled tasks in Temp/AppData/Recycle Bin, the hosts file, autorun.inf, antivirus state and Defender exclusions. Exports SHA-256 hashes with VirusTotal links. Not an antivirus. | Best elevated |
| `Invoke-NetSecAssistant` (alias `nsai`) | Explains findings, answers questions and gives a fix order. Offline by default; optional Claude mode. | No |
| `Start-NetSecToolkit` | Menu for everything above. `NetSecToolkit.cmd` opens it. | No |
| `Test-NetworkSpeed` | Speed test (latency, jitter, download, upload) that also shows the network you're on: SSID, band, channel, Wi-Fi standard, signal, security (WPA2/WPA3), router, and ISP. Supports Wi-Fi 7 multi-link (MLO). Keeps a history for comparing networks. | No |

Every command has built-in help, for example `Get-Help Test-NetworkSpeed -Full`. Add `-PassThru` to any command to get its results as objects for further scripting.

## Install

Requires Windows 10 or 11 and [PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows) or later.

```powershell
git clone https://github.com/EdwardOconnell/powershell-network-security-toolkit.git
cd powershell-network-security-toolkit
Get-ChildItem -Recurse -Filter *.ps* | Unblock-File     # only needed for downloaded ZIPs
Import-Module ./NetSecToolkit
```

To load it automatically in every session, copy the `NetSecToolkit` folder to `$HOME\Documents\PowerShell\Modules\`.

## Usage

```powershell
Invoke-DailySecurityCheck                      # run in an elevated window
Invoke-DailySecurityCheck -ActiveScan -LogHours 72
Get-HardeningStatus
Set-HardeningBaseline -WhatIf                  # preview every hardening step
Set-HardeningBaseline -Skip RemoteDesktop      # apply all but the steps you name
Get-FirewallAudit -ExportPath C:\fw-rules.csv
Set-FirewallBaseline -WhatIf                   # preview the firewall fixes
Get-FirewallLog -Hours 72
Get-ThreatExposure
Find-MalwareIndicator -ExportPath C:\hashes.csv
Find-NetworkDevice -Passive
Test-RouterExposure -Router 192.168.1.1
Test-NetworkSpeed -Seconds 15

# Results as objects
$warnings = Invoke-DailySecurityCheck -PassThru
Get-HardeningStatus -PassThru | Where-Object Level -in 'Risk', 'Warn'
Find-NetworkDevice -PassThru | Where-Object { -not $_.Hostname }
```

Or skip the typing: double-click `NetSecToolkit.cmd` (right-click > **Run as administrator** for the full check and for hardening) and pick from the menu.

### Findings

The audit commands report **findings**: a level (`OK`, `Info`, `Warn`, `Risk`), an area, a message and, where there is one, the fix. `-PassThru` returns them as objects, the daily check collects them into `Report_*.html`, and the assistant reads the ones from the checks you ran.

### Hardening baseline

`Set-HardeningBaseline` steps, all of which `-Skip` accepts:

| Step | What it does |
|---|---|
| `Firewall` | Firewall on for every profile, inbound connections blocked by default |
| `Logging` | Log blocked connections on every profile |
| `RemoteAssistance` | Turn off Remote Assistance and its firewall rules |
| `RemoteDesktop` | Turn off Remote Desktop and its firewall rules |
| `RemoteRegistry` | Stop and disable Remote Registry |
| `LegacyServices` | Stop and disable the Telnet server and Simple TCP/IP Services, if installed |
| `SMBv1` | Turn off the SMBv1 server protocol (SMBv2/3 sharing keeps working) |
| `NetBIOS` | Turn off NetBIOS over TCP/IP on every interface |
| `Guest` | Disable the built-in Guest account |
| `RestrictAnonymous` | Block anonymous listing of accounts and shares |
| `NoLMHash` | Stop storing LM password hashes |
| `NTLMv2` | Send NTLMv2 responses only |
| `PasswordPolicy` | Minimum length 8, lockout after 10 bad tries (never weakens a stricter policy) |
| `AutoRun` | Turn off AutoRun and AutoPlay for all drive types |

Run it with `-WhatIf` first. Skip `RemoteDesktop` if you remote into this PC, and `NetBIOS` if you reach an old NAS or printer by name. File sharing itself is left alone.

### Assistant

```powershell
Invoke-NetSecAssistant -Scan        # run the baseline checks, then ask questions
nsai plan                           # what to fix first, in order
nsai "what is netbios"
Get-HardeningStatus -PassThru | nsai list
```

Offline mode is the default: answers come from notes built into the module, and nothing leaves the PC. Claude mode (`-Mode Claude`, or `mode claude` at the prompt) sends your question and the findings to the Claude API for open questions. It needs your own API key in the `ANTHROPIC_API_KEY` environment variable of that PowerShell window. The toolkit reads the key from there for each request and never saves, displays or logs it; MAC addresses, the PC name and your user name are masked before sending unless you pass `-NoRedact`. API usage is billed to your Anthropic account.

## Project structure

```
NetSecToolkit.cmd         Opens the menu (Start-NetSecToolkit)
NetSecToolkit/
  NetSecToolkit.psd1      Module manifest
  NetSecToolkit.psm1      Loads Private/ then Public/, exports Public/ only
  Public/                 One file per exported command
  Private/                Shared helpers, pure parsing and rating functions, assistant notes
tests/                    Pester tests (run in CI on every push)
.github/workflows/ci.yml  PSScriptAnalyzer lint + Pester tests on Windows
```

Parsing and decision logic (netsh Wi-Fi output including Wi-Fi 7 MLO, firewall log lines, subnet math, risky-port matching, speed test math, threat ratings, suspicious-path rules, the assistant's topic matching and fix order) lives in pure functions under `Private/`, so it's unit tested without touching the system.

## Development

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path ./NetSecToolkit -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

## Output and privacy

Reports, snapshots, program hashes, and speed test history are saved to `Documents\SecurityChecks`. They contain IP addresses, MAC addresses, device names, and file paths, so the included `.gitignore` keeps them out of the repository.

Nothing is sent anywhere by the checks themselves. The exceptions are the ones you ask for: `Test-NetworkSpeed` (Cloudflare), the public IP lookup in `Test-RouterExposure` (api.ipify.org, skip it with `-NoPublicIp`), and the assistant's Claude mode.

## Notes

- **Only scan networks you own or are authorized to test.** On a work or shared network, use `Find-NetworkDevice -Passive` or get permission first.
- `Test-NetworkSpeed` uses Cloudflare's public speed test endpoints, so results can differ slightly from other speed test sites.
- `Test-RouterExposure -Ssh` requires SSH to be enabled on the router (LAN only). Turn it back off when you're done.
- `Find-MalwareIndicator` is not an antivirus. A finding is a reason to look at a file, not proof; check its hash on VirusTotal before deleting anything.
- `Get-HardeningStatus` reads the password policy from `net accounts`, which it can only parse on English-language Windows.
- Looking for the Windows XP edition? See [powershell-network-security-toolkit-xp](https://github.com/EdwardOconnell/powershell-network-security-toolkit-xp).

## Coming from the standalone scripts?

| Old script | New command |
|---|---|
| `Workday-SecurityCheck.ps1` | `Invoke-DailySecurityCheck` |
| `Check-Firewall.ps1` | `Get-FirewallAudit` |
| `Check-NetAdapters.ps1` | `Get-NetAdapterHealth` |
| `Scan-LocalNetwork.ps1` | `Find-NetworkDevice` |
| `Check-RouterFirewall.ps1` | `Test-RouterExposure` |
| `Test-NetworkSpeed.ps1` | `Test-NetworkSpeed` |

Parameters are the same, and reports keep saving to the same folder, so existing history and snapshots carry over.

## License

[MIT](LICENSE)

<p align="center">
  <img src="assets/footer-logo.png" alt="Edward O'Connell EO shield logo" width="180">
</p>
