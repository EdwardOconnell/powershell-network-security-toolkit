# Changelog

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
