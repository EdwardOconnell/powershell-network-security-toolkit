# Offline notes for Invoke-NetSecAssistant. Each topic is matched by its Words:
# words of 4 characters or fewer must match a whole word, longer ones match
# anywhere, and phrases (with a space) count the most.

$script:AssistantKB = @(
    @{ Id = 'commands'; Title = 'What this toolkit can do'
       Words = @('commands', 'what can you do', 'toolkit', 'functions', 'cmdlets')
       Text = 'Checks: Get-HardeningStatus (baseline), Get-AccountAudit (accounts and logon), Get-FirewallAudit (firewall rules), Get-FirewallLog (what was blocked), Get-NetAdapterHealth (adapters and connectivity), Find-NetworkDevice (devices on the subnet), Test-RouterExposure (router ports), Get-USBHistory (USB drives ever connected), Get-ThreatExposure (which threats could work here), Find-MalwareIndicator (signs of malware), Test-NetworkSpeed. Fixes: Set-HardeningBaseline and Set-FirewallBaseline, both with -WhatIf. Invoke-DailySecurityCheck runs the checks together and saves a report. Start-NetSecToolkit opens a menu.'
       Do = 'Invoke-DailySecurityCheck' }
    @{ Id = 'firewall'; Title = 'Windows Defender Firewall'
       Words = @('firewall', 'mpssvc', 'profile', 'inbound', 'outbound', 'allow rule', 'firewall rule', 'public profile', 'private profile', 'domain profile')
       Text = 'Windows Defender Firewall has three profiles: Domain (work networks with a domain controller), Private (networks you marked as trusted) and Public (everything else). Each should be on and block inbound connections by default; allow rules then open specific programs or ports. A rule that opens a commonly attacked port (RDP 3389, SMB 445, WinRM 5985) to Any remote address, or allows a program that lives in a user-writable folder, deserves a look. Outbound traffic is allowed by default, so the firewall will not stop malware already on the PC from calling out.'
       Do = 'Get-FirewallAudit lists the risky rules; Set-HardeningBaseline turns every profile on with inbound blocked.' }
    @{ Id = 'firewalllog'; Title = 'Firewall logging and pfirewall.log'
       Words = @('pfirewall', 'firewall log', 'logging', 'dropped', 'blocked', 'blocked traffic', 'blocked connections', 'port scan', 'drops')
       Text = 'With logging of blocked connections on, the firewall writes every dropped packet to pfirewall.log under System32\LogFiles\Firewall (it rolls over to pfirewall.log.old). Get-FirewallLog summarizes it: how much was blocked, which addresses tried to reach this PC directly, likely port scans (one source trying 10 or more ports) and blocked traffic from the internet. Most drops are harmless broadcast and discovery traffic from other devices. Blocked traffic from internet addresses aimed straight at this PC means the router forwards ports to it or the PC has a public address.'
       Do = 'Get-FirewallLog -Hours 72 (from an Administrator window)' }
    @{ Id = 'smb'; Title = 'SMB file sharing, SMBv1 and port 445'
       Words = @('smb', 'smbv1', 'smb1', '445', 'file sharing', 'file and printer', 'shares', 'share', 'server service', 'lanmanserver', 'wannacry', 'eternalblue', 'notpetya')
       Text = 'SMB is Windows file and printer sharing, on TCP 445. SMBv1 is the 1980s version of the protocol: WannaCry and NotPetya spread through its flaws (EternalBlue, MS17-010), and it has no modern protections. Windows 10 and 11 no longer install it by default, but it can be left over from an upgrade or turned on for an old NAS or printer. Turning the SMBv1 server off does not affect normal sharing, which uses SMBv2 and SMBv3. Port 445 listening is normal while sharing is on; the firewall should only allow it on Private networks.'
       Do = 'Set-HardeningBaseline (SMBv1 step). Check with: Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol' }
    @{ Id = 'netbios'; Title = 'NetBIOS over TCP/IP (ports 137-139)'
       Words = @('netbios', 'netbios over tcp', '137', '138', '139', 'nbt', 'nbtstat', 'wins', 'llmnr', 'nbt-ns')
       Text = 'NetBIOS over TCP/IP is the old Windows naming system. It uses UDP 137 and 138 and TCP 139 and answers name lookups from anyone on the network, which lets an attacker on the same Wi-Fi pretend to be a server and capture logon hashes (NBT-NS poisoning). Modern networks use DNS instead. Turning it off on every adapter closes those ports. The one cost: very old NAS boxes and printers that are only reachable by their NetBIOS name need their IP address instead.'
       Do = 'Set-HardeningBaseline (NetBIOS step); add -Skip NetBIOS to keep it. Check with: nbtstat -n' }
    @{ Id = 'rdp'; Title = 'Remote Desktop (port 3389)'
       Words = @('rdp', 'remote desktop', '3389', 'bluekeep', 'nla', 'network level authentication', 'termservice', 'fdenytsconnections')
       Text = 'Remote Desktop lets someone log on to this PC over the network on TCP 3389. It is one of the most attacked services on the internet: bots guess passwords around the clock, and flaws such as BlueKeep (2019) let attackers in with no password on unpatched systems. If you do not use it, turn it off. If you do, require Network Level Authentication, keep account lockout on, allow it on Private networks only, and never forward port 3389 on the router; use a VPN to reach home instead. Windows Home editions cannot host Remote Desktop at all.'
       Do = 'Set-HardeningBaseline (RemoteDesktop step), or -Skip RemoteDesktop to keep it' }
    @{ Id = 'remoteassist'; Title = 'Remote Assistance'
       Words = @('remote assistance', 'fallowtogethelp', 'msra', 'quick assist', 'invitation')
       Text = 'Remote Assistance lets someone you invite see or control your screen. It is on by default and rarely used now that Quick Assist exists. Leaving it on keeps firewall rules open for it and gives tech-support scammers one more built-in tool to walk people through. Turning it off loses nothing unless you rely on the old invitation files.'
       Do = 'Set-HardeningBaseline (RemoteAssistance step) or Set-FirewallBaseline' }
    @{ Id = 'rpc'; Title = 'RPC (port 135)'
       Words = @('rpc', '135', 'endpoint mapper', 'dcom', 'rpcss')
       Text = 'TCP 135 is the RPC endpoint mapper. Windows itself depends on it, so it always listens and cannot be turned off. What matters is the firewall: with inbound connections blocked by default, other devices cannot reach it. The high-numbered ports listening next to it (49664 and up) are RPC services that follow the same rule.'
       Do = 'Get-FirewallAudit to confirm no rule opens 135 to Any address' }
    @{ Id = 'winrm'; Title = 'WinRM and PowerShell remoting (ports 5985, 5986)'
       Words = @('winrm', '5985', '5986', 'psremoting', 'powershell remoting', 'remoting', 'enter-pssession')
       Text = 'WinRM is the service behind PowerShell remoting. It is off by default on Windows 10 and 11 and only listens after Enable-PSRemoting. If you do not manage this PC from another one, keep it off: an attacker with a stolen password can run commands through it.'
       Do = 'Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled' }
    @{ Id = 'router'; Title = 'Router exposure'
       Words = @('router', 'gateway', 'port forward', 'port forwarding', 'dmz', 'admin page', 'tr-069', 'telnet on router', 'shieldsup', 'public ip')
       Text = 'The router is the real border between your network and the internet. Test-RouterExposure checks which services it offers on the inside (admin page, Telnet, FTP, file sharing) and shows your public IP. Telnet, FTP and PPTP should be off, the admin page should use HTTPS with a password you chose, and the firmware should be current. Port forwards and DMZ send internet traffic straight to one device, so remove any you do not need. Testing your own public IP from inside is unreliable; use an outside scanner such as GRC ShieldsUP.'
       Do = 'Test-RouterExposure' }
    @{ Id = 'routerupnp'; Title = 'UPnP on the router'
       Words = @('upnp', 'ssdp', '1900', 'universal plug', 'upnphost', 'ssdpsrv')
       Text = 'UPnP lets any program on any device ask the router to open a port to the internet, with no password. Game consoles use it; so does malware. If nothing at home needs it, turn it off in the router admin page and forward the few ports you need by hand. On the PC, SSDP Discovery and UPnP Device Host are what network discovery uses to find such devices; they are fine at home and not needed on public Wi-Fi.'
       Do = 'Router admin page > UPnP > off' }
    @{ Id = 'remotereg'; Title = 'Remote Registry'
       Words = @('remote registry', 'remoteregistry', 'regedit remotely')
       Text = 'The Remote Registry service lets another computer read and change this PC''s registry over the network with an administrator password. It is disabled by default on Windows 10 and 11. If it is set to start, something turned it on; unless a management tool you use needs it, disable it.'
       Do = 'Set-HardeningBaseline (RemoteRegistry step)' }
    @{ Id = 'legacysvc'; Title = 'Telnet and Simple TCP/IP Services'
       Words = @('telnet', 'tlntsvr', 'simple tcp', 'simptcp', 'echo', 'chargen', 'daytime', 'legacy services')
       Text = 'The Telnet server sends everything, passwords included, in plain text. Simple TCP/IP Services (echo, chargen, daytime on ports 7, 9, 13, 17 and 19) are leftovers from the 1980s that attackers use to amplify floods. Neither is installed by default and nothing modern needs them.'
       Do = 'Set-HardeningBaseline (LegacyServices step)' }
    @{ Id = 'guest'; Title = 'The Guest account'
       Words = @('guest', 'guest account')
       Text = 'The built-in Guest account has no password. When it is enabled, anyone at the keyboard, and in some configurations anyone on the network, gets in without one. It is disabled by default. The toolkit finds it by its SID, so a renamed Guest is still caught.'
       Do = 'Set-HardeningBaseline (Guest step)' }
    @{ Id = 'autorun'; Title = 'AutoRun and AutoPlay'
       Words = @('autorun', 'autoplay', 'autorun.inf', 'nodrivetypeautorun', 'usb worm', 'usb worms')
       Text = 'AutoRun starts a program named in a drive''s autorun.inf as soon as the drive is plugged in. USB worms such as Conficker spread that way. Since Windows 7, Windows ignores autorun.inf on USB drives, so the classic trick no longer works by itself, but AutoPlay still runs discs and offers actions for drives. Setting NoDriveTypeAutoRun to 255 turns both off for every drive type. An autorun.inf on a USB stick is still a sign it has been in an infected PC.'
       Do = 'Set-HardeningBaseline (AutoRun step)' }
    @{ Id = 'anonymous'; Title = 'Anonymous (null session) access'
       Words = @('anonymous', 'null session', 'restrictanonymous', 'restrictanonymoussam', 'enumeration')
       Text = 'A null session is a connection to file sharing with no user name. On a loosely configured PC it can list the user accounts and shares, which gives a password guesser its target list. RestrictAnonymousSAM = 1 (the default) blocks listing accounts; RestrictAnonymous = 1 also blocks listing shares and is not set by default.'
       Do = 'Set-HardeningBaseline (RestrictAnonymous step), then restart' }
    @{ Id = 'lmhash'; Title = 'LM password hashes'
       Words = @('lm hash', 'lm hashes', 'nolmhash', 'lanman', 'weak hash')
       Text = 'The LM hash is a 1980s way of storing passwords that can be cracked in seconds. Windows has not stored it by default since Vista (NoLMHash = 1). If the check finds it off, someone changed it; turn it back on and change the passwords, because old hashes stay until each password is next changed.'
       Do = 'Set-HardeningBaseline (NoLMHash step), then change passwords' }
    @{ Id = 'ntlm'; Title = 'NTLMv2 and LmCompatibilityLevel'
       Words = @('ntlm', 'ntlmv1', 'ntlmv2', 'lmcompatibilitylevel', 'logon response')
       Text = 'When this PC logs on to another computer''s share it proves the password with an LM, NTLMv1 or NTLMv2 response. The first two can be cracked or relayed easily. LmCompatibilityLevel 3 or higher sends NTLMv2 only, which is what Windows does when the value is not set. A value below 3 was put there on purpose, usually for a very old NAS.'
       Do = 'Set-HardeningBaseline (NTLMv2 step); add -Skip NTLMv2 if an old device stops accepting logons' }
    @{ Id = 'policy'; Title = 'Password length and account lockout'
       Words = @('password policy', 'minimum password', 'password length', 'lockout', 'net accounts', 'bad password', 'lock out')
       Text = 'Two settings stop password guessing: a minimum length, so short passwords cannot be set, and account lockout, which freezes an account for a while after a number of wrong tries. The baseline sets 8 or more characters and a 30-minute lockout after 10 bad tries. A new minimum length applies the next time each password is changed. Longer is better: a passphrase of three or four words beats a short complex password.'
       Do = 'Set-HardeningBaseline (PasswordPolicy step). Check with: net accounts' }
    @{ Id = 'blankpw'; Title = 'Blank passwords'
       Words = @('blank password', 'no password', 'empty password', 'limitblankpassworduse', 'passwordrequired', 'passwordreq')
       Text = 'An account with no password lets anyone at the keyboard in. Windows limits the damage: with LimitBlankPasswordUse = 1 (the default) such an account cannot log on over the network. "PasswordRequired = False" means the account is allowed to have a blank password, not that it has one; set it back and give the account a password.'
       Do = 'net user "<name>" /passwordreq:yes, then net user "<name>" * to set a password' }
    @{ Id = 'admin'; Title = 'Administrator accounts'
       Words = @('administrator', 'administrators', 'admin account', 'standard account', 'limited account', 'built-in administrator')
       Text = 'Anything you run as an administrator can change the whole system once you approve the UAC prompt, and malware asks too. Day-to-day work is safer in a standard account, with one separate administrator account for installs. The built-in Administrator account (SID ending in -500) is disabled by default and should stay that way: it is the first name attackers try.'
       Do = 'Get-AccountAudit lists who is an administrator' }
    @{ Id = 'autologon'; Title = 'Automatic logon'
       Words = @('automatic logon', 'autologon', 'autoadminlogon', 'defaultpassword', 'netplwiz', 'auto logon')
       Text = 'With automatic logon, Windows signs in by itself at startup, so anyone who turns the PC on gets your desktop. When it is set through the registry, the password sits in plain text in the Winlogon key (DefaultPassword), readable by any administrator or anyone who boots the PC from a USB stick.'
       Do = 'netplwiz > tick "Users must enter a user name and password"; delete the DefaultPassword value' }
    @{ Id = 'screenlock'; Title = 'Screen lock'
       Words = @('screen saver', 'screensaver', 'screen lock', 'lock screen', 'lock the pc', 'dynamic lock')
       Text = 'An unlocked PC is open to whoever walks past. Windows key + L locks it right away. To lock it automatically, set a screen saver with "On resume, display logon screen", or have Windows require sign-in after sleep; Dynamic Lock can also lock it when your phone goes out of Bluetooth range.'
       Do = 'Settings > Accounts > Sign-in options' }
    @{ Id = 'uac'; Title = 'User Account Control (UAC)'
       Words = @('uac', 'user account control', 'enablelua', 'elevation', 'consent prompt')
       Text = 'UAC makes programs ask before they get administrator rights, even when you are signed in as an administrator. With it off (EnableLUA = 0), every program you start, and every piece of malware, has full control of the system without a prompt, and several Windows protections stop working.'
       Do = 'Control Panel > User Accounts > Change User Account Control settings > default level or higher, then restart' }
    @{ Id = 'dep'; Title = 'Data Execution Prevention (DEP)'
       Words = @('dep', 'data execution prevention', 'noexecute', 'bcdedit')
       Text = 'DEP stops code from running in memory areas meant for data, which blocks a whole class of exploits. On 64-bit Windows every 64-bit program always uses it; the policy (OptIn by default) only decides what happens to 32-bit programs. AlwaysOff is the one setting that is wrong.'
       Do = 'bcdedit /set "{current}" nx OptIn (then restart) if it was turned off' }
    @{ Id = 'updates'; Title = 'Windows updates and end of support'
       Words = @('update', 'updates', 'windows update', 'patch', 'patches', 'patched', 'hotfix', 'end of support', 'windows 10', 'esu', 'extended security updates')
       Text = 'Monthly Windows updates fix flaws that are public knowledge the day they ship, so a PC that falls months behind is exposed to attacks that are already written. The toolkit reads the date of the last installed update: over 45 days is a warning, over 120 a risk. Free security updates for Windows 10 ended on October 14, 2025; after that it only stays patched through Microsoft''s Extended Security Updates program, and the lasting fix is a supported Windows version.'
       Do = 'Settings > Windows Update > Check for updates' }
    @{ Id = 'threats'; Title = 'Which threats this PC is exposed to'
       Words = @('threat', 'threats', 'exposed', 'exposure', 'ransomware', 'worm', 'worms', 'botnet', 'get-threatexposure')
       Text = 'Get-ThreatExposure turns settings into plain answers: for SMB worms, Remote Desktop attacks, USB worms, password guessing, password theft, ransomware and malware, and unpatched flaws, it says whether this PC is Protected, Partly protected or Exposed, and why. Exposed means the attack would work today if it reached this PC. It reads settings and update history; it does not scan files.'
       Do = 'Get-ThreatExposure' }
    @{ Id = 'lsa'; Title = 'Password theft and LSA protection'
       Words = @('lsa', 'lsass', 'runasppl', 'credential guard', 'pass-the-hash', 'pass the hash', 'mimikatz', 'password theft', 'core isolation')
       Text = 'Windows keeps logon secrets in the memory of the LSASS process. Malware that runs as administrator can read them and reuse them on other computers (pass-the-hash). LSA protection (RunAsPPL) makes LSASS a protected process so ordinary administrator tools cannot read it; Credential Guard goes further on PCs that support it. Using a standard account day to day matters just as much, because the attack needs administrator rights first.'
       Do = 'Windows Security > Device security > Core isolation > Local Security Authority protection' }
    @{ Id = 'malware'; Title = 'Signs of malware'
       Words = @('malware', 'virus', 'infected', 'infection', 'trojan', 'suspicious', 'find-malwareindicator', 'hacked', 'compromised')
       Text = 'Find-MalwareIndicator is not an antivirus. It looks where malware has to live to survive a restart: startup entries, services, scheduled tasks, the Winlogon keys, plus the places it hides (Temp, the Recycle Bin, AppData, the Public folder) and the tricks it uses to stay (a hosts file that blocks antivirus sites, Defender exclusions, debugger hijacks of security tools). A finding is a reason to look, not proof: installers run from Temp too. Check the file''s SHA-256 on VirusTotal before deleting anything.'
       Do = 'Find-MalwareIndicator -ExportPath hashes.csv, then a full scan in Windows Security' }
    @{ Id = 'startup'; Title = 'Startup entries, Winlogon, AppInit_DLLs and IFEO'
       Words = @('startup', 'run key', 'runonce', 'winlogon', 'userinit', 'appinit', 'appinit_dlls', 'ifeo', 'image file execution', 'debugger', 'scheduled task', 'scheduled tasks', 'starts at logon')
       Text = 'Programs start by themselves from the Run and RunOnce registry keys, the Startup folders, services and scheduled tasks. Malware adds itself there, usually pointing at a file in Temp or AppData. Three registry tricks go deeper: Winlogon Shell and Userinit (run at every logon), AppInit_DLLs (a DLL loaded into every program) and Image File Execution Options Debugger (starting one program secretly runs another, used to disable Task Manager or antivirus). Task Manager > Startup apps shows the ordinary ones.'
       Do = 'Find-MalwareIndicator' }
    @{ Id = 'hosts'; Title = 'The hosts file'
       Words = @('hosts', 'hosts file', 'drivers\etc', 'redirect', 'redirects')
       Text = 'The hosts file (System32\drivers\etc\hosts) overrides DNS: a line there can send any site name to any address. Malware uses it to point antivirus and update sites at nothing, or banks at a fake server. Ad-block lists and some developer tools use it legitimately. Lines you did not add that name Microsoft, antivirus or search sites should go.'
       Do = 'notepad $env:windir\System32\drivers\etc\hosts (as administrator)' }
    @{ Id = 'virustotal'; Title = 'Checking files with VirusTotal'
       Words = @('virustotal', 'hash', 'hashes', 'sha256', 'sha-256', 'exportpath', 'signer', 'signature', 'signed')
       Text = 'A SHA-256 hash identifies an exact file. Pasting it into virustotal.com shows what 70 or more antivirus engines say about that file without uploading it. Find-MalwareIndicator -ExportPath saves a CSV of every program it looked at with its hash, its code-signing status and a ready-made link. A file nobody has seen before is not proof of anything; a file many engines flag is.'
       Do = 'Find-MalwareIndicator -ExportPath hashes.csv' }
    @{ Id = 'antivirus'; Title = 'Antivirus and Microsoft Defender'
       Words = @('antivirus', 'defender', 'real-time', 'realtime', 'definitions', 'security center', 'exclusion', 'exclusions', 'windows security', 'tamper protection')
       Text = 'Microsoft Defender is built in and turns itself on when no other antivirus is installed. What matters: real-time protection on, definitions updated in the last few days, and Tamper Protection on so malware cannot switch it off. Exclusions tell Defender not to scan a folder, file type or process; malware with administrator rights adds exclusions for its own folder, so any you did not add, or any that covers a whole drive, Temp or AppData, should be removed.'
       Do = 'Windows Security > Virus & threat protection; Update-MpSignature' }
    @{ Id = 'apipa'; Title = 'APIPA (169.254.x.x) and DHCP'
       Words = @('apipa', '169.254', 'dhcp', 'no ip', 'ip address', 'lease')
       Text = 'An address that starts with 169.254 means the adapter asked for an address by DHCP and nobody answered, so Windows made one up. The PC can only talk to other devices in the same state. Check the cable or Wi-Fi connection and that the router''s DHCP server is on.'
       Do = 'ipconfig /release, then ipconfig /renew; Get-NetAdapterHealth' }
    @{ Id = 'connectivity'; Title = 'Gateway, DNS and connectivity'
       Words = @('gateway', 'dns', 'ping', 'internet', 'connectivity', 'no internet', 'offline', 'packet errors', 'driver')
       Text = 'Get-NetAdapterHealth works outward: the adapter and its driver, the IP address, whether the gateway (router) answers, then an internet address, a DNS lookup and an HTTPS connection. The first step that fails is where the problem is: no gateway reply is the local network, ping without DNS is the DNS server, DNS without HTTPS is usually a firewall or proxy.'
       Do = 'Get-NetAdapterHealth' }
    @{ Id = 'speed'; Title = 'Connection speed'
       Words = @('speed', 'slow', 'bandwidth', 'mbps', 'latency', 'wi-fi signal', 'test-networkspeed')
       Text = 'Test-NetworkSpeed shows the network you are on (SSID, band, channel, signal, link rate, router, ISP) and measures router ping, internet latency and jitter, and download and upload speed against Cloudflare''s speed test, so you can tell a slow internet line from a weak wireless link. Each result is added to a CSV history.'
       Do = 'Test-NetworkSpeed' }
    @{ Id = 'devices'; Title = 'Devices on the network, ARP and MAC addresses'
       Words = @('devices', 'device', 'arp', 'mac address', 'randomized', 'random mac', 'unknown device', 'new device', 'find-networkdevice', 'neighbor')
       Text = 'Find-NetworkDevice lists what shares your subnet, from a ping sweep and the neighbor (ARP) table (-Passive sends nothing and reads the table only). Every device has a MAC address; phones and laptops now use a random one per network for privacy, so a "new" device with a randomized MAC is usually one you already own. The daily check remembers the devices it has seen on each network and flags new ones with a fixed MAC. If you do not recognize one, compare it with the router''s client list.'
       Do = 'Find-NetworkDevice (only on networks you own or may scan)' }
    @{ Id = 'usb'; Title = 'USB storage history'
       Words = @('usb', 'usbstor', 'flash drive', 'thumb drive', 'usb drive', 'usb storage', 'serial number')
       Text = 'Windows records every USB storage device ever connected, with its model and serial number, under the USBSTOR registry key. Get-USBHistory lists them, and the daily check flags any that appeared since the last run, which shows when someone plugged a drive in while you were away.'
       Do = 'Get-USBHistory' }
    @{ Id = 'ports'; Title = 'Listening ports'
       Words = @('listening', 'ports', 'open port', 'open ports', 'netstat', 'get-nettcpconnection', '49664')
       Text = 'A listening port is a program waiting for connections. Listening is not the same as reachable: the firewall decides who can connect. Some always listen on Windows (135 RPC, 445 file sharing, the 49664+ range). The ones to question are remote-control and legacy services: 3389 Remote Desktop, 5985 WinRM, 5900 VNC, 23 Telnet, 21 FTP, 22 SSH.'
       Do = 'Get-NetTCPConnection -State Listen | Sort-Object LocalPort; Get-Process -Id <OwningProcess>' }
    @{ Id = 'undo'; Title = 'Undoing a hardening step'
       Words = @('undo', 'revert', 'roll back', 'rollback', 'turn back on', 're-enable', 'reenable', 'broke', 'stopped working')
       Text = 'Each step changes one thing, so it can be undone on its own. Remote Desktop: System Properties > Remote. Remote Assistance: the same tab. NetBIOS: adapter properties > IPv4 > Advanced > WINS > Default. SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $true. Services: Set-Service <name> -StartupType Manual. Guest: net user Guest /active:yes. Registry values (RestrictAnonymous, NoLMHash, LmCompatibilityLevel, NoDriveTypeAutoRun): delete the value or set the old number. Password policy: net accounts /minpwlen:0 /lockoutthreshold:0.'
       Do = 'Next time, preview with Set-HardeningBaseline -WhatIf and leave things out with -Skip' }
    @{ Id = 'whatif'; Title = '-WhatIf, -Confirm and -Skip'
       Words = @('whatif', '-whatif', 'preview', 'confirm', '-confirm', 'skip', '-skip', 'dry run')
       Text = 'Only two commands change settings: Set-HardeningBaseline and Set-FirewallBaseline. Both accept -WhatIf, which lists every change without making it, and -Confirm, which asks before each one. Set-HardeningBaseline -Skip leaves named steps alone. Step names: Firewall, Logging, RemoteAssistance, RemoteDesktop, RemoteRegistry, LegacyServices, SMBv1, NetBIOS, Guest, RestrictAnonymous, NoLMHash, NTLMv2, PasswordPolicy, AutoRun.'
       Do = 'Set-HardeningBaseline -WhatIf' }
    @{ Id = 'daily'; Title = 'The all-in-one check and its reports'
       Words = @('daily', 'daily check', 'invoke-dailysecuritycheck', 'report', 'reports', 'snapshot', 'html', 'transcript', 'securitychecks')
       Text = 'Invoke-DailySecurityCheck runs every check in one go, compares the network devices and USB drives with the last run, prints a summary and a fix order, and saves four files in Documents\SecurityChecks: Report_*.html (open in a browser), Check_*.txt (the full console output), Snapshot_*.json (what the next run compares against) and Hashes_*.csv. It changes no settings.'
       Do = 'Invoke-DailySecurityCheck' }
    @{ Id = 'assistant'; Title = 'This assistant and Claude mode'
       Words = @('assistant', 'claude', 'claude mode', 'api key', 'anthropic', 'offline mode', 'redact', 'privacy', 'nsai')
       Text = 'Offline mode (the default) answers from notes built into the module and the findings of the checks you ran; nothing leaves the PC. Claude mode sends your question and the findings to the Claude API for open questions. It needs your own API key in the ANTHROPIC_API_KEY environment variable of this PowerShell window; the toolkit reads it from there for each request and never saves, prints or logs it. MAC addresses, the PC name and your user name are masked before sending unless you pass -NoRedact. Usage is billed to your Anthropic account.'
       Do = 'Set $env:ANTHROPIC_API_KEY in this window, then: Invoke-NetSecAssistant -Mode Claude (or type: mode claude)' }
)
