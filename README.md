# Windows Sandbox Escape Test

## Overview

This PowerShell script tests the Windows Sandbox escape technique documented in the ITOCHU Cyber & Intelligence blog post. It automates the setup and execution of a controlled security research test that demonstrates how scheduled tasks can be used to escape Windows Sandbox isolation.

## Threat Background

### MirrorFace APT Campaign

In January 2025, the National Police Agency (NPA) and the National Center of Incident Readiness and Strategy for Cybersecurity (NISC) released a security advisory regarding an APT attack campaign targeting organizations in Japan by MirrorFace (a subgroup of APT10). The advisory highlighted that MirrorFace exploited Windows Sandbox and Visual Studio Code as attack techniques.

### LilimRAT and Windows Sandbox Abuse

MirrorFace utilized LilimRAT, a customized version of the open-source Lilith RAT, which was specifically designed to run only within Windows Sandbox environments. The malware checks for the existence of the WDAGUtilityAccount user folder and terminates if it is not present, indicating it was purpose-built for sandbox execution.

### Attack Flow

The typical attack flow documented by ITOCHU Cyber & Intelligence involves:

1. Compromising a target machine
2. Enabling Windows Sandbox feature (requires administrator privileges)
3. Creating a WSB configuration file on the system
4. Rebooting the host machine to activate Windows Sandbox
5. Executing malware within the sandbox according to WSB file configuration
6. Establishing C2 communication, often via Tor network
7. Operating in an environment free from security products (Windows Defender is disabled in sandbox)

### Why Attackers Use Windows Sandbox

Windows Sandbox provides attackers with several advantages:

- Isolation from host security products and monitoring tools
- Windows Defender is disabled by default and cannot be enabled
- Activities within the sandbox are not logged by host monitoring tools
- Malware can access host machine files through mapped folders
- When executed via Task Scheduler under SYSTEM privileges, sandbox runs in background without visible window
- Artifacts within the sandbox are deleted when it closes, making forensic investigation difficult

### Emerging Threats - wsb.exe Command-Line Interface

Windows 11 updates introduced wsb.exe, which significantly increases attack surface:

- Background execution without GUI
- Sandbox configuration via command-line arguments (no WSB file needed)
- Persistent data inside sandbox when window is closed
- Remote session capabilities

These updates make detection more challenging as traditional forensic artifacts (WSB files) may not exist.

## Prerequisites

- Windows 10 Pro/Enterprise or Windows 11 Pro/Enterprise
- Administrator privileges
- At least 4GB of available RAM
- Virtualization enabled in BIOS
- One of the following for process monitoring:
  - Sysmon installed and running
  - Windows Event Log Process Creation auditing enabled (Event ID 4688)

## Installation

1. Save the script to a location on your system
2. Open PowerShell as Administrator
3. Navigate to the script location
4. Run the script

## Usage

```powershell
.\SandboxEscapeTest.ps1
```

The script will:
1. Check for and enable Windows Sandbox feature if needed
2. Verify process auditing or Sysmon presence
3. Create C:\SandBoxShenanigans folder structure
4. Generate a Windows Sandbox configuration file
5. Create an inner PowerShell script for sandbox execution
6. Launch Windows Sandbox with the configuration
7. Log all activities

## What the Test Does

### Host System Actions
- Enables Windows Sandbox feature
- Creates folder structure for testing
- Generates .wsb configuration file
- Maps host folder to sandbox for read/write access
- Launches sandbox with automated script execution

### Inside the Sandbox
- Compiles a C# DNS lookup binary
- Creates a scheduled task XML file (WSB escape payload)
- Creates a test user account named WSBShenanigans
- Tests the DNS lookup binary
- Logs all activities to the mapped folder

### Real-World Attack Techniques (MirrorFace Campaign)

Based on ITOCHU Cyber & Intelligence research, MirrorFace used the following attack flow:

#### Attack Components
1. **BAT file**: Orchestrates extraction and execution
2. **Archiver**: Tool like 7-Zip to extract malware
3. **Archive file**: Contains the malware payload (LilimRAT)
4. **WSB configuration file**: Defines folder mapping and startup commands

#### Typical WSB Configuration Used by Attackers
```xml
<Configuration>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\{Host-side folder}</HostFolder>
      <SandboxFolder>C:\{Sandbox-side folder}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\{Sandbox-side folder}\{random}.bat</Command>
  </LogonCommand>
  <MemoryInMB>1024</MemoryInMB>
</Configuration>
```

#### Attack Execution Flow
1. Enable Windows Sandbox feature on compromised host
2. Place attack files (BAT, archiver, archive) in host folder
3. Restart host machine to activate sandbox feature
4. Execute WSB file (either manually or via Task Scheduler as SYSTEM)
5. BAT file auto-executes in sandbox, extracts and runs malware
6. Malware establishes C2 communication via Tor network
7. Attacker operates with access to host files through mapped folders
8. No detection by host security products or monitoring tools

#### Stealth Techniques
- **Background Execution**: When launched via Task Scheduler under SYSTEM account, no sandbox window appears
- **Tor Network**: Encrypts C2 communication and conceals C2 server location
- **No Antivirus**: Windows Defender is disabled in sandbox and cannot be enabled
- **Evading EDR**: Host EDR cannot monitor activities inside sandbox
- **Artifact Deletion**: When sandbox closes, all internal files are deleted (unless using wsb.exe with persistent mode)

## Output Locations

All test artifacts are created in C:\SandBoxShenanigans:

- test_log.txt - Host system activity log
- sandbox.wsb - Windows Sandbox configuration file
- SharedFolder\sandbox_log.txt - Sandbox activity log
- SharedFolder\DNSLookup.exe - Compiled C# binary
- SharedFolder\DNSLookup.cs - C# source code
- SharedFolder\WSBEscapeTask.xml - Scheduled task XML
- SharedFolder\inner_script.ps1 - Sandbox execution script

## Events to Monitor

### Windows Event Logs

#### Security Log (Event ID 4688 - Process Creation)
Search for these processes to track the attack chain:

```
EventID: 4688
Process Names to Monitor:
- powershell.exe
- csc.exe (C# compiler)
- DNSLookup.exe
- cmd.exe
- net.exe or net1.exe (user creation)
```

Filter command:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Message -match 'powershell|csc|DNSLookup|WSBShenanigans'}
```

#### Security Log (Event ID 4720 - User Account Created)
```
EventID: 4720
Account Name: WSBShenanigans
```

Filter command:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} | Where-Object {$_.Message -match 'WSBShenanigans'}
```

#### Security Log (Event ID 4624 - Logon Events)
Monitor for any logon attempts with WSBShenanigans account

#### System Log (Event ID 7045 - Service Installation)
If the scheduled task is registered as a service

### Sysmon Events

#### Event ID 1 - Process Creation
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=1)]]
      and
      *[EventData[Data[@Name='Image'] and (
        Data='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' or
        Data='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' or
        Data='C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe'
      )]]
    </Select>
  </Query>
</QueryList>
```

Key fields to examine:
- ParentImage (should show WindowsSandbox.exe or related)
- CommandLine (shows script execution details)
- User (WDAGUtilityAccount indicates sandbox context)

#### Event ID 11 - File Creation
Monitor for:
- DNSLookup.exe creation
- DNSLookup.cs creation
- WSBEscapeTask.xml creation
- sandbox_log.txt writes

```
EventID: 11
TargetFilename patterns:
- *\SharedFolder\DNSLookup.exe
- *\SharedFolder\WSBEscapeTask.xml
- *\SharedFolder\sandbox_log.txt
```

#### Event ID 3 - Network Connection
Monitor DNS lookup binary network activity:
```
EventID: 3
Image: *\DNSLookup.exe
DestinationPort: 53 (DNS)
```

#### Event ID 13 - Registry Value Set
If the scheduled task modifies registry:
```
EventID: 13
TargetObject: *\Schedule\TaskCache\*
```

### PowerShell Operational Log (Event ID 4104 - Script Block Logging)
If PowerShell script block logging is enabled:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -match 'WSBShenanigans|SandBox|inner_script'}
```

### Windows Sandbox Process Monitoring

Monitor the following processes to detect Windows Sandbox execution on the host:

| Process Name | Path | Detection Context |
|--------------|------|-------------------|
| WindowsSandbox.exe | C:\Windows\System32\WindowsSandbox.exe | WSB file execution and normal startup |
| WindowsSandboxClient.exe | C:\Windows\System32\WindowsSandboxClient.exe | WSB file execution and normal startup |
| cmproxyd.exe | C:\Windows\System32\cmproxyd.exe | WSB file execution and normal startup |
| WindowsSandboxServer.exe | C:\Program Files\WindowsApps\MicrosoftWindows.WindowsSandbox_0.3.1.0_x64__cw5n1h2txyewy | Command execution using wsb.exe (Windows 11 preview only) |
| WindowsSandboxRemoteSession.exe | C:\Program Files\WindowsApps\MicrosoftWindows.WindowsSandbox_0.3.1.0_x64__cw5n1h2txyewy | Command execution using wsb.exe (Windows 11 preview only) |
| wsb.exe | C:\Users\{USERNAME}\AppData\Local\Microsoft\WindowsApps\wsb.exe | Command-line sandbox execution (Windows 11 preview only) |
| vmmemWindowsSandbox | Memory process | Contains sandbox memory (Windows 11) |
| vmmem | Memory process | Contains sandbox memory (Windows 10) |

### Windows Sandbox Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 1 | Microsoft-Windows-Hyper-V-VmSwitch-Operational | Network adapter operations |
| 7045 | System | Service installation (Windows Sandbox service) |
| 4688 | Security | Process creation events |
| 4624 | Security | Successful account logon |
| Various | Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | RDP session related to sandbox |

## Search Queries by Tool

### Windows Event Viewer
1. Open Event Viewer
2. Navigate to Windows Logs > Security
3. Filter Current Log
4. Add Event IDs: 4688, 4720, 4624
5. Search for "WSBShenanigans" or "SandBox"

### Sysmon View
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {
    $_.Message -match 'WSBShenanigans|DNSLookup|SharedFolder|WDAGUtilityAccount'
} | Format-List TimeCreated, Id, Message
```

### Splunk Query
```
index=windows (source="WinEventLog:Security" EventCode IN (4688, 4720, 4624)) OR (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (1, 3, 11, 13))
| search "WSBShenanigans" OR "DNSLookup" OR "SharedFolder" OR "WDAGUtilityAccount"
| table _time, EventCode, ComputerName, User, Process, CommandLine, TargetFilename
```

### Elastic/ELK Query
```
event.code:(4688 OR 4720 OR 4624 OR 1 OR 3 OR 11 OR 13) AND 
(process.name:("powershell.exe" OR "csc.exe" OR "DNSLookup.exe") OR 
 user.name:"WSBShenanigans" OR 
 file.path:*SharedFolder*)
```

## Detection Indicators

### Behavioral Indicators
- PowerShell execution within Windows Sandbox context (WDAGUtilityAccount)
- C# compiler (csc.exe) execution in sandbox
- User account creation in sandbox environment
- File writes to mapped/shared folders
- Scheduled task XML file creation
- DNS resolution from custom binary

### File System Indicators
- C:\SandBoxShenanigans directory creation
- Files in SharedFolder with .xml, .exe, .cs extensions
- Log files tracking sandbox activity

### Network Indicators
- DNS queries from DNSLookup.exe
- Uncommon user agent strings if binary is modified
- Connections to configurable domains

## Forensic Artifacts

### Host Machine Artifacts

Based on ITOCHU Cyber & Intelligence research, the following artifacts may remain on the host machine:

#### File System
- **$MFT**: Records creation of WSB files, mount source folders, and VHDX files
- **$UsnJrnl**: Logs WSB file creation, mount source folder creation, and VHDX file creation
- **Prefetch**: May record loading of WSB and VHDX files
- **VHDX Location**: C:\ProgramData\Microsoft\Windows\Containers (contains parent and differential virtual disks)

#### Registry
```
HKLM\SOFTWARE\Classes\Applications\WindowsSandbox.exe
HKLM\SOFTWARE\Classes\Windows.Sandbox\shell\open\command
HKLM\SOFTWARE\Microsoft\Windows Sandbox\Capabilities\FileAssociations
```

#### Process Memory
The vmmemWindowsSandbox (Windows 11) or vmmem (Windows 10) process contains sandbox memory and can be scanned for malware signatures using Yara or similar tools.

### Windows Sandbox VHDX Analysis

If sandbox-related processes are detected, preserve all VHDX folders with parent and differential disk chain intact. The VHDX can be mounted for forensic analysis.

#### Available Artifacts Inside Sandbox
- **$MFT**: Available (operations on shared host folders are not recorded)
- **$UsnJrnl**: Available (operations on shared host folders are not recorded)
- **Registry**: Available (Amcache updates may not be present)
- **Browser History**: Available for Edge and user-installed browsers
- **Event Logs**: Available (default storage: 20,480 KB, some events like task schedules may not be recorded)

#### Unavailable Artifacts Inside Sandbox
- **Prefetch**: Not recorded
- **SRUM**: Not recorded

### Event Log Indicators (Sandbox Context)

When analyzing mounted VHDX files:

**Security Log Events**
- Event ID 4624: Successful logon
- Event ID 4625: Failed logon
- Event ID 4648: Logon with explicit credentials
- Event ID 7045: Service installation

### Network Indicators
- DNS queries from DNSLookup.exe
- Uncommon user agent strings if binary is modified
- Connections to configurable domains

## Enabling Process Auditing Manually

If the script does not automatically enable process auditing:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

Verify:
```powershell
auditpol /get /subcategory:"Process Creation"
```

## Installing Sysmon

Download Sysmon from Microsoft Sysinternals:
https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

Basic installation:
```powershell
sysmon64.exe -accepteula -i
```

With configuration file:
```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
```

## Cleaning Up

To remove test artifacts:

```powershell
Remove-Item -Path "C:\SandBoxShenanigans" -Recurse -Force
```

To disable Windows Sandbox feature:
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -NoRestart
```

## Security Considerations

This script is for authorized security testing and research only. Use only in controlled environments:

- Do not run on production systems without approval
- Ensure proper logging and monitoring are in place
- Review all generated files before use
- The test creates a local user account that should be removed after testing
- Sandbox is isolated but the test demonstrates escape techniques

### Recommended Countermeasures (Based on ITOCHU Research)

#### Prevention

1. **Keep Windows Sandbox Disabled by Default**
   - Windows Sandbox is disabled by default and should remain so unless required for business purposes
   - Regularly audit which systems have the feature enabled

2. **Restrict Administrator Privileges**
   - Enabling Windows Sandbox requires administrator privileges
   - Follow principle of least privilege for user accounts
   - Monitor privilege escalation attempts

3. **Implement AppLocker Policies**
   - Create policies to block Windows Sandbox executables
   - Block the following processes:
     - WindowsSandbox.exe
     - WindowsSandboxClient.exe
     - wsb.exe
   - AppLocker generates Event ID 8003 (EXE and DLL), 8004 (Script), 8006 (MSI), 8007 (Packaged app) when blocking execution

4. **Group Policy Management**
   - Use Group Policy to prevent installation of Windows Sandbox feature
   - Monitor for unauthorized Group Policy changes

#### Detection

1. **Monitor Feature Enablement**
   - Alert on Windows Sandbox feature being enabled
   - Track changes to optional features via Event Logs

2. **Process Monitoring**
   - Alert on execution of Windows Sandbox processes
   - Monitor parent-child process relationships
   - Watch for sandbox processes launched from unexpected parents (e.g., Task Scheduler, schtasks.exe)

3. **Memory Scanning**
   - Scan vmmemWindowsSandbox (Windows 11) or vmmem (Windows 10) process memory
   - Use Yara rules to detect malware signatures in sandbox memory

4. **Network Monitoring**
   - Monitor for Tor network traffic
   - Track unusual DNS queries
   - Correlate network activity with sandbox process execution

5. **File System Monitoring**
   - Alert on WSB file creation
   - Monitor C:\ProgramData\Microsoft\Windows\Containers for VHDX files
   - Track changes to shared/mapped folders

#### Response

1. **Preserve VHDX Files**
   - If sandbox activity detected, immediately preserve VHDX folder structure
   - Maintain parent and differential disk chain integrity
   - Copy entire C:\ProgramData\Microsoft\Windows\Containers folder before sandbox closes

2. **Memory Acquisition**
   - Capture memory dump including vmmemWindowsSandbox/vmmem process
   - Use tools like Volatility or Rekall for analysis

3. **Network Forensics**
   - Capture packet captures during suspected sandbox activity
   - Analyze for C2 communication patterns

## Troubleshooting

### Windows Sandbox Does Not Launch
- Verify virtualization is enabled in BIOS
- Check Windows version (Pro/Enterprise required)
- Restart after enabling the feature
- Ensure sufficient system resources

### Process Auditing Events Not Appearing
- Verify audit policy is enabled
- Check Security log for Event ID 4688
- Restart after enabling auditing
- Ensure log is not full

### Sysmon Not Detecting Events
- Verify Sysmon service is running
- Check configuration includes process creation events
- Review Sysmon operational log permissions

### Script Execution Policy Errors
Run as Administrator:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

## References

### Primary Research

ITOCHU Cyber & Intelligence - Hack The Sandbox: Unveiling the Truth Behind Disappearing Artifacts
https://blog-en.itochuci.co.jp/entry/2025/03/12/140000

JSAC2025 Presentation
https://jsac.jpcert.or.jp/archive/2025/pdf/JSAC2025_2_9_kamekawa_sasada_niwa_en.pdf

### Official Advisories

National Police Agency (NPA) - Advisory on MirrorFace Cyber Attacks
https://www.npa.go.jp/bureau/cyber/koho/caution/caution20250108.html

National Police Agency - Windows Sandbox Abuse Techniques and Detection
https://www.npa.go.jp/bureau/cyber/pdf/20250108_windowssandbox.pdf

### Additional Threat Intelligence

ESET - Operation AkaiRyu: MirrorFace invites Europe to EXPO 2025 and revives ANEL backdoor
https://jsac.jpcert.or.jp/archive/2025/pdf/JSAC2025_2_8_dominik_breitenbacher_en.pdf

Trend Micro - Spot the Difference: Earth Kasha's New LODEINFO Campaign
https://www.trendmicro.com/en_us/research/24/k/lodeinfo-campaign-of-earth-kasha.html

JPCERT/CC - MirrorFace Attack against Japanese Organisations
https://blogs.jpcert.or.jp/en/2024/07/mirrorface-attack-against-japanese-organisations.html

ESET - Unmasking MirrorFace: Operation LiberalFace
https://www.welivesecurity.com/2022/12/14/unmasking-mirrorface-operation-liberalface-targeting-japanese-political-entities/

### Microsoft Documentation

Windows Sandbox Overview
https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview

Windows Sandbox Architecture
https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-architecture

Windows Sandbox Configuration
https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file

Windows 11 KB5044384 Update (wsb.exe introduction)
https://support.microsoft.com/en-us/topic/october-24-2024-kb5044384-os-build-26100-2161-preview-5a4ac390-7c7b-4f7f-81c2-c2b329ac86ab

AppLocker Documentation
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview

## License

This script is provided for educational and authorized security testing purposes only. Use at your own risk. Brush your teeth and floss, and also consider eating less and excercising more while we are giving advice 
