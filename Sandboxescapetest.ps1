#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$BaseFolder = "C:\SandBoxShenanigans"
$LogFile = Join-Path $BaseFolder "test_log.txt"
$ConfigFile = Join-Path $BaseFolder "sandbox.wsb"
$MappedFolder = Join-Path $BaseFolder "SharedFolder"
$InnerScriptPath = Join-Path $MappedFolder "inner_script.ps1"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage
}

Write-Log "=== Starting Windows Sandbox Escape Test ==="

Write-Log "Checking for process auditing and monitoring tools..."

$sysmonPresent = $false
$auditingEnabled = $false

try {
    $sysmonDriver = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($null -eq $sysmonDriver) {
        $sysmonDriver = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    }
    
    if ($sysmonDriver) {
        $sysmonPresent = $true
        Write-Log "Sysmon is installed and running: $($sysmonDriver.Status)"
    } else {
        Write-Log "WARNING: Sysmon is not installed"
    }
} catch {
    Write-Log "WARNING: Could not detect Sysmon: $_"
}

try {
    $auditPolicy = auditpol /get /subcategory:"Process Creation" /r | Select-String "Process Creation"
    if ($auditPolicy -match "Success") {
        $auditingEnabled = $true
        Write-Log "Process Creation auditing (Event 4688) is enabled"
    } else {
        Write-Log "WARNING: Process Creation auditing (Event 4688) is not enabled"
        Write-Log "Enabling Process Creation auditing..."
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        Write-Log "Process Creation auditing has been enabled"
        $auditingEnabled = $true
    }
} catch {
    Write-Log "WARNING: Could not check or enable process auditing: $_"
}

if (-not $sysmonPresent -and -not $auditingEnabled) {
    Write-Log "CRITICAL: Neither Sysmon nor Process Creation auditing (4688) are available"
    Write-Log "It is highly recommended to install Sysmon or enable process auditing before continuing"
    $continue = Read-Host "Do you want to continue anyway? (yes/no)"
    if ($continue -notlike "y*") {
        Write-Log "Test aborted by user"
        exit 0
    }
}

Write-Log "Checking if Windows Sandbox feature is enabled..."
$sandboxFeature = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM"

if ($sandboxFeature.State -ne "Enabled") {
    Write-Log "Enabling Windows Sandbox feature..."
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -NoRestart -WarningAction SilentlyContinue
        Write-Log "Windows Sandbox feature enabled successfully. Restart may be required."
    } catch {
        Write-Log "Failed to enable Windows Sandbox: $_"
        exit 1
    }
} else {
    Write-Log "Windows Sandbox feature is already enabled."
}

if (-not (Test-Path $BaseFolder)) {
    Write-Log "Creating base folder: $BaseFolder"
    New-Item -ItemType Directory -Path $BaseFolder -Force | Out-Null
} else {
    Write-Log "Base folder already exists: $BaseFolder"
}

if (-not (Test-Path $MappedFolder)) {
    Write-Log "Creating mapped folder: $MappedFolder"
    New-Item -ItemType Directory -Path $MappedFolder -Force | Out-Null
} else {
    Write-Log "Mapped folder already exists: $MappedFolder"
}

Write-Log "Creating inner sandbox script..."

$innerScript = @'
$ErrorActionPreference = "Stop"

$LogFile = "C:\Users\WDAGUtilityAccount\Desktop\SharedFolder\sandbox_log.txt"
$OutputFolder = "C:\Users\WDAGUtilityAccount\Desktop\SharedFolder"

function Write-SandboxLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - [SANDBOX] $Message"
    Add-Content -Path $LogFile -Value $logMessage
}

Write-SandboxLog "=== Sandbox inner script started ==="

Write-SandboxLog "Creating C# DNS lookup binary..."

$csharpCode = @"
using System;
using System.Net;

namespace SandboxTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string domain = "example.com";
            if (args.Length > 0)
            {
                domain = args[0];
            }
            
            Console.WriteLine(String.Format("Looking up domain: {0}", domain));
            
            try
            {
                IPHostEntry hostEntry = Dns.GetHostEntry(domain);
                Console.WriteLine(String.Format("Resolved {0} to:", domain));
                foreach (IPAddress addr in hostEntry.AddressList)
                {
                    Console.WriteLine(String.Format("  {0}", addr.ToString()));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("Error: {0}", ex.Message));
            }
        }
    }
}
"@

$csharpPath = Join-Path $OutputFolder "DNSLookup.cs"
$exePath = Join-Path $OutputFolder "DNSLookup.exe"

Set-Content -Path $csharpPath -Value $csharpCode
Write-SandboxLog "C# source code written to: $csharpPath"

try {
    $cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (-not (Test-Path $cscPath)) {
        $cscPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    }
    
    & $cscPath /out:$exePath $csharpPath 2>&1 | Out-Null
    Write-SandboxLog "Binary compiled successfully: $exePath"
} catch {
    Write-SandboxLog "Failed to compile binary: $_"
}

Write-SandboxLog "Creating scheduled task XML for WSB escape..."

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-08T12:00:00</Date>
    <Author>WSBShenanigans</Author>
    <Description>Sandbox escape test task</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c echo Sandbox escape task executed</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$taskXmlPath = Join-Path $OutputFolder "WSBEscapeTask.xml"
Set-Content -Path $taskXmlPath -Value $taskXml
Write-SandboxLog "Scheduled task XML created: $taskXmlPath"

Write-SandboxLog "Creating user account WSBShenanigans..."

try {
    $username = "WSBShenanigans"
    $password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    
    $userExists = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    if (-not $userExists) {
        New-LocalUser -Name $username -Password $password -Description "Sandbox test user account" -PasswordNeverExpires -UserMayNotChangePassword
        Write-SandboxLog "User account created: $username"
    } else {
        Write-SandboxLog "User account already exists: $username"
    }
} catch {
    Write-SandboxLog "Failed to create user account: $_"
}

Write-SandboxLog "Testing DNS lookup binary..."
try {
    if (Test-Path $exePath) {
        $result = & $exePath "google.com" 2>&1
        $result | ForEach-Object { Write-SandboxLog "DNS Output: $_" }
    }
} catch {
    Write-SandboxLog "Failed to test DNS lookup: $_"
}

Write-SandboxLog "=== Sandbox inner script completed ==="
'@

Set-Content -Path $InnerScriptPath -Value $innerScript
Write-Log "Inner script created: $InnerScriptPath"

Write-Log "Creating Windows Sandbox configuration file..."

$wsbConfig = @"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$MappedFolder</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\SharedFolder</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\SharedFolder\inner_script.ps1</Command>
  </LogonCommand>
  <Networking>Enable</Networking>
  <vGPU>Enable</vGPU>
  <AudioInput>Enable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Disable</ProtectedClient>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Enable</ClipboardRedirection>
  <MemoryInMB>4096</MemoryInMB>
</Configuration>
"@

Set-Content -Path $ConfigFile -Value $wsbConfig
Write-Log "Sandbox configuration file created: $ConfigFile"

Write-Log "Launching Windows Sandbox..."
try {
    Start-Process -FilePath "WindowsSandbox.exe" -ArgumentList $ConfigFile
    Write-Log "Windows Sandbox launched successfully"
    Write-Log "Monitor the sandbox activity. Logs will be written to: $MappedFolder\sandbox_log.txt"
} catch {
    Write-Log "Failed to launch Windows Sandbox: $_"
    Write-Log "Ensure Windows Sandbox is enabled and the system has been restarted if needed"
}

Write-Log "=== Test initialization complete ==="
Write-Log "Check the following locations for results:"
Write-Log "  - Host log: $LogFile"
Write-Log "  - Sandbox log: $MappedFolder\sandbox_log.txt"
Write-Log "  - DNS binary: $MappedFolder\DNSLookup.exe"
Write-Log "  - Task XML: $MappedFolder\WSBEscapeTask.xml"
