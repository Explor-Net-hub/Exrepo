# ===== Ultimate System Explorer v7.0 =====
# PowerShell 5.1+ | Administrator Required
# Complete System Diagnostics with Advanced Software Analysis

# ---------- COMPATIBLE ADMIN ELEVATION ----------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $psPath = if ($PSVersionTable.PSVersion.Major -ge 6) { "pwsh" } else { "powershell.exe" }
    Start-Process $psPath "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ---------- OUTPUT SETUP ----------
$outputFile = "$env:USERPROFILE\Desktop\System_Explorer_Report.txt"
if (Test-Path $outputFile) { Remove-Item $outputFile -Force -ErrorAction SilentlyContinue }

# ---------- REPORT HEADER ----------
$datetime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$username = $env:USERNAME
Add-Content -Path $outputFile -Value "===== ENTERPRISE SYSTEM REPORT ====="
Add-Content -Path $outputFile -Value "Generated: $datetime | User: $username"
Add-Content -Path $outputFile -Value "OS: $([System.Environment]::OSVersion.Version)"
Add-Content -Path $outputFile -Value "PowerShell: $($PSVersionTable.PSVersion)`n"

# ---------- SYSTEM INFORMATION ----------
Add-Content -Path $outputFile -Value "`n===== SYSTEM INFORMATION ====="
try {
    $sysInfo = Get-ComputerInfo | Select-Object CsName, OsName, OsArchitecture, WindowsProductName, WindowsVersion, CsNumberOfLogicalProcessors, CsTotalPhysicalMemory
    $sysInfo | Format-List | Out-String -Width 150 | Add-Content -Path $outputFile
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] System info: $($_.Exception.Message)"
}

# ---------- UPTIME & BOOT INFO ----------
Add-Content -Path $outputFile -Value "`n===== SYSTEM UPTIME ====="
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $lastBoot = $osInfo.LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    $uptimeString = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    Add-Content -Path $outputFile -Value "Last Boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss'))"
    Add-Content -Path $outputFile -Value "Uptime: $uptimeString"
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] Uptime check: $($_.Exception.Message)"
}

# ---------- MEMORY USAGE ----------
Add-Content -Path $outputFile -Value "`n===== MEMORY USAGE ====="
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $totalKB = $os.TotalVisibleMemorySize
    $freeKB = $os.FreePhysicalMemory
    $usedKB = $totalKB - $freeKB
    
    $totalGB = [math]::Round($totalKB / (1024 * 1024), 2)
    $usedGB = [math]::Round($usedKB / (1024 * 1024), 2)
    $usedPercent = [math]::Round(($usedKB / $totalKB) * 100, 2)
    
    Add-Content -Path $outputFile -Value "Total RAM: $totalGB GB"
    Add-Content -Path $outputFile -Value "Used RAM: $usedGB GB ($usedPercent%)"
    Add-Content -Path $outputFile -Value "Status: $(if ($usedPercent -gt 85) {'🔴 High'} else {'✅ Normal'})"
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] Memory calculation: $($_.Exception.Message)"
}

# ---------- ADVANCED INSTALLED SOFTWARE ANALYSIS (WITH INSTALL PATH) ----------
Add-Content -Path $outputFile -Value "`n===== INSTALLED SOFTWARE ANALYSIS ====="
try {
    # Traditional Win32 apps with deep sleep detection
    $paths = @(
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $win32Apps = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | 
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,
            @{Name = "InstallPath"; Expression = {
                if ($_.InstallLocation) { $_.InstallLocation }
                elseif ($_.UninstallString) { ($_.UninstallString -split '"')[1] | Split-Path -Parent }
                else { "Not Available" }
            }},
            @{Name = "Status"; Expression = {
                if ($_.InstallDate) {
                    $installDate = try { [DateTime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null) } 
                    catch { $null }
                    if ($installDate -and $installDate -lt (Get-Date).AddMonths(-6)) {
                        "💤 Deep Sleep"
                    } else {
                        "✅ Active"
                    }
                } else {
                    "❓ Unknown"
                }
            }} |
        Sort-Object DisplayName

    # UWP apps
    $uwpApps = Get-AppxPackage | 
        Select-Object @{Name = "DisplayName"; Expression = { $_.Name }}, 
                      @{Name = "DisplayVersion"; Expression = { $_.Version }}, 
                      Publisher,
                      @{Name = "InstallDate"; Expression = { $_.InstallTime }},
                      @{Name = "InstallPath"; Expression = { $_.InstallLocation }},
                      @{Name = "Status"; Expression = {
                          if ($_.InstallTime -and $_.InstallTime -lt (Get-Date).AddMonths(-6)) {
                              "💤 Deep Sleep"
                          } else {
                              "✅ Active"
                          }
                      }} |
        Sort-Object DisplayName

    # Combine and output
    $allApps = $win32Apps + $uwpApps | Sort-Object DisplayName -Unique
    $totalApps = $allApps.Count
    
    Add-Content -Path $outputFile -Value "`nTotal Installed Applications: $totalApps"
    Add-Content -Path $outputFile -Value "Deep Sleep Apps: $(($allApps | Where-Object { $_.Status -eq '💤 Deep Sleep' }).Count)"
    Add-Content -Path $outputFile -Value "Active Apps: $(($allApps | Where-Object { $_.Status -eq '✅ Active' }).Count)"
    
    # Show all apps with status and install path
    Add-Content -Path $outputFile -Value "`nAll Applications (Status: 💤 Deep Sleep = Not used in 6+ months):"
    $allApps | Select-Object DisplayName, DisplayVersion, Status, InstallPath | 
        Format-Table -AutoSize -Wrap | 
        Out-String -Width 200 | 
        Add-Content -Path $outputFile
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] Software analysis: $($_.Exception.Message)"
}

# ---------- NETWORK STATUS ----------
Add-Content -Path $outputFile -Value "`n===== NETWORK STATUS ====="
try {
    # Basic network config
    $ipConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer
    $dnsConfig = Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
    
    Add-Content -Path $outputFile -Value "IP Configuration:"
    $ipConfig | Format-List | Out-String -Width 150 | Add-Content -Path $outputFile
    
    Add-Content -Path $outputFile -Value "DNS Servers:"
    $dnsConfig | Format-List | Out-String -Width 150 | Add-Content -Path $outputFile
    
    # Internet connectivity test
    $testSites = @("google.com", "microsoft.com", "cloudflare.com")
    $internetStatus = $false
    
    foreach ($site in $testSites) {
        try {
            if (Test-Connection -ComputerName $site -Count 1 -Quiet -ErrorAction Stop) {
                $internetStatus = $true
                break
            }
        } catch {}
    }
    
    Add-Content -Path $outputFile -Value "Internet Connectivity: $(if ($internetStatus) {'✅ Connected'} else {'🔴 Disconnected'})"
    
    # Gateway and routing
    $gateways = Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | 
                Select-Object InterfaceAlias, NextHop
    Add-Content -Path $outputFile -Value "`nNetwork Gateways:"
    $gateways | Format-Table -AutoSize | Out-String -Width 150 | Add-Content -Path $outputFile
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] Network status: $($_.Exception.Message)"
}

# ---------- SYSTEM HEALTH EVALUATION ----------
Add-Content -Path $outputFile -Value "`n===== SYSTEM HEALTH EVALUATION ====="
try {
    # Ensure $usedPercent is defined
    if (-not (Get-Variable -Name "usedPercent" -ErrorAction SilentlyContinue)) {
        $os = Get-CimInstance Win32_OperatingSystem
        $totalKB = $os.TotalVisibleMemorySize
        $freeKB = $os.FreePhysicalMemory
        $usedPercent = [math]::Round((($totalKB - $freeKB) / $totalKB) * 100, 2)
    }

    # CPU Load
    $cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    
    # Disk Health
    $diskHealth = Get-PhysicalDisk | Select-Object DeviceID, HealthStatus
    
    # Service Status
    $criticalServices = Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } |
                        Select-Object Name, DisplayName, Status
    
    # Health Summary
    $issues = @()
    if ($cpuLoad -gt 80) { $issues += "High CPU usage detected ($cpuLoad%) - consider process optimization" }
    if ($usedPercent -gt 85) { $issues += "High RAM usage ($usedPercent%) - consider adding more memory" }
    if ($diskHealth.HealthStatus -contains "Unhealthy") { $issues += "Unhealthy disk detected - immediate backup recommended" }
    if ($criticalServices) { $issues += "Critical services not running: $($criticalServices.Count)" }
    
    if ($issues.Count -eq 0) {
        Add-Content -Path $outputFile -Value "System Health: ✅ Optimal"
    } else {
        Add-Content -Path $outputFile -Value "System Health: ⚠️ Needs Attention"
        $issues | ForEach-Object { Add-Content -Path $outputFile -Value " • $_" }
        
        if ($criticalServices) {
            Add-Content -Path $outputFile -Value "`nStopped Critical Services:"
            $criticalServices | Format-Table -AutoSize | Out-String -Width 150 | Add-Content -Path $outputFile
        }
    }
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] Health evaluation: $($_.Exception.Message)"
}

# ---------- SECURITY STATUS ----------
Add-Content -Path $outputFile -Value "`n===== SECURITY STATUS ====="
try {
    $avStatus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    if ($avStatus) {
        Add-Content -Path $outputFile -Value "Antivirus Protection: ✅ Enabled"
        $avStatus | ForEach-Object { Add-Content -Path $outputFile -Value " • $($_.displayName)" }
    } else {
        Add-Content -Path $outputFile -Value "Antivirus Protection: 🔴 Not Detected"
    }
    
    $firewallStatus = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq "True" }
    Add-Content -Path $outputFile -Value "Firewall Status: $(if ($firewallStatus) {'✅ Enabled'} else {'🔴 Disabled'})"
    
    # Windows Update Status
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $pendingCount = $updateSearcher.Search("IsInstalled=0").Updates.Count
    Add-Content -Path $outputFile -Value "Windows Updates: $(if ($pendingCount -eq 0) {'✅ Up-to-date'} else {'⚠️ $pendingCount updates pending'})"
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] Security status: $($_.Exception.Message)"
}

# ---------- CRITICAL EVENTS ----------
Add-Content -Path $outputFile -Value "`n===== CRITICAL EVENTS (Last 24h) ====="
try {
    $events = Get-WinEvent -LogName System -MaxEvents 20 -ErrorAction SilentlyContinue |
              Where-Object { $_.Level -in (1, 2) -and $_.TimeCreated -gt (Get-Date).AddHours(-24) }
    
    if ($events) {
        $events | Select-Object TimeCreated, Id, ProviderName, Message | 
        Format-Table -AutoSize | Out-String -Width 150 | Add-Content -Path $outputFile
    } else {
        Add-Content -Path $outputFile -Value "✅ No critical events found"
    }
}
catch {
    Add-Content -Path $outputFile -Value "[ERROR] Event logs: $($_.Exception.Message)"
}

# ---------- REPORT SUMMARY ----------
Add-Content -Path $outputFile -Value "`n===== REPORT SUMMARY ====="
Add-Content -Path $outputFile -Value "Report generated in: $((Get-Date) - [datetime]$datetime | Select-Object -ExpandProperty TotalSeconds | ForEach-Object { [math]::Round($_, 1) }) seconds"
Add-Content -Path $outputFile -Value "Total checks performed: 8"
Add-Content -Path $outputFile -Value "Errors encountered: $($Error.Count)"
Add-Content -Path $outputFile -Value "Deep Sleep Apps: $(($allApps | Where-Object { $_.Status -eq '💤 Deep Sleep' }).Count)"
Add-Content -Path $outputFile -Value "`n===== END OF REPORT ====="

# Open report
if (Test-Path $outputFile) {
    Start-Process notepad.exe $outputFile
}