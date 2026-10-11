function Get-EndpointDiagnostics {
    <#
    .SYNOPSIS
        Collects health and configuration data from a Windows endpoint and writes an HTML report.

    .DESCRIPTION
        Gathers system info, disk space and health, pending reboot status, network config and
        connectivity, security status, recent critical/error events, stopped auto-start services,
        and installed applications. Each check is graded OK / WARN / FAIL / INFO and summarized
        at the top of the report.

        Runs without admin rights. A few checks (BitLocker) need an elevated session and are
        marked INFO when skipped.

    .PARAMETER OutputPath
        Folder for the HTML report. Defaults to the current user's Desktop.

    .PARAMETER EventDays
        How many days of System and Application error events to include. Default 3.

    .PARAMETER MaxEvents
        Maximum number of events to include. Default 25.

    .PARAMETER IncludeApps
        Add the installed applications list to the report. Off by default to keep the report
        focused on health checks.

    .PARAMETER NoOpen
        Do not open the report in the browser when finished.

    .PARAMETER PassThru
        Return the collected data as an object in addition to writing the report.

    .EXAMPLE
        Get-EndpointDiagnostics

    .EXAMPLE
        Get-EndpointDiagnostics -OutputPath C:\Temp -EventDays 7 -NoOpen

    .EXAMPLE
        Get-EndpointDiagnostics -IncludeApps
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),
        [ValidateRange(1, 30)][int]$EventDays = 3,
        [ValidateRange(1, 200)][int]$MaxEvents = 25,
        [switch]$IncludeApps,
        [switch]$NoOpen,
        [switch]$PassThru
    )

    $findings = New-Object System.Collections.Generic.List[object]
    function Add-Finding {
        param([string]$Check, [string]$Status, [string]$Detail)
        $findings.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin  = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # ---------- System ----------
    Write-Host '[*] Collecting system info...'
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $uptime     = (Get-Date) - $os.LastBootUpTime
    $ramTotalGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $ramFreeGB  = [math]::Round(($os.FreePhysicalMemory * 1KB) / 1GB, 1)

    $system = [pscustomobject][ordered]@{
        'Computer name'    = $env:COMPUTERNAME
        'Manufacturer'     = $cs.Manufacturer
        'Model'            = $cs.Model
        'Serial number'    = $bios.SerialNumber
        'OS'               = $os.Caption
        'Version'          = "$($cv.DisplayVersion) (build $($os.BuildNumber).$($cv.UBR))"
        'Install date'     = $os.InstallDate
        'Last boot'        = $os.LastBootUpTime
        'Uptime'           = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        'CPU'              = $cpu.Name.Trim()
        'Cores / threads'  = "$($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors)"
        'RAM total (GB)'   = $ramTotalGB
        'RAM free (GB)'    = $ramFreeGB
        'Logged-on user'   = $cs.UserName
        'Domain'           = $cs.Domain
        'Running as admin' = $isAdmin
    }

    if ($uptime.TotalDays -gt 14) {
        Add-Finding 'Uptime' 'WARN' "$([math]::Floor($uptime.TotalDays)) days since last reboot"
    } else {
        Add-Finding 'Uptime' 'OK' "$([math]::Floor($uptime.TotalDays)) days since last reboot"
    }

    $ramFreePct = if ($ramTotalGB) { [math]::Round($ramFreeGB / $ramTotalGB * 100, 0) } else { 0 }
    if ($ramFreePct -lt 10) {
        Add-Finding 'Memory' 'WARN' "$ramFreePct% free ($ramFreeGB of $ramTotalGB GB)"
    } else {
        Add-Finding 'Memory' 'OK' "$ramFreePct% free ($ramFreeGB of $ramTotalGB GB)"
    }

    # ---------- Disks ----------
    Write-Host '[*] Checking disks...'
    $disks = foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
        $pct = if ($d.Size) { [math]::Round($d.FreeSpace / $d.Size * 100, 1) } else { 0 }
        $status = if ($pct -lt 5) { 'FAIL' } elseif ($pct -lt 15) { 'WARN' } else { 'OK' }
        Add-Finding "Free space $($d.DeviceID)" $status "$pct% free"
        [pscustomobject][ordered]@{
            'Drive'     = $d.DeviceID
            'Label'     = $d.VolumeName
            'Size (GB)' = [math]::Round($d.Size / 1GB, 1)
            'Free (GB)' = [math]::Round($d.FreeSpace / 1GB, 1)
            'Free %'    = $pct
            'Status'    = $status
        }
    }

    $physical = $null
    try {
        $physical = foreach ($p in (Get-PhysicalDisk -ErrorAction Stop)) {
            $status = if ("$($p.HealthStatus)" -eq 'Healthy') { 'OK' } else { 'FAIL' }
            Add-Finding "Disk health: $($p.FriendlyName)" $status "$($p.HealthStatus)"
            [pscustomobject][ordered]@{
                'Disk'        = $p.FriendlyName
                'Media'       = "$($p.MediaType)"
                'Bus'         = "$($p.BusType)"
                'Size (GB)'   = [math]::Round($p.Size / 1GB, 0)
                'Health'      = "$($p.HealthStatus)"
                'Operational' = ($p.OperationalStatus -join ', ')
                'Status'      = $status
            }
        }
    } catch {
        Add-Finding 'Disk health' 'INFO' 'Could not query physical disks'
    }

    # ---------- Pending reboot ----------
    Write-Host '[*] Checking for pending reboot...'
    $rebootReasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $rebootReasons += 'Component Based Servicing'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $rebootReasons += 'Windows Update'
    }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $rebootReasons += 'Pending file rename operations' }

    if ($rebootReasons) {
        Add-Finding 'Pending reboot' 'WARN' ($rebootReasons -join ', ')
    } else {
        Add-Finding 'Pending reboot' 'OK' 'None detected'
    }

    # ---------- Network ----------
    Write-Host '[*] Checking network...'
    $network = $null
    $netcfg  = $null
    try {
        $netcfg = Get-NetIPConfiguration -ErrorAction Stop |
            Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' }
        $network = foreach ($n in $netcfg) {
            [pscustomobject][ordered]@{
                'Adapter'     = $n.InterfaceAlias
                'Description' = $n.InterfaceDescription
                'IPv4'        = ($n.IPv4Address.IPAddress -join ', ')
                'Gateway'     = ($n.IPv4DefaultGateway.NextHop -join ', ')
                'DNS servers' = (($n.DNSServer | Where-Object { $_.AddressFamily -eq 2 }).ServerAddresses -join ', ')
                'MAC'         = $n.NetAdapter.MacAddress
                'Link speed'  = $n.NetAdapter.LinkSpeed
            }
        }
    } catch {
        Add-Finding 'Network config' 'INFO' 'Could not read IP configuration'
    }

    if (-not $network) {
        Add-Finding 'Network' 'FAIL' 'No active adapter with a default gateway'
    } else {
        $gateway = @(@($netcfg)[0].IPv4DefaultGateway.NextHop)[0]
        if (Test-Connection -ComputerName $gateway -Count 2 -Quiet -ErrorAction SilentlyContinue) {
            Add-Finding 'Gateway ping' 'OK' "$gateway responded"
        } else {
            Add-Finding 'Gateway ping' 'WARN' "$gateway did not respond (may block ICMP)"
        }
    }

    try {
        $null = Resolve-DnsName -Name 'www.microsoft.com' -QuickTimeout -ErrorAction Stop
        Add-Finding 'DNS resolution' 'OK' 'Resolved www.microsoft.com'
    } catch {
        Add-Finding 'DNS resolution' 'FAIL' 'Could not resolve www.microsoft.com'
    }

    # ---------- Security ----------
    Write-Host '[*] Checking security status...'
    $security = New-Object System.Collections.Generic.List[object]

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $sigAge = [math]::Floor(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays)
        $security.Add([pscustomobject]@{ Setting = 'Defender real-time protection'; Value = $mp.RealTimeProtectionEnabled })
        $security.Add([pscustomobject]@{ Setting = 'Defender signatures updated'; Value = "$($mp.AntivirusSignatureLastUpdated) ($sigAge days ago)" })
        if ($mp.RealTimeProtectionEnabled) {
            Add-Finding 'Defender real-time protection' 'OK' 'Enabled'
        } else {
            Add-Finding 'Defender real-time protection' 'FAIL' 'Disabled (check for third-party AV)'
        }
        if ($sigAge -gt 3) {
            Add-Finding 'Defender signatures' 'WARN' "$sigAge days old"
        } else {
            Add-Finding 'Defender signatures' 'OK' "$sigAge days old"
        }
    } catch {
        Add-Finding 'Defender' 'INFO' 'Status unavailable (third-party AV or no access)'
    }

    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($f in $fw) {
            $security.Add([pscustomobject]@{ Setting = "Firewall: $($f.Name)"; Value = $f.Enabled })
        }
        $fwOff = @($fw | Where-Object { -not $_.Enabled })
        if ($fwOff.Count -gt 0) {
            Add-Finding 'Firewall' 'WARN' "Disabled on: $(($fwOff.Name) -join ', ')"
        } else {
            Add-Finding 'Firewall' 'OK' 'Enabled on all profiles'
        }
    } catch {
        Add-Finding 'Firewall' 'INFO' 'Could not read firewall profiles'
    }

    if ($isAdmin) {
        try {
            $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            $security.Add([pscustomobject]@{ Setting = "BitLocker $env:SystemDrive"; Value = "$($bl.ProtectionStatus) ($($bl.VolumeStatus))" })
            if ("$($bl.ProtectionStatus)" -eq 'On') {
                Add-Finding 'BitLocker' 'OK' 'Protection on'
            } else {
                Add-Finding 'BitLocker' 'WARN' "Protection $($bl.ProtectionStatus)"
            }
        } catch {
            Add-Finding 'BitLocker' 'INFO' 'Could not query BitLocker'
        }
    } else {
        Add-Finding 'BitLocker' 'INFO' 'Skipped (requires admin)'
    }

    try {
        $lastPatch = Get-HotFix -ErrorAction Stop |
            Where-Object { $_.InstalledOn } |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1
        if ($lastPatch) {
            $patchAge = [math]::Floor(((Get-Date) - $lastPatch.InstalledOn).TotalDays)
            $security.Add([pscustomobject]@{ Setting = 'Last update installed'; Value = "$($lastPatch.HotFixID) on $($lastPatch.InstalledOn.ToString('yyyy-MM-dd')) ($patchAge days ago)" })
            if ($patchAge -gt 45) {
                Add-Finding 'Windows updates' 'WARN' "Last update $patchAge days ago"
            } else {
                Add-Finding 'Windows updates' 'OK' "Last update $patchAge days ago"
            }
        }
    } catch {
        Add-Finding 'Windows updates' 'INFO' 'Could not read update history'
    }

    # ---------- Services ----------
    Write-Host '[*] Checking services...'
    $services = Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" |
        Sort-Object DisplayName |
        Select-Object @{ n = 'Name'; e = { $_.Name } },
                      @{ n = 'Display name'; e = { $_.DisplayName } },
                      @{ n = 'State'; e = { $_.State } },
                      @{ n = 'Exit code'; e = { $_.ExitCode } }

    $failedSvc = @($services | Where-Object { $_.'Exit code' -ne 0 })
    if ($failedSvc.Count -gt 0) {
        Add-Finding 'Auto-start services' 'WARN' "$($failedSvc.Count) stopped with a non-zero exit code"
    } else {
        Add-Finding 'Auto-start services' 'OK' 'No failed auto-start services'
    }

    # ---------- Events ----------
    Write-Host "[*] Reading error events from the last $EventDays day(s)..."
    $events = @()
    try {
        $filter = @{ LogName = 'System', 'Application'; Level = 1, 2; StartTime = (Get-Date).AddDays(-$EventDays) }
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop |
            Select-Object @{ n = 'Time'; e = { $_.TimeCreated } },
                          @{ n = 'Log'; e = { $_.LogName } },
                          @{ n = 'Level'; e = { $_.LevelDisplayName } },
                          @{ n = 'Source'; e = { $_.ProviderName } },
                          @{ n = 'Event ID'; e = { $_.Id } },
                          @{ n = 'Message'; e = {
                              $m = "$($_.Message)" -split "`r?`n" | Select-Object -First 1
                              if ($m.Length -gt 200) { $m.Substring(0, 200) + '...' } else { $m }
                          } })
    } catch {
        # Get-WinEvent throws when no events match; treat as none found.
    }

    $critical = @($events | Where-Object { $_.Level -eq 'Critical' })
    if ($critical.Count -gt 0) {
        Add-Finding 'Event log' 'WARN' "$($critical.Count) critical and $($events.Count - $critical.Count) error events in $EventDays day(s)"
    } else {
        Add-Finding 'Event log' 'INFO' "$($events.Count) error events in $EventDays day(s)"
    }

    # ---------- Installed apps (optional) ----------
    $apps = $null
    if ($IncludeApps) {
        Write-Host '[*] Listing installed applications...'
        $uninstallKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $apps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
            Select-Object @{ n = 'Name'; e = { $_.DisplayName } },
                          @{ n = 'Version'; e = { $_.DisplayVersion } },
                          @{ n = 'Publisher'; e = { $_.Publisher } },
                          @{ n = 'Installed'; e = { $_.InstallDate } } |
            Sort-Object Name -Unique

        Add-Finding 'Installed applications' 'INFO' "$(@($apps).Count) found"
    }

    # ---------- Report ----------
    Write-Host '[*] Building report...'
    $order = @{ FAIL = 0; WARN = 1; INFO = 2; OK = 3 }
    $sortedFindings = $findings | Sort-Object { $order[$_.Status] }, Check

    function ConvertTo-Section {
        param([string]$Title, $Data, [switch]$List)
        if (-not $Data) { return "<h2>$Title</h2><p class='none'>None found.</p>" }
        $params = @{ Fragment = $true; PreContent = "<h2>$Title</h2>" }
        if ($List) { $params.As = 'List' }
        return (($Data | ConvertTo-Html @params) -join "`n")
    }

    $css = @(
        '<style>',
        'body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2328; background: #ffffff; }',
        'h1 { font-size: 22px; margin-bottom: 4px; }',
        'h2 { font-size: 16px; margin-top: 28px; border-bottom: 1px solid #d0d7de; padding-bottom: 4px; }',
        'p.meta { color: #656d76; margin-top: 0; }',
        'p.none { color: #656d76; font-style: italic; }',
        'table { border-collapse: collapse; font-size: 13px; width: 100%; }',
        'th, td { border: 1px solid #d0d7de; padding: 4px 8px; text-align: left; vertical-align: top; }',
        'th { background: #f6f8fa; }',
        'td.OK { background: #dafbe1; font-weight: 600; }',
        'td.WARN { background: #fff8c5; font-weight: 600; }',
        'td.FAIL { background: #ffebe9; font-weight: 600; }',
        'td.INFO { background: #ddf4ff; font-weight: 600; }',
        '</style>'
    ) -join "`n"

    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $sections = @(
        "<h1>Endpoint Diagnostics: $env:COMPUTERNAME</h1>",
        "<p class='meta'>Generated $generated by $env:USERNAME. Admin session: $isAdmin.</p>",
        (ConvertTo-Section -Title 'Summary' -Data $sortedFindings),
        (ConvertTo-Section -Title 'System' -Data $system -List),
        (ConvertTo-Section -Title 'Logical disks' -Data $disks),
        (ConvertTo-Section -Title 'Physical disks' -Data $physical),
        (ConvertTo-Section -Title 'Network' -Data $network),
        (ConvertTo-Section -Title 'Security' -Data $security),
        (ConvertTo-Section -Title 'Stopped auto-start services' -Data $services),
        (ConvertTo-Section -Title "Critical and error events (last $EventDays days)" -Data $events)
    )
    if ($IncludeApps) {
        $sections += (ConvertTo-Section -Title 'Installed applications' -Data $apps)
    }
    $body = $sections -join "`n"

    $html = "<!DOCTYPE html>`n<html><head><meta charset='utf-8'><title>Endpoint Diagnostics - $env:COMPUTERNAME</title>`n$css`n</head><body>`n$body`n</body></html>"
    $html = $html -replace '<td>(OK|WARN|FAIL|INFO)</td>', '<td class="$1">$1</td>'

    if (-not (Test-Path $OutputPath)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force
    }
    $stamp      = Get-Date -Format 'yyyyMMdd_HHmm'
    $reportFile = Join-Path $OutputPath "EndpointDiag_$($env:COMPUTERNAME)_$stamp.html"
    Set-Content -Path $reportFile -Value $html -Encoding UTF8

    $sortedFindings | Format-Table -AutoSize | Out-Host
    Write-Host "[+] Report saved to $reportFile" -ForegroundColor Green

    if (-not $NoOpen) { Invoke-Item $reportFile }

    if ($PassThru) {
        [pscustomobject]@{
            Findings   = $sortedFindings
            System     = $system
            Disks      = $disks
            Physical   = $physical
            Network    = $network
            Security   = $security
            Services   = $services
            Events     = $events
            Apps       = $apps
            ReportPath = $reportFile
        }
    }
}
