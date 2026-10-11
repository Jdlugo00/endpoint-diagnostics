# Endpoint Diagnostics

A PowerShell tool that checks the health of a Windows endpoint and produces a color-coded HTML report. One command replaces the first 10 to 15 minutes of a typical support ticket: checking disk space, uptime, pending reboots, network, security status, and recent errors by hand.

## The problem

Most desktop support tickets start the same way. Before you can fix anything, you have to answer basic questions: When did this machine last reboot? Is the disk full? Is a reboot pending? Can it reach the gateway and resolve DNS? Is Defender running? What errors has it logged?

Answering those means opening five or six different tools. This script runs every check at once, grades each one, and puts the problems at the top of a single report you can read in seconds or attach to a ticket.

## What it checks

| Area | Checks | Graded as |
|---|---|---|
| System | Model, serial, OS build, uptime, CPU, RAM | WARN if uptime over 14 days or RAM under 10% free |
| Disks | Free space per drive, physical disk health | WARN under 15% free, FAIL under 5% or unhealthy disk |
| Pending reboot | Component Based Servicing, Windows Update, pending file renames | WARN if any are set |
| Network | Active adapters, IP, gateway, DNS servers, gateway ping, DNS lookup | FAIL if no gateway or DNS fails |
| Security | Defender real-time protection and signature age, firewall profiles, BitLocker, last update installed | FAIL if real-time protection is off, WARN for stale signatures, disabled firewall, BitLocker off, or no update in 45 days |
| Services | Auto-start services that are not running | WARN if any stopped with a non-zero exit code |
| Event log | Critical and error events from System and Application logs | WARN if any critical events |
| Applications (optional) | Installed programs (machine and current user), with `-IncludeApps` | Listed for reference |

Every result is graded **OK**, **WARN**, **FAIL**, or **INFO**, and the summary table sorts failures to the top.

## Usage

Requires Windows 10 or 11 with Windows PowerShell 5.1 or PowerShell 7. No modules to install. Runs as a standard user; run as administrator to include the BitLocker check.

**Option 1: Paste into PowerShell (no execution policy changes needed)**

1. Open `Get-EndpointDiagnostics.ps1`, copy the entire contents, and paste them into a PowerShell window. This loads the function.
2. Run it:

```powershell
Get-EndpointDiagnostics
```

**Option 2: Dot-source the file**

```powershell
. .\Get-EndpointDiagnostics.ps1
Get-EndpointDiagnostics
```

### Options

```powershell
# Save the report somewhere else and include 7 days of events
Get-EndpointDiagnostics -OutputPath C:\Temp -EventDays 7

# Add the installed applications list
Get-EndpointDiagnostics -IncludeApps

# Don't open the report automatically
Get-EndpointDiagnostics -NoOpen

# Return the data as an object for further scripting
$result = Get-EndpointDiagnostics -PassThru -NoOpen
$result.Findings | Where-Object Status -eq 'FAIL'
```

| Parameter | Default | Description |
|---|---|---|
| `-OutputPath` | Desktop | Folder for the HTML report |
| `-EventDays` | 3 | Days of event history to include (1 to 30) |
| `-MaxEvents` | 25 | Maximum events to include (1 to 200) |
| `-IncludeApps` | off | Add the installed applications list to the report |
| `-NoOpen` | off | Don't open the report when finished |
| `-PassThru` | off | Also return the collected data as an object |

The report is saved as `EndpointDiag_<COMPUTERNAME>_<timestamp>.html`, and the summary prints to the console.

## Design decisions

**Built-in cmdlets only.** Everything uses CIM, the registry, and modules that ship with Windows. Nothing to install, so it works on a locked-down machine or a fresh image.

**Runs without admin.** Most support starts in the user's session. Checks that need elevation are marked INFO with a note instead of failing the whole run.

**One check failing doesn't stop the rest.** Each section is wrapped so a missing cmdlet or access error becomes an INFO line. A machine with third-party antivirus, for example, still gets a full report.

**Problems first.** The summary sorts FAIL, then WARN, then INFO, then OK, so the first thing you read is what needs attention.

**Installed apps are opt-in.** The application list doesn't tell you whether a machine is healthy, it makes the report several times longer, and it's the most sensitive part to share. It's off by default and added with `-IncludeApps` for the tickets that need it: version conflicts, confirming a software deployment landed, or checking for unapproved software.

**Paste-friendly.** The whole tool is a single function with spaces instead of tabs, so it can be pasted into a console on machines where running scripts is blocked by execution policy.

**Reduced false positives.** Many auto-start services are normally stopped (trigger-start services that exit cleanly). The script lists them all but only warns about ones that stopped with an error code. Gateway ping failures are WARN rather than FAIL because some networks block ICMP.

## Privacy note

Reports contain the computer name, serial number, logged-on username, and IP and MAC addresses, plus the installed software list when `-IncludeApps` is used. Treat them as internal data. The `.gitignore` in this repo excludes report files so they are never committed by accident.

## Roadmap

- Run against a remote computer with `-ComputerName`
- Export findings to CSV for tracking multiple machines
- Optional checks for Outlook profile size and OneDrive sync status
- Pester tests for the grading logic

## License

MIT
