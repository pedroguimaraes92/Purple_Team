#requires -Version 5.1
<#
.SYNOPSIS
  Windows Incident Diagnosis / Forensic Triage Script

.DESCRIPTION
  Coleta artefatos úteis para resposta a incidentes e investigação inicial em hosts Windows.
  Foco em alterações de estado e evidências em:
    - sistema e contexto
    - processos, árvore, command line, modules
    - rede, conexões, DNS cache, ARP, rotas, listeners
    - serviços, drivers, tarefas agendadas
    - contas locais, grupos, logons recentes
    - persistência (Run keys, Startup, WMI, AppInit, IFEO, Winlogon, services)
    - arquivos recentes em locais críticos
    - logs do Windows (Security, System, PowerShell, Defender, TaskScheduler, Sysmon se existir)
    - artefatos auxiliares como Prefetch e PowerShell history

  O script é predominantemente read-only.
  Alguns comandos podem exigir execução como Administrador.

.PARAMETER OutDir
  Diretório base de saída. Se omitido, cria pasta no diretório atual.

.PARAMETER DaysBack
  Quantos dias para trás considerar em vários eventos e arquivos recentes.

.PARAMETER MaxFileScan
  Quantidade máxima de arquivos por diretório no modo de triagem de mudanças recentes.

.PARAMETER NoHash
  Desabilita cálculo de hash SHA256 de arquivos recentes.

.EXAMPLE
  powershell.exe -ExecutionPolicy Bypass -File .\windows_incident_diagnosis.ps1

.EXAMPLE
  .\windows_incident_diagnosis.ps1 -OutDir C:\IR -DaysBack 14 -MaxFileScan 300

.NOTES
  Ideal executar como Administrador.
#>

[CmdletBinding()]
param(
    [string]$OutDir = "",
    [int]$DaysBack = 14,
    [int]$MaxFileScan = 400,
    [switch]$NoHash
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Globals
# ------------------------------------------------------------
$script:StartTs     = Get-Date
$script:StartTsUtc  = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$script:HostName    = $env:COMPUTERNAME
$script:DomainName  = try { [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name } catch { $env:USERDOMAIN }
$script:BaseOutDir  = if ([string]::IsNullOrWhiteSpace($OutDir)) {
    Join-Path -Path (Get-Location) -ChildPath ("windows_ir_{0}_{1}" -f $script:HostName, $script:StartTsUtc)
} else {
    Join-Path -Path $OutDir -ChildPath ("windows_ir_{0}_{1}" -f $script:HostName, $script:StartTsUtc)
}
$script:EvidenceDir = Join-Path $script:BaseOutDir 'evidence'
$script:ReportsDir  = Join-Path $script:BaseOutDir 'reports'
$script:LogsDir     = Join-Path $script:BaseOutDir 'logs'
$script:TimelineDir = Join-Path $script:BaseOutDir 'timeline'
$script:Summary     = New-Object System.Collections.Generic.List[object]
$script:Findings    = New-Object System.Collections.Generic.List[object]
$script:Timeline    = New-Object System.Collections.Generic.List[object]

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
function New-OutputStructure {
    foreach ($dir in @($script:BaseOutDir, $script:EvidenceDir, $script:ReportsDir, $script:LogsDir, $script:TimelineDir)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')]
        [string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    $logFile = Join-Path $script:LogsDir 'execution.log'
    Add-Content -LiteralPath $logFile -Value $line
    Write-Host $line
}

function Safe-Run {
    param(
        [string]$Name,
        [scriptblock]$ScriptBlock,
        [string]$OutFile = "",
        [switch]$Json,
        [switch]$Csv
    )
    try {
        Write-Log "Running: $Name"
        $result = & $ScriptBlock

        if ($OutFile) {
            $full = Join-Path $script:EvidenceDir $OutFile
            if ($Json) {
                $result | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $full -Encoding UTF8
            } elseif ($Csv) {
                $result | Export-Csv -LiteralPath $full -NoTypeInformation -Encoding UTF8
            } else {
                $result | Out-File -LiteralPath $full -Encoding UTF8 -Width 4096
            }
        }

        $script:Summary.Add([pscustomobject]@{
            Name   = $Name
            Status = 'OK'
            Output = $OutFile
        }) | Out-Null

        return $result
    }
    catch {
        $msg = $_.Exception.Message
        Write-Log "Failed: $Name :: $msg" 'WARN'
        $script:Summary.Add([pscustomobject]@{
            Name   = $Name
            Status = 'FAILED'
            Output = $msg
        }) | Out-Null
        return $null
    }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Title,
        [string]$Details
    )
    $script:Findings.Add([pscustomobject]@{
        TimeUtc  = (Get-Date).ToUniversalTime().ToString("o")
        Category = $Category
        Severity = $Severity
        Title    = $Title
        Details  = $Details
    }) | Out-Null
}

function Add-TimelineEvent {
    param(
        [datetime]$Time,
        [string]$Source,
        [string]$Type,
        [string]$Details
    )
    if ($null -eq $Time) { return }
    $script:Timeline.Add([pscustomobject]@{
        TimeLocal = $Time.ToString("yyyy-MM-dd HH:mm:ss")
        TimeUtc   = $Time.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Source    = $Source
        Type      = $Type
        Details   = $Details
    }) | Out-Null
}

function Export-ObjectBoth {
    param(
        [Parameter(Mandatory=$true)] $InputObject,
        [Parameter(Mandatory=$true)] [string]$BaseName
    )
    $jsonPath = Join-Path $script:EvidenceDir ($BaseName + '.json')
    $csvPath  = Join-Path $script:EvidenceDir ($BaseName + '.csv')

    try { $InputObject | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $jsonPath -Encoding UTF8 } catch {}
    try { $InputObject | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 } catch {}
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-SHA256 {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        }
    } catch {}
    return $null
}

function Get-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name = ""
    )
    try {
        if ($Name) {
            return (Get-ItemProperty -LiteralPath $Path -ErrorAction Stop).$Name
        } else {
            return Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        }
    } catch {
        return $null
    }
}

function Get-UserProfileMap {
    $profiles = @{}
    try {
        Get-CimInstance Win32_UserProfile -ErrorAction Stop | ForEach-Object {
            if ($_.LocalPath) { $profiles[$_.SID] = $_.LocalPath }
        }
    } catch {}
    return $profiles
}

function Convert-SidToName {
    param([string]$Sid)
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $Sid
    }
}

function Get-RecentFiles {
    param(
        [string[]]$Paths,
        [datetime]$Since,
        [int]$MaxPerPath = 300,
        [switch]$WithHash
    )

    $items = New-Object System.Collections.Generic.List[object]

    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        try {
            Get-ChildItem -LiteralPath $path -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LastWriteTime -ge $Since -or $_.CreationTime -ge $Since -or $_.LastAccessTime -ge $Since
                } |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First $MaxPerPath |
                ForEach-Object {
                    $hash = $null
                    if ($WithHash) { $hash = Get-SHA256 -Path $_.FullName }

                    $obj = [pscustomobject]@{
                        Path           = $_.FullName
                        Name           = $_.Name
                        Extension      = $_.Extension
                        Length         = $_.Length
                        CreationTime   = $_.CreationTime
                        LastWriteTime  = $_.LastWriteTime
                        LastAccessTime = $_.LastAccessTime
                        Directory      = $_.DirectoryName
                        HashSHA256     = $hash
                    }
                    $items.Add($obj) | Out-Null

                    Add-TimelineEvent -Time $_.CreationTime  -Source 'FileSystem' -Type 'FileCreation' -Details $_.FullName
                    Add-TimelineEvent -Time $_.LastWriteTime -Source 'FileSystem' -Type 'FileWrite'    -Details $_.FullName
                }
        } catch {}
    }

    return $items
}

# ------------------------------------------------------------
# Collection functions
# ------------------------------------------------------------
function Collect-SystemContext {
    $os = Safe-Run -Name 'OS and computer info' -ScriptBlock {
        [pscustomobject]@{
            Hostname                = $env:COMPUTERNAME
            Domain                  = $script:DomainName
            Username                = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            IsAdmin                 = Test-IsAdmin
            CurrentTimeLocal        = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            CurrentTimeUtc          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            TimeZone                = (Get-TimeZone).Id
            PSVersion               = $PSVersionTable.PSVersion.ToString()
            OSName                  = (Get-CimInstance Win32_OperatingSystem).Caption
            OSVersion               = (Get-CimInstance Win32_OperatingSystem).Version
            BuildNumber             = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            LastBootUpTime          = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            InstallDate             = (Get-CimInstance Win32_OperatingSystem).InstallDate
            Manufacturer            = (Get-CimInstance Win32_ComputerSystem).Manufacturer
            Model                   = (Get-CimInstance Win32_ComputerSystem).Model
            TotalPhysicalMemoryGB   = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
            BIOSSerial              = (Get-CimInstance Win32_BIOS).SerialNumber
        }
    } -OutFile 'system_context.json' -Json

    Safe-Run -Name 'IP configuration' -ScriptBlock { ipconfig /all } -OutFile 'ipconfig_all.txt'
    Safe-Run -Name 'Routing table' -ScriptBlock { route print } -OutFile 'route_print.txt'
    Safe-Run -Name 'ARP table' -ScriptBlock { arp -a } -OutFile 'arp_table.txt'
    Safe-Run -Name 'DNS cache' -ScriptBlock { ipconfig /displaydns } -OutFile 'dns_cache.txt'
    Safe-Run -Name 'Firewall profiles' -ScriptBlock { netsh advfirewall show allprofiles } -OutFile 'firewall_profiles.txt'
    Safe-Run -Name 'Local shares' -ScriptBlock { net share } -OutFile 'local_shares.txt'
}

function Collect-Processes {
    $processes = Safe-Run -Name 'Processes enriched' -ScriptBlock {
        $cim = @{}
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object { $cim[$_.ProcessId] = $_ }

        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $p = $_
            $cp = $cim[$p.Id]

            $owner = $null
            try {
                if ($cp) {
                    $o = Invoke-CimMethod -InputObject $cp -MethodName GetOwner -ErrorAction Stop
                    if ($o.User) {
                        $owner = if ($o.Domain) { "$($o.Domain)\$($o.User)" } else { $o.User }
                    }
                }
            } catch {}

            $path = $null
            try { $path = $p.Path } catch {}

            $company = $null
            $description = $null
            $product = $null
            if ($path -and (Test-Path -LiteralPath $path)) {
                try {
                    $vi = (Get-Item -LiteralPath $path).VersionInfo
                    $company = $vi.CompanyName
                    $description = $vi.FileDescription
                    $product = $vi.ProductName
                } catch {}
            }

            [pscustomobject]@{
                Name              = $p.ProcessName
                PID               = $p.Id
                ParentPID         = if ($cp) { $cp.ParentProcessId } else { $null }
                SessionId         = $p.SessionId
                StartTime         = try { $p.StartTime } catch { $null }
                CPU               = try { $p.CPU } catch { $null }
                WorkingSetMB      = [math]::Round($p.WorkingSet64 / 1MB, 2)
                PrivateMemoryMB   = try { [math]::Round($p.PrivateMemorySize64 / 1MB, 2) } catch { $null }
                Handles           = $p.Handles
                Threads           = $p.Threads.Count
                Path              = $path
                CommandLine       = if ($cp) { $cp.CommandLine } else { $null }
                ExecutableHash    = if ($path -and -not $NoHash) { Get-SHA256 -Path $path } else { $null }
                Owner             = $owner
                Company           = $company
                Description       = $description
                Product           = $product
            }
        } | Sort-Object StartTime
    }

    if ($processes) {
        Export-ObjectBoth -InputObject $processes -BaseName 'processes_enriched'

        foreach ($p in $processes) {
            if ($p.StartTime) {
                Add-TimelineEvent -Time $p.StartTime -Source 'Process' -Type 'ProcessStart' -Details ("{0} PID={1} PPID={2} CMD={3}" -f $p.Name, $p.PID, $p.ParentPID, $p.CommandLine)
            }

            if ($p.CommandLine -match '(?i)powershell(.+)-enc(odedcommand)?\s+' -or
                $p.CommandLine -match '(?i)frombase64string' -or
                $p.CommandLine -match '(?i)iex\s*\(' -or
                $p.CommandLine -match '(?i)downloadstring' -or
                $p.CommandLine -match '(?i)rundll32' -or
                $p.CommandLine -match '(?i)regsvr32' -or
                $p.CommandLine -match '(?i)mshta' -or
                $p.CommandLine -match '(?i)wscript|cscript|wmic|certutil|bitsadmin|psexec|schtasks') {
                Add-Finding -Category 'Process' -Severity 'High' -Title "Suspicious command line in PID $($p.PID)" -Details ("{0} :: {1}" -f $p.Name, $p.CommandLine)
            }

            if ($p.Path -and $p.Path -match '(?i)\\Users\\Public\\|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\ProgramData\\' -and
                $p.Name -notmatch '^(svchost|dllhost|conhost|cmd|powershell|pwsh)$') {
                Add-Finding -Category 'Process' -Severity 'Medium' -Title "Process running from uncommon writable path" -Details ("{0} :: {1}" -f $p.Name, $p.Path)
            }

            if ([string]::IsNullOrWhiteSpace($p.Company) -and $p.Path -and $p.Path -match '(?i)\\Windows\\|\\Program Files') {
                Add-Finding -Category 'Process' -Severity 'Low' -Title "Unsigned/unknown vendor candidate under trusted path" -Details ("{0} :: {1}" -f $p.Name, $p.Path)
            }
        }
    }

    $modules = Safe-Run -Name 'Loaded modules by process' -ScriptBlock {
        $out = New-Object System.Collections.Generic.List[object]
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $proc = $_
            try {
                foreach ($m in $proc.Modules) {
                    $out.Add([pscustomobject]@{
                        ProcessName = $proc.ProcessName
                        PID         = $proc.Id
                        ModuleName  = $m.ModuleName
                        FileName    = $m.FileName
                        FileVersion = $m.FileVersionInfo.FileVersion
                        Company     = $m.FileVersionInfo.CompanyName
                    }) | Out-Null
                }
            } catch {}
        }
        $out
    }

    if ($modules) {
        Export-ObjectBoth -InputObject $modules -BaseName 'process_modules'
    }
}

function Collect-Network {
    $tcp = Safe-Run -Name 'TCP connections' -ScriptBlock {
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
                          CreationTime, AppliedSetting, OffloadState
    }

    $udp = Safe-Run -Name 'UDP endpoints' -ScriptBlock {
        Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, OwningProcess
    }

    $listeners = Safe-Run -Name 'Netstat full' -ScriptBlock { netstat -ano } -OutFile 'netstat_ano.txt'

    $procMap = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object { $procMap[$_.ProcessId] = $_ }
    } catch {}

    if ($tcp) {
        $enriched = foreach ($c in $tcp) {
            $proc = $procMap[[int]$c.OwningProcess]
            [pscustomobject]@{
                State         = $c.State
                LocalAddress  = $c.LocalAddress
                LocalPort     = $c.LocalPort
                RemoteAddress = $c.RemoteAddress
                RemotePort    = $c.RemotePort
                OwningProcess = $c.OwningProcess
                ProcessName   = if ($proc) { $proc.Name } else { $null }
                CommandLine   = if ($proc) { $proc.CommandLine } else { $null }
                CreationTime  = $c.CreationTime
            }
        }

        Export-ObjectBoth -InputObject $enriched -BaseName 'tcp_connections_enriched'

        foreach ($c in $enriched) {
            if ($c.State -eq 'Listen' -and $c.LocalAddress -notin @('127.0.0.1','::1','0.0.0.0','::')) {
                Add-Finding -Category 'Network' -Severity 'Medium' -Title 'Unexpected external-facing listener' -Details ("{0}:{1} PID={2} {3}" -f $c.LocalAddress, $c.LocalPort, $c.OwningProcess, $c.ProcessName)
            }

            if ($c.RemoteAddress -and $c.RemoteAddress -notmatch '^(127\.|10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|::1|fe80:|0\.0\.0\.0$)' -and $c.State -match 'Established|SynSent') {
                Add-Finding -Category 'Network' -Severity 'Info' -Title 'Active external connection' -Details ("{0}:{1} -> {2}:{3} PID={4} {5}" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.OwningProcess, $c.ProcessName)
            }
        }
    }

    if ($udp) {
        Export-ObjectBoth -InputObject $udp -BaseName 'udp_endpoints'
    }
}

function Collect-ServicesAndDrivers {
    $services = Safe-Run -Name 'Services' -ScriptBlock {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName, Description
    }

    if ($services) {
        Export-ObjectBoth -InputObject $services -BaseName 'services'

        foreach ($s in $services) {
            if ($s.PathName -match '(?i)\\Users\\|\\ProgramData\\|\\AppData\\|\\Temp\\') {
                Add-Finding -Category 'Service' -Severity 'High' -Title 'Service binary under writable/uncommon path' -Details ("{0} :: {1}" -f $s.Name, $s.PathName)
            }
            if ($s.StartMode -eq 'Auto' -and $s.StartName -notmatch 'LocalSystem|LocalService|NetworkService' -and $s.StartName) {
                Add-Finding -Category 'Service' -Severity 'Medium' -Title 'Auto service running with explicit account' -Details ("{0} :: {1}" -f $s.Name, $s.StartName)
            }
        }
    }

    $drivers = Safe-Run -Name 'Drivers' -ScriptBlock {
        Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType
    }

    if ($drivers) {
        Export-ObjectBoth -InputObject $drivers -BaseName 'drivers'
        foreach ($d in $drivers) {
            if ($d.PathName -match '(?i)\\Users\\|\\ProgramData\\|\\Temp\\') {
                Add-Finding -Category 'Driver' -Severity 'High' -Title 'Driver loaded from suspicious path' -Details ("{0} :: {1}" -f $d.Name, $d.PathName)
            }
        }
    }
}

function Collect-ScheduledTasks {
    $tasks = Safe-Run -Name 'Scheduled tasks' -ScriptBlock {
        Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
            $task = $_
            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop } catch {}
            $actions = $task.Actions | ForEach-Object {
                "{0} {1} {2}" -f $_.Execute, $_.Arguments, $_.WorkingDirectory
            }

            [pscustomobject]@{
                TaskName     = $task.TaskName
                TaskPath     = $task.TaskPath
                State        = $task.State
                Author       = $task.Principal.UserId
                RunLevel     = $task.Principal.RunLevel
                Description  = $task.Description
                Triggers     = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName + ":" + $_.StartBoundary }) -join " | "
                Actions      = $actions -join " || "
                LastRunTime  = if ($info) { $info.LastRunTime } else { $null }
                NextRunTime  = if ($info) { $info.NextRunTime } else { $null }
                LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
            }
        }
    }

    if ($tasks) {
        Export-ObjectBoth -InputObject $tasks -BaseName 'scheduled_tasks'
        foreach ($t in $tasks) {
            if ($t.Actions -match '(?i)\\Users\\|\\ProgramData\\|\\AppData\\|\\Temp\\|powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32') {
                Add-Finding -Category 'ScheduledTask' -Severity 'High' -Title 'Potentially suspicious scheduled task action' -Details ("{0}{1} :: {2}" -f $t.TaskPath, $t.TaskName, $t.Actions)
            }
            if ($t.LastRunTime) {
                Add-TimelineEvent -Time $t.LastRunTime -Source 'ScheduledTask' -Type 'TaskExecution' -Details ("{0}{1} :: {2}" -f $t.TaskPath, $t.TaskName, $t.Actions)
            }
        }
    }
}

function Collect-Accounts {
    Safe-Run -Name 'Local users (net user)' -ScriptBlock { net user } -OutFile 'net_user.txt'
    Safe-Run -Name 'Local groups (net localgroup)' -ScriptBlock { net localgroup } -OutFile 'net_localgroup.txt'
    Safe-Run -Name 'Administrators group members' -ScriptBlock { net localgroup administrators } -OutFile 'local_admins.txt'

    $localUsers = Safe-Run -Name 'Local user accounts detail' -ScriptBlock {
        try {
            Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, UserMayChangePassword, AccountExpires, Description, SID
        } catch {
            Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
                Select-Object Name, Disabled, Lockout, PasswordRequired, PasswordChangeable, SID, FullName
        }
    }

    if ($localUsers) {
        Export-ObjectBoth -InputObject $localUsers -BaseName 'local_users'
        foreach ($u in $localUsers) {
            $enabled = if ($u.PSObject.Properties.Name -contains 'Enabled') { $u.Enabled } else { -not $u.Disabled }
            if ($enabled -and $u.Name -match '^(test|admin2|backup|svc|support|temp|helpdesk)$') {
                Add-Finding -Category 'Account' -Severity 'Medium' -Title 'Potentially risky local account name' -Details $u.Name
            }
        }
    }
}

function Collect-Persistence {
    $autoruns = New-Object System.Collections.Generic.List[object]

    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($rk in $runKeys) {
        try {
            if (Test-Path -LiteralPath $rk) {
                $p = Get-ItemProperty -LiteralPath $rk
                foreach ($prop in $p.PSObject.Properties) {
                    if ($prop.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') {
                        $autoruns.Add([pscustomobject]@{
                            Category = 'RunKey'
                            Path     = $rk
                            Name     = $prop.Name
                            Value    = [string]$prop.Value
                        }) | Out-Null
                    }
                }
            }
        } catch {}
    }

    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($sp in $startupPaths) {
        try {
            if (Test-Path -LiteralPath $sp) {
                Get-ChildItem -LiteralPath $sp -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    $autoruns.Add([pscustomobject]@{
                        Category = 'StartupFolder'
                        Path     = $sp
                        Name     = $_.Name
                        Value    = $_.FullName
                    }) | Out-Null
                }
            }
        } catch {}
    }

    $extraReg = @(
        @{ Cat='WinlogonShell'; Path='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='Shell' },
        @{ Cat='WinlogonUserinit'; Path='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='Userinit' },
        @{ Cat='AppInitDLLs'; Path='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows'; Name='AppInit_DLLs' },
        @{ Cat='LoadAppInitDLLs'; Path='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows'; Name='LoadAppInit_DLLs' },
        @{ Cat='IFEO'; Path='HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; Name='' }
    )

    foreach ($item in $extraReg) {
        try {
            if ($item.Cat -eq 'IFEO') {
                if (Test-Path -LiteralPath $item.Path) {
                    Get-ChildItem -LiteralPath $item.Path -ErrorAction SilentlyContinue | ForEach-Object {
                        $dbg = Get-RegistryValueSafe -Path $_.PSPath -Name 'Debugger'
                        if ($dbg) {
                            $autoruns.Add([pscustomobject]@{
                                Category = 'IFEO'
                                Path     = $_.PSPath
                                Name     = 'Debugger'
                                Value    = $dbg
                            }) | Out-Null
                        }
                    }
                }
            } else {
                $val = Get-RegistryValueSafe -Path $item.Path -Name $item.Name
                if ($null -ne $val -and [string]::IsNullOrWhiteSpace([string]$val) -eq $false) {
                    $autoruns.Add([pscustomobject]@{
                        Category = $item.Cat
                        Path     = $item.Path
                        Name     = $item.Name
                        Value    = [string]$val
                    }) | Out-Null
                }
            }
        } catch {}
    }

    try {
        $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
            Select-Object Name, CommandLineTemplate, ExecutablePath
        foreach ($wc in $wmiConsumers) {
            $autoruns.Add([pscustomobject]@{
                Category = 'WMIEventConsumer'
                Path     = 'root\subscription\CommandLineEventConsumer'
                Name     = $wc.Name
                Value    = "$($wc.ExecutablePath) | $($wc.CommandLineTemplate)"
            }) | Out-Null
        }
    } catch {}

    try {
        $wmiBindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        foreach ($wb in $wmiBindings) {
            $autoruns.Add([pscustomobject]@{
                Category = 'WMIBinding'
                Path     = 'root\subscription\__FilterToConsumerBinding'
                Name     = 'Binding'
                Value    = ($wb.Filter + ' -> ' + $wb.Consumer)
            }) | Out-Null
        }
    } catch {}

    if ($autoruns.Count -gt 0) {
        Export-ObjectBoth -InputObject $autoruns -BaseName 'persistence_autoruns'

        foreach ($a in $autoruns) {
            if ($a.Value -match '(?i)\\Users\\|\\ProgramData\\|\\AppData\\|\\Temp\\|powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32') {
                Add-Finding -Category 'Persistence' -Severity 'High' -Title "Suspicious persistence entry [$($a.Category)]" -Details ("{0} :: {1} :: {2}" -f $a.Path, $a.Name, $a.Value)
            }
        }
    }
}

function Collect-FileSystemArtifacts {
    $since = (Get-Date).AddDays(-1 * $DaysBack)
    $paths = @(
        "$env:SystemRoot\Temp",
        "$env:TEMP",
        "$env:ProgramData",
        "$env:PUBLIC",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:SystemRoot\System32\Tasks",
        "$env:SystemRoot\Prefetch",
        "$env:SystemRoot\System32\wbem\Repository"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    $recent = Get-RecentFiles -Paths $paths -Since $since -MaxPerPath $MaxFileScan -WithHash:(-not $NoHash)
    if ($recent.Count -gt 0) {
        Export-ObjectBoth -InputObject $recent -BaseName 'recent_files_triage'

        foreach ($f in $recent) {
            if ($f.Path -match '(?i)\.(ps1|vbs|js|jse|hta|bat|cmd|dll|exe|scr|dat|tmp|zip|7z|rar|lnk)$') {
                Add-Finding -Category 'File' -Severity 'Info' -Title 'Interesting recent file extension in triage path' -Details $f.Path
            }
            if ($f.Path -match '(?i)\\Startup\\|\\System32\\Tasks\\') {
                Add-Finding -Category 'File' -Severity 'Medium' -Title 'Recent file in persistence-related directory' -Details $f.Path
            }
        }
    }

    # Prefetch inventory
    $prefetch = Safe-Run -Name 'Prefetch files' -ScriptBlock {
        $pfDir = "$env:SystemRoot\Prefetch"
        if (Test-Path -LiteralPath $pfDir) {
            Get-ChildItem -LiteralPath $pfDir -File -Force -ErrorAction SilentlyContinue |
                Select-Object Name, FullName, Length, CreationTime, LastWriteTime, LastAccessTime
        }
    }

    if ($prefetch) {
        Export-ObjectBoth -InputObject $prefetch -BaseName 'prefetch_inventory'
        foreach ($pf in $prefetch) {
            Add-TimelineEvent -Time $pf.LastWriteTime -Source 'Prefetch' -Type 'ProgramExecutionArtifact' -Details $pf.Name
        }
    }

    # PowerShell history
    $profiles = Get-UserProfileMap
    $psHist = New-Object System.Collections.Generic.List[object]

    foreach ($sid in $profiles.Keys) {
        $profilePath = $profiles[$sid]
        $histPath = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path -LiteralPath $histPath) {
            try {
                $content = Get-Content -LiteralPath $histPath -ErrorAction SilentlyContinue
                $psHist.Add([pscustomobject]@{
                    SID       = $sid
                    User      = Convert-SidToName -Sid $sid
                    Path      = $histPath
                    LineCount = $content.Count
                    Preview   = ($content | Select-Object -Last 50) -join "`n"
                }) | Out-Null
            } catch {}
        }
    }

    if ($psHist.Count -gt 0) {
        $psHist | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $script:EvidenceDir 'powershell_history.json') -Encoding UTF8

        foreach ($h in $psHist) {
            if ($h.Preview -match '(?i)invoke-webrequest|iwr|downloadstring|frombase64string|iex|mimikatz|rubeus|sekurlsa|set-mppreference|add-mppreference|net user|net localgroup|schtasks|sc create|reg add') {
                Add-Finding -Category 'PowerShellHistory' -Severity 'High' -Title 'Interesting commands in PowerShell history' -Details ("{0} :: {1}" -f $h.User, $h.Path)
            }
        }
    }
}

function Collect-EventLogs {
    $since = (Get-Date).AddDays(-1 * $DaysBack)

    $logTargets = @(
        @{ Name='Security'; Path='event_security.csv' },
        @{ Name='System'; Path='event_system.csv' },
        @{ Name='Application'; Path='event_application.csv' },
        @{ Name='Microsoft-Windows-PowerShell/Operational'; Path='event_powershell_operational.csv' },
        @{ Name='Windows PowerShell'; Path='event_windows_powershell.csv' },
        @{ Name='Microsoft-Windows-TaskScheduler/Operational'; Path='event_taskscheduler_operational.csv' },
        @{ Name='Microsoft-Windows-Windows Defender/Operational'; Path='event_defender_operational.csv' },
        @{ Name='Microsoft-Windows-Sysmon/Operational'; Path='event_sysmon_operational.csv' }
    )

    foreach ($lt in $logTargets) {
        Safe-Run -Name "Event log $($lt.Name)" -ScriptBlock {
            Get-WinEvent -FilterHashtable @{
                LogName   = $lt.Name
                StartTime = $since
            } -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, ProcessId, ThreadId, Message
        } -OutFile $lt.Path -Csv
    }

    # Security focused IDs
    $secInteresting = Safe-Run -Name 'Security interesting events' -ScriptBlock {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            StartTime = $since
            Id        = @(4624,4625,4634,4648,4672,4688,4697,4698,4702,4719,4720,4722,4723,4724,4728,4732,4738,4740,4768,4769,4776,4782,4798,4799,5140,5145)
        } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, ProviderName, Message
    }

    if ($secInteresting) {
        Export-ObjectBoth -InputObject $secInteresting -BaseName 'security_interesting_events'

        foreach ($e in $secInteresting) {
            Add-TimelineEvent -Time $e.TimeCreated -Source 'Security' -Type ("EventID " + $e.Id) -Details (($e.Message -replace '\s+',' ') -replace "`r|`n",' ')

            switch ($e.Id) {
                4720 { Add-Finding -Category 'EventLog' -Severity 'High' -Title 'User account created' -Details $e.Message }
                4732 { Add-Finding -Category 'EventLog' -Severity 'High' -Title 'User added to privileged local group' -Details $e.Message }
                4698 { Add-Finding -Category 'EventLog' -Severity 'High' -Title 'Scheduled task created' -Details $e.Message }
                4702 { Add-Finding -Category 'EventLog' -Severity 'High' -Title 'Scheduled task updated' -Details $e.Message }
                4697 { Add-Finding -Category 'EventLog' -Severity 'High' -Title 'Service installed in system' -Details $e.Message }
                4688 {
                    if ($e.Message -match '(?i)powershell|pwsh|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|schtasks|sc\.exe|net\.exe') {
                        Add-Finding -Category 'EventLog' -Severity 'Medium' -Title 'Interesting process creation in Security log' -Details $e.Message
                    }
                }
                4624 {
                    if ($e.Message -match '(?i)Logon Type:\s+3|Logon Type:\s+10') {
                        Add-Finding -Category 'EventLog' -Severity 'Info' -Title 'Remote/network logon observed' -Details $e.Message
                    }
                }
            }
        }
    }

    $psOperational = Safe-Run -Name 'PowerShell Operational interesting events' -ScriptBlock {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            StartTime = $since
            Id        = @(400,403,4103,4104,4105,4106)
        } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, ProviderName, Message
    }

    if ($psOperational) {
        Export-ObjectBoth -InputObject $psOperational -BaseName 'powershell_interesting_events'
        foreach ($e in $psOperational) {
            Add-TimelineEvent -Time $e.TimeCreated -Source 'PowerShellOperational' -Type ("EventID " + $e.Id) -Details (($e.Message -replace '\s+',' ') -replace "`r|`n",' ')
            if ($e.Message -match '(?i)invoke-expression|downloadstring|frombase64string|encodedcommand|new-object\s+net\.webclient|iwr|iex') {
                Add-Finding -Category 'PowerShellLog' -Severity 'High' -Title 'Suspicious PowerShell content in operational log' -Details $e.Message
            }
        }
    }

    $defender = Safe-Run -Name 'Defender detections recent' -ScriptBlock {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Windows Defender/Operational'
            StartTime = $since
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 1116,1117,5007,5013 } |
        Select-Object TimeCreated, Id, ProviderName, Message
    }

    if ($defender) {
        Export-ObjectBoth -InputObject $defender -BaseName 'defender_interesting_events'
        foreach ($e in $defender) {
            Add-TimelineEvent -Time $e.TimeCreated -Source 'Defender' -Type ("EventID " + $e.Id) -Details (($e.Message -replace '\s+',' ') -replace "`r|`n",' ')
            if ($e.Id -eq 5007) {
                Add-Finding -Category 'Defender' -Severity 'High' -Title 'Defender setting changed' -Details $e.Message
            }
            if ($e.Id -in 1116,1117) {
                Add-Finding -Category 'Defender' -Severity 'Medium' -Title 'Defender detection/remediation event' -Details $e.Message
            }
        }
    }
}

function Collect-DefenderState {
    $mp = Safe-Run -Name 'Defender preferences' -ScriptBlock {
        try { Get-MpPreference } catch { $null }
    }

    if ($mp) {
        $mp | ConvertTo-Json -Depth 8 | Out-File -LiteralPath (Join-Path $script:EvidenceDir 'defender_preferences.json') -Encoding UTF8

        try {
            if ($mp.DisableRealtimeMonitoring -eq $true) {
                Add-Finding -Category 'Defender' -Severity 'High' -Title 'Realtime monitoring disabled' -Details 'Get-MpPreference indicates DisableRealtimeMonitoring=True'
            }

            if ($mp.ExclusionPath -and $mp.ExclusionPath.Count -gt 0) {
                Add-Finding -Category 'Defender' -Severity 'Medium' -Title 'Defender exclusion paths configured' -Details ($mp.ExclusionPath -join '; ')
            }

            if ($mp.ExclusionProcess -and $mp.ExclusionProcess.Count -gt 0) {
                Add-Finding -Category 'Defender' -Severity 'Medium' -Title 'Defender exclusion processes configured' -Details ($mp.ExclusionProcess -join '; ')
            }
        } catch {}
    }
}

function Collect-InstalledSoftware {
    $software = Safe-Run -Name 'Installed software from uninstall registry' -ScriptBlock {
        $roots = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
        )

        $out = New-Object System.Collections.Generic.List[object]
        foreach ($root in $roots) {
            if (Test-Path -LiteralPath $root) {
                Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
                        if ($p.DisplayName) {
                            $out.Add([pscustomobject]@{
                                DisplayName     = $p.DisplayName
                                DisplayVersion  = $p.DisplayVersion
                                Publisher       = $p.Publisher
                                InstallDate     = $p.InstallDate
                                InstallLocation = $p.InstallLocation
                                UninstallString = $p.UninstallString
                                RegistryPath    = $_.PSPath
                            }) | Out-Null
                        }
                    } catch {}
                }
            }
        }
        $out | Sort-Object DisplayName -Unique
    }

    if ($software) {
        Export-ObjectBoth -InputObject $software -BaseName 'installed_software'
    }
}

function Collect-UserSessions {
    Safe-Run -Name 'Current sessions (query user)' -ScriptBlock { query user } -OutFile 'query_user.txt'
    Safe-Run -Name 'Current sessions (quser)' -ScriptBlock { quser } -OutFile 'quser.txt'
    Safe-Run -Name 'Logged on users' -ScriptBlock { whoami /all } -OutFile 'whoami_all.txt'
}

function Build-Reports {
    $summaryPath = Join-Path $script:ReportsDir 'collection_summary.csv'
    $findingsPath = Join-Path $script:ReportsDir 'findings.csv'
    $timelinePath = Join-Path $script:TimelineDir 'timeline.csv'
    $timelineJson = Join-Path $script:TimelineDir 'timeline.json'
    $reportTxt = Join-Path $script:ReportsDir 'executive_report.txt'

    try { $script:Summary  | Export-Csv -LiteralPath $summaryPath  -NoTypeInformation -Encoding UTF8 } catch {}
    try { $script:Findings | Export-Csv -LiteralPath $findingsPath -NoTypeInformation -Encoding UTF8 } catch {}
    try {
        $orderedTimeline = $script:Timeline | Sort-Object {[datetime]$_.TimeLocal}
        $orderedTimeline | Export-Csv -LiteralPath $timelinePath -NoTypeInformation -Encoding UTF8
        $orderedTimeline | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $timelineJson -Encoding UTF8
    } catch {}

    $highCount   = ($script:Findings | Where-Object Severity -eq 'High').Count
    $mediumCount = ($script:Findings | Where-Object Severity -eq 'Medium').Count
    $lowCount    = ($script:Findings | Where-Object Severity -eq 'Low').Count
    $infoCount   = ($script:Findings | Where-Object Severity -eq 'Info').Count

    $topFindings = $script:Findings |
        Sort-Object @{Expression={
            switch ($_.Severity) {
                'High'   { 4 }
                'Medium' { 3 }
                'Low'    { 2 }
                'Info'   { 1 }
                default  { 0 }
            }
        }} -Descending |
        Select-Object -First 50

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Windows Incident Diagnosis Report") | Out-Null
    $lines.Add(("Host: {0}" -f $script:HostName)) | Out-Null
    $lines.Add(("Domain: {0}" -f $script:DomainName)) | Out-Null
    $lines.Add(("Generated: {0}" -f (Get-Date))) | Out-Null
    $lines.Add(("DaysBack: {0}" -f $DaysBack)) | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("Findings summary") | Out-Null
    $lines.Add(("High   : {0}" -f $highCount)) | Out-Null
    $lines.Add(("Medium : {0}" -f $mediumCount)) | Out-Null
    $lines.Add(("Low    : {0}" -f $lowCount)) | Out-Null
    $lines.Add(("Info   : {0}" -f $infoCount)) | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("Top findings") | Out-Null

    foreach ($f in $topFindings) {
        $lines.Add(("[{0}] [{1}] {2}" -f $f.Severity, $f.Category, $f.Title)) | Out-Null
        $lines.Add(("  {0}" -f ($f.Details -replace "`r|`n",' '))) | Out-Null
    }

    $lines.Add("") | Out-Null
    $lines.Add("Output folders") | Out-Null
    $lines.Add(("Evidence : {0}" -f $script:EvidenceDir)) | Out-Null
    $lines.Add(("Reports  : {0}" -f $script:ReportsDir)) | Out-Null
    $lines.Add(("Timeline : {0}" -f $script:TimelineDir)) | Out-Null
    $lines.Add(("Logs     : {0}" -f $script:LogsDir)) | Out-Null

    $lines | Out-File -LiteralPath $reportTxt -Encoding UTF8
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
New-OutputStructure
Write-Log "Starting Windows incident diagnosis triage"
Write-Log ("Output directory: {0}" -f $script:BaseOutDir)
Write-Log ("Running as admin: {0}" -f (Test-IsAdmin))

Collect-SystemContext
Collect-UserSessions
Collect-Processes
Collect-Network
Collect-ServicesAndDrivers
Collect-ScheduledTasks
Collect-Accounts
Collect-Persistence
Collect-FileSystemArtifacts
Collect-EventLogs
Collect-DefenderState
Collect-InstalledSoftware
Build-Reports

Write-Log "Triage completed" 'OK'
Write-Host ""
Write-Host "Done."
Write-Host ("Base output: {0}" -f $script:BaseOutDir)
Write-Host ("Executive report: {0}" -f (Join-Path $script:ReportsDir 'executive_report.txt'))
Write-Host ("Findings CSV: {0}" -f (Join-Path $script:ReportsDir 'findings.csv'))
Write-Host ("Timeline CSV: {0}" -f (Join-Path $script:TimelineDir 'timeline.csv'))
