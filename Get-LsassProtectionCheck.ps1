function Get-LsaProtectionStatus {
    param(
        [string]$ComputerName = "localhost",
        [string]$UserName = "Administrator"
    )

    $result = Invoke-Command -HostName $ComputerName -UserName $UserName -SSHTransport -ErrorAction Stop -ScriptBlock {
        $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
        $regValue = if ($reg) { $reg.RunAsPPL } else { 0 }

        $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime

        $event = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Wininit'] and (EventID=12)]]" -MaxEvents 1 -ErrorAction SilentlyContinue

        $confirmedThisBoot = [bool]($event -and ($event.TimeCreated -ge $bootTime))

        [PSCustomObject]@{
            RunAsPPLValue    = $regValue
            RuntimeConfirmed = $confirmedThisBoot
        }
    }

    $configuredIntent = switch ($result.RunAsPPLValue) {
        0       { 'Disabled' }
        1       { 'EnabledWithUefiLock' }
        2       { 'EnabledWithoutUefiLock' }
        default { 'Unknown' }
    }

    $isConfiguredEnabled = $result.RunAsPPLValue -in @(1, 2)

    $status = if ($isConfiguredEnabled -and $result.RuntimeConfirmed) {
        'Protected'
    } elseif ($isConfiguredEnabled -and -not $result.RuntimeConfirmed) {
        'Mismatch: configured enabled but not confirmed running protected (reboot pending?)'
    } elseif (-not $isConfiguredEnabled -and $result.RuntimeConfirmed) {
        'Mismatch: registry disabled but LSASS confirmed running protected (UEFI lock still active?)'
    } else {
        'Disabled'
    }

    [PSCustomObject]@{
        RunAsPPLValue    = $result.RunAsPPLValue
        ConfiguredIntent = $configuredIntent
        RuntimeConfirmed = $result.RuntimeConfirmed
        Status           = $status
    }
}

function Get-CredentialGuardStatus {
    param(
        [string]$ComputerName = "localhost",
        [string]$UserName = "Administrator"
    )

    $dg = Invoke-Command -HostName $ComputerName -UserName $UserName -SSHTransport -ErrorAction Stop -ScriptBlock {
        $raw = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
        [PSCustomObject]@{
            SecurityServicesConfigured = @($raw.SecurityServicesConfigured)
            SecurityServicesRunning    = @($raw.SecurityServicesRunning)
        }
    }

    $isConfigured = $dg.SecurityServicesConfigured -contains 1
    $isRunning    = $dg.SecurityServicesRunning -contains 1

    $status = if ($isConfigured -and $isRunning) {
        'Enabled'
    } elseif ($isConfigured -and -not $isRunning) {
        'Mismatch: Credential Guard configured but not running (reboot pending or hardware unsupported?)'
    } elseif (-not $isConfigured -and $isRunning) {
        'Mismatch: Credential Guard running but not configured (unexpected)'
    } else {
        'Disabled'
    }

    [PSCustomObject]@{
        SecurityServicesConfigured = $dg.SecurityServicesConfigured
        SecurityServicesRunning    = $dg.SecurityServicesRunning
        Status                     = $status
    }
}

function Get-LsassAccessAudit {
    param(
        [string]$ComputerName = "localhost",
        [string]$UserName = "Administrator",
        [int]$LookbackMinutes = 60,
        [string[]]$SourceImageWhitelist = @(
            'C:\Windows\System32\svchost.exe',
            'C:\Windows\System32\wininit.exe',
            'C:\Windows\System32\csrss.exe',
            'C:\Windows\System32\services.exe',
            'C:\Windows\System32\lsass.exe',
            'C:\Program Files\Windows Defender\MsMpEng.exe'
        )
    )

    try {
        $rawEvents = Invoke-Command -HostName $ComputerName -UserName $UserName -SSHTransport -ErrorAction Stop -ScriptBlock {
            param($LookbackMinutes)
            $since = (Get-Date).AddMinutes(-$LookbackMinutes)
            Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=10]]" -ErrorAction SilentlyContinue |
                Where-Object { $_.TimeCreated -ge $since } |
                ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $data = @{}
                    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
                    [PSCustomObject]@{
                        TimeCreated   = $_.TimeCreated
                        SourceImage   = $data['SourceImage']
                        TargetImage   = $data['TargetImage']
                        GrantedAccess = $data['GrantedAccess']
                    }
                }
        } -ArgumentList $LookbackMinutes
    } catch {
        return [PSCustomObject]@{
            Status = "Unreachable: $($_.Exception.Message)"
        }
    }

    $PROCESS_VM_READ = 0x0010

    $alerts = foreach ($e in $rawEvents) {
        $accessInt = [int]$e.GrantedAccess
        if (($accessInt -band $PROCESS_VM_READ) -ne 0) {
            [PSCustomObject]@{
                TimeCreated   = $e.TimeCreated
                SourceImage   = $e.SourceImage
                GrantedAccess = $e.GrantedAccess
                Whitelisted   = $e.SourceImage -in $SourceImageWhitelist
            }
        }
    }

    $nonWhitelistedAlerts = @($alerts | Where-Object { -not $_.Whitelisted })

    $status = if ($nonWhitelistedAlerts.Count -gt 0) {
        'Attention: PROCESS_VM_READ against lsass.exe from non-whitelisted process(es)'
    } elseif (@($alerts).Count -gt 0) {
        'Attention: PROCESS_VM_READ against lsass.exe from whitelisted process(es) - review'
    } else {
        'Pass: no PROCESS_VM_READ access to lsass.exe observed in lookback window'
    }

    [PSCustomObject]@{
        Status        = $status
        EventsScanned = $rawEvents.Count
        Alerts        = $alerts
    }
}

function Invoke-LsassProtectionAudit {
    param(
        [string]$ComputerName = "localhost",
        [string]$UserName = "Administrator",
        [int]$LookbackMinutes = 60
    )

    try {
        $lsaProtection   = Get-LsaProtectionStatus -ComputerName $ComputerName -UserName $UserName
        $credentialGuard = Get-CredentialGuardStatus -ComputerName $ComputerName -UserName $UserName
        $accessAudit     = Get-LsassAccessAudit -ComputerName $ComputerName -UserName $UserName -LookbackMinutes $LookbackMinutes
    } catch {
        return [PSCustomObject]@{
            ComputerName     = $ComputerName
            Timestamp        = Get-Date
            OverallStatus    = 'Unreachable'
            Findings         = @("Connection failed: $($_.Exception.Message)")
            LsaProtection    = $null
            CredentialGuard  = $null
            AccessAudit      = $null
        }
    }

    $findings = @()

    if ($lsaProtection.Status -ne 'Protected') {
        $findings += "LsaProtection: $($lsaProtection.Status)"
    }

    if ($credentialGuard.Status -ne 'Enabled') {
        $findings += "CredentialGuard: $($credentialGuard.Status)"
    }

    if ($accessAudit.Status -like 'Attention*') {
        foreach ($a in $accessAudit.Alerts) {
            $findings += "AccessAudit: PROCESS_VM_READ against lsass.exe from '$($a.SourceImage)' at $($a.TimeCreated) (Whitelisted: $($a.Whitelisted))"
        }
    } elseif ($accessAudit.Status -like 'Unreachable*') {
        $findings += "AccessAudit: $($accessAudit.Status)"
    }

    $overallStatus = if ($findings.Count -gt 0) { 'Attention' } else { 'Pass' }

    [PSCustomObject]@{
        ComputerName    = $ComputerName
        Timestamp       = Get-Date
        OverallStatus   = $overallStatus
        Findings        = $findings
        LsaProtection   = $lsaProtection
        CredentialGuard = $credentialGuard
        AccessAudit     = $accessAudit
    }
}
