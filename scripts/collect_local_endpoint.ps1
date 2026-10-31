# Read-only, current Windows identity only. No audit-policy or device changes.
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
function Fingerprint([string]$value){
    $h=[System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($env:SEDRA_SENSOR_SALT))
    try{return ([BitConverter]::ToString($h.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($value)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
}
$events=[System.Collections.Generic.List[object]]::new()
$coverage=[ordered]@{}
$since=(Get-Date).AddDays(-7)
try{
    $records=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=$since} -MaxEvents 200 -ErrorAction Stop)
    foreach($r in $records){
        [xml]$xml=$r.ToXml();$fields=@{}
        foreach($d in $xml.Event.EventData.Data){$fields[[string]$d.Name]=[string]$d.'#text'}
        if($fields.TargetUserSid -eq $identity.User.Value){
            $events.Add(@{source_id="Security:$($r.RecordId):$($r.TimeCreated.ToUniversalTime().ToString('o'))";channel='logon';kind=$(if($r.Id -eq 4624){'logon_success'}else{'logon_failure'});at=$r.TimeCreated.ToUniversalTime().ToString('o');detail=@{event_id=$r.Id;logon_type=$fields.LogonType;provider='Windows Security';identity_scope='current Windows SID only'}})
        }
    }
    $coverage.security='readable_current_sid_only'
}catch{$coverage.security=$(if($_.Exception -is [System.UnauthorizedAccessException] -or $_.FullyQualifiedErrorId -match 'Unauthorized|Permission'){'access_denied'}else{'no_matching_events_or_unavailable'})}
try{
    $records=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';Id=21,23,24,25;StartTime=$since} -MaxEvents 200 -ErrorAction Stop)
    foreach($r in $records){
        [xml]$xml=$r.ToXml();$userNode=$xml.SelectSingleNode("//*[local-name()='User']")
        if($null -ne $userNode -and $userNode.InnerText -ieq $identity.Name){
            $kinds=@{21='session_logon';23='session_logoff';24='session_disconnect';25='session_reconnect'}
            $events.Add(@{source_id="LSM:$($r.RecordId):$($r.TimeCreated.ToUniversalTime().ToString('o'))";channel='logon';kind=$kinds[[int]$r.Id];at=$r.TimeCreated.ToUniversalTime().ToString('o');detail=@{event_id=$r.Id;provider='Windows LocalSessionManager';identity_scope='current Windows identity only'}})
        }
    }
    $coverage.session_log='readable_current_identity_only'
}catch{$coverage.session_log='no_matching_events_or_unavailable'}
# A session snapshot is state, not a newly generated authentication event.
$session=[System.Diagnostics.Process]::GetCurrentProcess().SessionId
$events.Add(@{source_id="session-snapshot:$session";channel='logon';kind='current_session_snapshot';at=[DateTime]::UtcNow.ToString('o');detail=@{session_id=$session;provider='WindowsIdentity / Process.SessionId';evidence='Current session state, not a new logon event'}})
$devices=[System.Collections.Generic.List[string]]::new()
try{
    foreach($disk in @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop)){
        if($disk.InterfaceType -eq 'USB' -or $disk.PNPDeviceID -like 'USBSTOR\*' -or $disk.PNPDeviceID -like 'USB\*'){$devices.Add((Fingerprint ("disk:"+$disk.PNPDeviceID)))}
    }
    foreach($volume in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction Stop)){$devices.Add((Fingerprint ("removable-volume:"+$volume.DeviceID)))}
    $coverage.usb='connected_presence_polling_no_contents_read'
}catch{$coverage.usb='unavailable'}
$processes=[System.Collections.Generic.List[object]]::new()
try{
    # Observe only direct children of this SEDRA server, never unrelated processes/command lines.
    foreach($p in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($env:SEDRA_SERVER_PID)" -ErrorAction Stop)){
        if($p.Name -like 'python*'){$processes.Add(@{pid=[int]$p.ProcessId;created=$p.CreationDate.ToUniversalTime().ToString('o')})}
    }
    $coverage.process='connected_server_child_processes_only'
}catch{$coverage.process='unavailable'}
@{observed_at=[DateTime]::UtcNow.ToString('o');identity=(Fingerprint $identity.User.Value);host_id=(Fingerprint $env:COMPUTERNAME);events=@($events.ToArray());usb_devices=@($devices.ToArray());processes=@($processes.ToArray());coverage=$coverage} | ConvertTo-Json -Depth 7 -Compress
