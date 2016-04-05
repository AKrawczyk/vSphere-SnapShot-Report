<#
.SYNOPSIS
  
   Script creates report of currently active snapshots from all vms for given vCenter and sends out e-mail reminders to owners of outdated snapshots.
 
.DESCRIPTION
  
   Script is using get-view PowerCLI cmdlet to find virtual machines with active snapshots. This list is further processed to retrieve detailed information
   that is used to create report and send notifications to users who keep their snapshots longer than defined threshold ($notify_threshold variable).
 
.PARAMETER vcenter_srv
 
   Mandatory parameter indicating vCenter server to connect to (FQDN or IP address).
 
.EXAMPLE
 
    snapshot_report.ps1 -vcenter_srv vcenter.company.com
 
    To generate snapshot report about active snapshots for vCenter passed as FQDN.
 
.EXAMPLE
 
    snapshot_report.ps1 -vcenter_srv 10.0.0.1
 
    To generate snapshot report about active snapshots for vCenter passed as IP Address.
 
.EXAMPLE
 
    snapshot_report.ps1
 
    Script will interactively ask for mandatory parameter.
#>
 
#[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True,Position=1)]
  [ValidateNotNullOrEmpty()]
   [string]$vcenter_srv
)
 
Function Write-And-Log {
 
[CmdletBinding()]
Param(
   [Parameter(Mandatory=$True,Position=1)]
   [ValidateNotNullOrEmpty()]
   [string]$LogFile,
   [Parameter(Mandatory=$True,Position=2)]
   [ValidateNotNullOrEmpty()]
   [string]$line,
 
   [Parameter(Mandatory=$False,Position=3)]
   [int]$Severity=0,
 
   [Parameter(Mandatory=$False,Position=4)]
   [string]$type="terse"
 
  
)
 
$timestamp = (Get-Date -Format ("[yyyy-MM-dd HH:mm:ss] "))
$ui = (Get-Host).UI.RawUI
 
switch ($Severity) {
 
        {$_ -gt 0} {$ui.ForegroundColor = "red"; $type ="full"; $LogEntry = $timestamp + ":Error: " + $line; break;}
        {$_ -eq 0} {$ui.ForegroundColor = "green"; $LogEntry = $timestamp + ":Info: " + $line; break;}
        {$_ -lt 0} {$ui.ForegroundColor = "yellow"; $LogEntry = $timestamp + ":Warning: " + $line; break;}
 
}
switch ($type) {
  
        "terse"   {Write-Output $LogEntry; break;}
        "full"    {Write-Output $LogEntry; $LogEntry | Out-file $LogFile -Append; break;}
        "logonly" {$LogEntry | Out-file $LogFile -Append; break;}
    
}
 
$ui.ForegroundColor = "white"
 
}
 
 
#this function will retrieve from AD displayname and e-mail address of snapshot creator account based on his "NT-style" username (domain\login).
Function Find-User ($username){
   if ($username -ne $null)
   {
      $login = (($username.split("\"))[1])
  
      $adsi_searcher = [adsisearcher]"(samaccountname=$login)"
  $userinfo = New-Object PSObject
  $userinfo | Add-Member -Name "email" -Value $adsi_searcher.FindOne().Properties.mail -MemberType NoteProperty
  $userinfo | Add-Member -Name "name" -Value $adsi_searcher.FindOne().Properties.displayname -MemberType NoteProperty
      return ,$userinfo
  
   }
}
 
#variables
$ScriptRoot = Split-Path $MyInvocation.MyCommand.Path
$StartTime = Get-Date -Format "yyyyMMddHHmmss_"
$logdir = $ScriptRoot + "\SnapReportLogs\"
$transcriptfilename = $logdir + $StartTime + "SnapReport_Transcript.log"
$logfilename = $logdir + "SnapReport.log"
$csvoutfile = $logdir + "SnapshotReport4_$($vcenter_srv).csv"
$all_snaps_info =@()
$event_age = 0
[int]$notify_threshold = 1
$now = Get-Date
$date = $now.ToLongDateString()
 
#of course you need to adjust variables below.
$emailto = "cloudadmin@company.com"
$emailcc = "admin@company.com"
$emailfrom = "vCenterServer@company.com"
$smtpserver = "smtp.company.com"
 
#hit ENTER.
$cr_lf = "`r`n"
 
#start PowerShell transcript
#Start-Transcript -Path $transcriptfilename
 
#test for log directory, create if needed
if ( -not (Test-Path $logdir)) {
New-Item -type directory -path $logdir 2>&1 > $null
}
 
Remove-Item -Path ($logdir + "\*.*") -Confirm:$false -Force:$true -ErrorAction SilentlyContinue 2>&1 > $null
 
#load PowerCLI snap-in
$vmsnapin = Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
$Error.Clear()
if ($vmsnapin -eq $null) {
Add-PSSnapin VMware.VimAutomation.Core
if ($error.Count -eq 0) {
write-and-log $logfilename "PowerCLI VimAutomation.Core Snap-in was successfully enabled." 0 "terse"
}
else{
write-and-log $logfilename "Could not enable PowerCLI VimAutomation.Core Snap-in, exiting script" 1 "terse"
Exit
}
}
else{
write-and-log $logfilename "PowerCLI VimAutomation.Core Snap-in is already enabled" 0 "terse"
}
 
$error.clear()
Connect-VIServer -Server $vcenter_srv -ErrorAction SilentlyContinue 2>&1 > $null
if ($error.count) {
write-and-log $logfilename $error[0].exception $error.count
}
else {
        #measuring execution time is really hip these days.
        $stop_watch = [Diagnostics.Stopwatch]::StartNew()
 
write-and-log $logfilename "vCenter server $vcenter_srv successfully connected" $error.count "full"
        #get event database retention time, we can't find snapshot creators there, if the snapshot is older than that.
        $event_age = get-advancedsetting -entity $vcenter_srv -name "event.maxAge"
        #use get-view to find snapshotted vms with a speed of light!
        $snaps = get-view -ViewType VirtualMachine -Filter @{"snapshot" = ""} -Property Name | % {get-vm -id $_.MoRef | get-snapshot}
if ($($snaps | measure).count){
                #for each of snapshots found - create helper object for the report.
                foreach ($snap in $snaps){
$single_snap_info = New-Object PSObject
$single_snap_info | Add-Member -Name "VMName" -Value $($snap.VM).name -MemberType NoteProperty
$single_snap_info | Add-Member -Name "SnapshotName" -Value $snap.name -MemberType NoteProperty
$single_snap_info | Add-Member -Name "SizeInGB" -Value $("{0:N2}" -f ($snap.SizeGB / 1024)) -MemberType NoteProperty
$single_snap_info | Add-Member -Name "CreatedTime" -Value $($snap.Created.ToString("yyyy-MM-dd@HH:mm:ss")) -MemberType NoteProperty
$search_start_time = $snap.Created.AddMinutes(-10)
$how_old = $now - $snap.Created
$single_snap_info | Add-Member -Name "AgeInDays" -Value $("{0:N2}" -f $how_old.TotalDays) -MemberType NoteProperty
                    #search event database for snapshot creator, use time window from -10 minutes before snapshot creation timestamp up to 20 minutes past this timestamp.
if ($how_old.TotalDays -lt $event_age.Value){
 
$search_finish_time = $search_start_time.AddMinutes(20)
$snap_creation_events = Get-VIEvent -Entity $snap.VM -Start $search_start_time -Finish $search_finish_time -Type Info | where-object {$_.FullFormattedMessage.contains("Create virtual machine snapshot")}
 
try {
$user = $snap_creation_events[0].UserName
} 
catch [System.Exception] {
$user = $snap_creation_events.UserName
}
$single_snap_info | Add-Member -Name "CreatedByLogin" -Value $user -MemberType NoteProperty
$user_info = Find-User($user)
$single_snap_info | Add-Member -Name "CreatedByFullName" -Value $($user_info.name) -MemberType NoteProperty

if ([string]::IsNullOrWhiteSpace($user_info.email) -or [string]::IsNullOrEmpty($user_info.email)) {
if ($user.Contains("DOMAIN\")) {
$user_info.email = $user.Replace("DOMAIN\", "") + "@company.com"
}
if ($user.Contains("DOMAIN\")) {
$user_info.email = $user.Replace("DOMAIN\", "") + "@company.com"
}
}

$single_snap_info | Add-Member -Name "CreatedByEMail" -Value $($user_info.email) -MemberType NoteProperty
$single_snap_info | Add-Member -Name "Snapshot older than" -Value "" -MemberType NoteProperty
}
else {

$single_snap_info | Add-Member -Name "CreatedByLogin" -Value "Unknown" -MemberType NoteProperty
$single_snap_info | Add-Member -Name "CreatedByFullName" -Value "Unknown" -MemberType NoteProperty
$single_snap_info | Add-Member -Name "CreatedByEMail" -Value "" -MemberType NoteProperty
$single_snap_info | Add-Member -Name "Snapshot older than" -Value "Not in vCenter Events Database if over $($event_age.Value) days old" -MemberType NoteProperty
}
$all_snaps_info += $single_snap_info
}
 
            #OK, we've got our report ready, let's search it for people who keep their snapshots longer than our $notify_threshold.
$send_reminders2 = $all_snaps_info | where-object {(([int]$_.AgeInDays) -gt $notify_threshold) -and !(([string]$_.CreatedByLogin).contains("older"))} | sort-object CreatedByLogin -unique
            if ($send_reminders2){
                #for each unique login prepare a message containing list of names of all vms with outdated snapshots (so single e-mail for all snapshots owned by this login).
                foreach ($login in $send_reminders2){
                    $message =""
 
if (![string]::IsNullOrWhiteSpace($login.CreatedByEMail) -or ![string]::IsNullOrEmpty($login.CreatedByEMail)) {
                        #only if there is an e-mail address of course
 
                        $owned_snaps = $all_snaps_info | where-object {(([int]$_.AgeInDays) -gt $notify_threshold) -and ($_.CreatedByLogin -eq $login.CreatedByLogin)} | sort-object VMName -unique
$message = "Hi " + ((([string]$login.CreatedByFullName).split(" "))[0]) + "," + $cr_lf + $cr_lf
$message += ("This is an automated message to notify you that you are the owner of snapshots older than $($notify_threshold) days for the following virtual machines: " + $cr_lf + $cr_lf)
 
foreach ($vm in $owned_snaps) {
$message += ($vm.VMName + $cr_lf)
$message += ("     Age in Days = " + $vm.AgeInDays + $cr_lf)
$message += ("     Created on  = " + $vm.CreatedTime + $cr_lf)
}
 
$message += $cr_lf
$message += ("Please delete these snapshots or contact the Cloud Support team if you need to retain them." + $cr_lf + $cr_lf)
$message += ("Thank You" + $cr_lf)
$message += ("Cloud Support Team" + $cr_lf)
$message += ("IT" + $cr_lf)
$message += ("Company" + $cr_lf)
$message += ("-----------------------------------------------" + $cr_lf)  
$message += "E: CloudAdmin@company.com"   
                    
                        #send the message to snapshot owner, with system admins team on cc.
Send-MailMessage -to $($login.CreatedByEMail) -cc $emailto -from $emailfrom -subject "Outdated VMware snapshots notification for $($login.CreatedByFullName)" -body $message -SmtpServer $smtpserver
}
}
}
 
$all_snaps_info | sort-object -Property VMName | Export-Csv -Path $csvoutfile -NoTypeInformation

$messageadmin = "Hi All," + $cr_lf + $cr_lf
$messageadmin += ("Please see attachement for the current list of active snapshots on $vcenter_srv." + $cr_lf + $cr_lf)
$messageadmin += ("Thank You" + $cr_lf)
$messageadmin += ("Cloud Support Team" + $cr_lf)
$messageadmin += ("IT" + $cr_lf)
$messageadmin += ("Company" + $cr_lf)
$messageadmin += ("-----------------------------------------------" + $cr_lf)  
$messageadmin += "E: CloudAdmin@company.com" 
 
#let's spam sysadmins further.
            Send-mailmessage -to $emailto -cc $emailcc -from $emailfrom -subject "Active snapshots report for $vcenter_srv on $date" -body $messageadmin -Attachments $csvoutfile -SmtpServer $smtpserver
}
else {
            #or inform them there are no snapshots at all.

$messageadmin = "Hi All," + $cr_lf + $cr_lf
$messageadmin += ("There are no active snapshots on $vcenter_srv." + $cr_lf + $cr_lf)
$messageadmin += ("Thank You" + $cr_lf)
$messageadmin += ("Cloud Support Team" + $cr_lf)
$messageadmin += ("IT" + $cr_lf)
$messageadmin += ("Company" + $cr_lf)
$messageadmin += ("-----------------------------------------------" + $cr_lf)  
$messageadmin += "E: CloudAdmin@company.com"

Send-mailmessage -to $emailto -cc $emailcc -from $emailfrom -subject "Active snapshots report for $vcenter_srv on $date" -body $messageadmin -SmtpServer $smtpserver
}
$stop_watch.Stop()
        $elapsed_seconds = ($stop_watch.elapsedmilliseconds)/1000
write-and-log $logfilename "Snapshot report for $vcenter_srv vCenter created in $("{0:N2}" -f $elapsed_seconds) seconds" 0 "full"
}
Disconnect-VIServer -Server $vcenter_srv -Confirm:$false -Force:$true -ErrorAction SilentlyContinue 2>&1 > $null