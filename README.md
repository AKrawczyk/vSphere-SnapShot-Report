# vSphere-SnapShot-Report
PowerShell with PowerCLI script to report on SnapShots
</br>
Modified By: Aaron Krawczyk - Aaron.krawczyk@cit.ie</br>
</br>
#Setup</br>
The PC/Server must have both PowerShell and Vmware PowerCLI installed on it.</br>
</br>
# How to install PowerShell and VMWare PowerCLI</br>
PowerShell comes a part of Windows 7, 8, 10, 2008, 2012 and 2016</br>
Goto VMWare.com and download VMWare PowerCLI 5.5</br>
Install VMWare PowerCLI 5.5</br>
</br>
# How to configure the script</br>
Edit the PowerShell script and enter the informion relevent to your orgisnation</br>
$emailto</br>
$emailcc</br>
$emailfrom</br>
$smtpserver</br>
The section below is used modify admin domain logins and create a valid user email</br>
Edit this section to match orginsations domain and users</br>
if ([string]::IsNullOrWhiteSpace($user_info.email) -or [string]::IsNullOrEmpty($user_info.email)) {</br>
if ($user.Contains("DOMAIN\")) {</br>
$user_info.email = $user.Replace("DOMAIN\", "") + "@company.com"</br>
}</br>
if ($user.Contains("DOMAIN\")) {</br>
$user_info.email = $user.Replace("DOMAIN\", "") + "@company.com"</br>
}</br>
}</br>
</br>
# How to run the script</br>
1. Open Powershell command windows</br>
2. .\snapshot_report.ps1 -vcenter_srv vcenter.company.com</br>
</br>
Log Files</br>
The script will write out information to a log file and CSV.</br>
This will be located in a sub folder of the script called 'SnapReportLogs'.</br>
