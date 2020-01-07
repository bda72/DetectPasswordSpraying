<# 
.SYNOPSIS
DetectPasswordSpraying.ps1 - Detects potential password spraying attempts

.DESCRIPTION 
Find potential password spraying attempts based on the number of current users with a badPwdCount in the past X minutes, log users and send email

.OUTPUTS
Results are saved at each run to a time-stamped CSV file. There is also a daily log file where the quantity of AD accounts with a badPwdCount of at least '1' are wrtten in a time-stamped entry.

.EXAMPLE
./DetectPasswordSpraying.ps1
This script is designed to run as a scheduled task. Change the variables in the GLOBALS section and execute the script.

.NOTES
Written by Brian D. Arnold

Change Log:
2019-11-03 Initial version
2019-11-10 Started creating a CSV at every run instead of only when threshold is crossed. Average CSV size is below a few KB.
2019-11-11 Added a second attachment to alert emails of the daily history log file to show a pattern. Added file cleanup section at the end.
#>

###############
##### PRE #####
###############

# Script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Start Transcript
If( -not (Test-Path "$scriptDir\Transcripts")){New-Item -ItemType Directory -Path "$scriptDir\Transcripts"}
Start-Transcript -Path ("$scriptDir\Transcripts\{0:yyyyMMdd}_Log.txt"  -f $(get-date)) -Append

# Create Results folder if missing
If( -not (Test-Path "$scriptDir\Results")){New-Item -ItemType Directory -Path "$scriptDir\Results"}

###################
##### GLOBALS #####
###################

# SMTP Settings
$smtpServer = "smtp.contoso.com"
$smtpFrom = "AD Alert <server-01@contoso.com>"
$smtpTo = "user@contoso.com"
$messageSubject = "Potential Password Spraying Detected"

# Time variables
$Minutes = 5 #how far back to include bad password counts
$CurrDate = (Get-Date).AddMinutes(-$minutes).ToFileTime()
$Date = Get-Date -F "yyyy-MM-dd_HHmm" #date and time for attachment name
$LogDate = Get-Date -F "yyyy-MM-dd" #date and time for log file
$CleanupDate = (Get-Date).AddDays(-60) #how many days of files to keep

# Number of users with a badPwdCount that generates an alert
$Alert = "1"

# File variables
$ResultsFile = "$scriptDir\Results\ADUsers-badPwdCount_$Date.csv"
$HistoryFile = "$scriptDir\Results\ADUsers-badPwdCount_History_$LogDate.txt"

# Folder vaiables
$LogFolder = "$scriptDir\Results"

################
##### MAIN #####
################

# Get PDC Emulator which holds all bad password counts
$PDC = Get-ADDomain | Select-Object -ExpandProperty PDCEmulator

# Get all bad password counts above zero that happened in the past X minutes
$Results = Get-ADUser -Filter "(badPwdCount -ge '1') -AND (badPasswordTime -ge $CurrDate)" -Properties badPwdCount,badPasswordTime,description,physicalDeliveryOfficeName,company,LockedOut,lockoutTime -Server $PDC `
 | Select Name,badPwdCount,@{n='badPasswordTime';e={[DateTime]::FromFileTime($_.badPasswordTime)}},@{n="Enabled";e={$_.enabled}},@{n="Locked Out";e={$_.LockedOut}},`
 @{n='Lockout Time';e={[DateTime]::FromFileTime($_.lockoutTime) -replace '12/31/1600 7:00:00 PM','N/A'}},@{n="Description";e={$_.description}},@{n="Office";e={$_.physicalDeliveryOfficeName}},@{n="Company";e={$_.company}} | Sort badPasswordTime -Descending

# Write count to a log to keep a history
(Get-Date -F "yyyy-MM-dd HH:mm") + " - " + ($Results | Measure-Object).count + " Users" >> $HistoryFile

# Export to CSV for attachment
$Results | Export-csv -Path $ResultsFile -NoTypeInformation

if($Results.count -ge $Alert){

$Messagebody = @"
<font face='arial'>
<B>$(($Results | Measure-Object).count)</B> user accounts had a logon failure due to bad password within the past $Minutes minutes. An unusually high amount of users with a bad password in a short period of time could indicate a password spraying attack. The alert threshold in this script is set to <B>$Alert</B> users.
<ul style="list-style-type:disc;">
  <li>A failed logon increases the <b>badPwdCount</B> attribute by one and updates the <B>badPasswordTime</B> attribute.</li>
  <li>The last two passwords in a user's password history do <u>NOT</u> increase the <b>badPwdCount</B> attribute.</li>
  <li>A successful login clears the <b>badPwdCount</B> attribute but not the <B>badPasswordTime</B> attribute.</li>
</ul>
</font>
"@
 
# HTML Style Settings
    $style = "
        <style>
        BODY{font-family: Arial; font-size: 10pt;}
        TABLE{border: 1px solid black; border-collapse: collapse; background-color: #DCDFDF;}
        TH{border: 1px solid white; background: #7FB1B3; padding: 5px;}
        TD{colspan=12; align=center}
        TD{border: 1px solid white; padding: 5px;}
        </style>
        "
# Send email
$message = New-Object System.Net.Mail.MailMessage $smtpfrom, $smtpto
$message.Subject = $messageSubject
$message.IsBodyHTML = $true
$message.Body = $messagebody + ($Results | ConvertTo-Html -Head $style)
$attachment = New-Object Net.Mail.Attachment($ResultsFile)
$attachment2 = New-Object Net.Mail.Attachment($HistoryFile)
$message.Attachments.Add($attachment)
$message.Attachments.Add($attachment2)
$smtp = New-Object Net.Mail.SmtpClient($smtpServer)
$smtp.Send($message)

$attachment.Dispose();
$attachment2.Dispose();
$message.Dispose();
}

################
##### POST #####
################

# Clear variables
Clear-Variable Results,ResultsFile

# Delete files over X days old to manage folder size
Get-ChildItem -Path $LogFolder -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $CleanupDate } | Remove-Item -Force