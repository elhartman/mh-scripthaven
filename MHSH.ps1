Import-Module Microsoft.Powershell.LocalAccounts
$scriptpath = $MyInvocation.MyCommand.Path
$dir = Split-Path $scriptpath
Push-Location $dir

# ----------------------------------------------------------
# BEGIN FUNCTIONS
# ----------------------------------------------------------

function disableSubscribedContent{
    Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

    Write-Output "Elevating priviledges for this process"
    do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

    Write-Output "Disabling automatic downloading and installing of subscribed content"
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "FeatureManagementEnabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContentEnabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-314559Enabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338393Enabled" 0
    Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0

    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")
    { Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2 }

    if(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")
    { Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1 }



}
function disableSubscribedContentCheck{
    if(-Not (Test-Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"))
    {
        # If ContentDeliveryManager doesn't exist it's likely not supported by the OS
        exit 2 
    }

    try
    {
        $prop = Get-ItemPropertyValue "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContentEnabled" 
    }
    catch
    {
        # If SubscribedContentEnabled value doesn't exist assume it's turned on
        exit 0
    }

    if($prop -eq 0)
    {
        # Function is disabled if set to 0
        exit 1
    }

    exit 0



}
function progress($seconds){
    $doneDT = (Get-Date).AddSeconds($seconds)
    while($doneDT -gt (Get-Date)) {
        $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
        $percent = ($seconds - $secondsLeft) / $seconds * 100
        Write-Progress -Activity "Waiting..." -Status "Preparing for next copy..." -SecondsRemaining $secondsLeft -PercentComplete $percent
        [System.Threading.Thread]::Sleep(500)
    }
    Write-Progress -Activity "Waiting..." -Status "Preparing for next copy..." -SecondsRemaining 0 -Completed
}


function massWProfileMigration{
    $theList = @()
    $counter = 0
    $skip = 0
    Write-Host "If you did not read the readme.md, do not proceed until you have thoroughly inspected the document readme.md."
    $destination = Read-Host -prompt "Provide the precise directory to which backups will be copied"

    While($skip -eq 0){
        $entry = Read-Host -prompt "Enter hostname (leave blank to proceed)"
        $theList += $entry

        if($entry -ne ""){
            $counter = $counter + 1
            Write-Host "Host $entry added"
        }

        else{
            $skip = 1
            Write-Host "Preparing to copy files to $destination"
            Start-Sleep 5
        }
    }   
    $param = $theList.length + 1

    for ($i=0; $i -le $theList.length; $i++){
        $pullfrom = "\\"+$theList[$i]+"\migrate\Users\"
        Write-Host "Pulling from: $pullfrom"
        $goto = $destination+"\"+$theList[$i]
        Write-Host "Writing to: $goto"
        Robocopy.exe $pullfrom $goto /xd `"Application Data`" /xd `"Appdata`" /xd `"Public`" /x `"Local Settings`" /xd `"All Users`" /xd `"Default`" /xd `"lftadmin`" /xd `"csiadmin`" /s /r:1 /w:5
        progress 60
    }

    Read-Host "Process complete. Press <enter> key to quit..."
}


function removeOneDrive{
    #   Description:
    # This script will remove and disable OneDrive integration.
    Import-Module -DisableNameChecking $PSScriptRoot\..\lib\force-mkdir.psm1
    Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

    Write-Output "Kill OneDrive process"
    taskkill.exe /F /IM "OneDrive.exe"
    taskkill.exe /F /IM "explorer.exe"

    Write-Output "Remove OneDrive"
    if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
    }
    if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
    }

    Write-Output "Removing OneDrive leftovers"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
    # check if directory is empty before removing:
    If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
    }

    Write-Output "Disable OneDrive via Group Policies"
    force-mkdir "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
    Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

    Write-Output "Remove Onedrive from explorer sidebar"
    New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
    mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    Remove-PSDrive "HKCR"

    Write-Output "Removing run hook for new users"
    reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
    reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
    reg unload "hku\Default"

    Write-Output "Removing startmenu entry"
    Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

    Write-Output "Removing scheduled task"
    Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

    Write-Output "Restarting explorer"
    Start-Process "explorer.exe"

    Write-Output "Waiting for explorer to complete loading"
    Start-Sleep 10

    Write-Output "Removing additional OneDrive leftovers"
    foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
        Takeown-Folder $item.FullName
        Remove-Item -Recurse -Force $item.FullName
    }
}


function removeOneDriveCheck{
    $odpath = Get-ItemPropertyValue "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive" "CurrentVersionPath" -ErrorAction SilentlyContinue
    if (Test-Path -Path $odpath -PathType Container)
    { exit 0 }

    $res = Get-ItemPropertyValue "Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue
    if ($res -gt 0)
    { exit 0 }

    $res2 = Get-ItemPropertyValue "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue
    if ($res2 -gt 0)
    { exit 0 }

    exit 1
}


function pushCurrentDir{
    Import-Module Microsoft.Powershell.LocalAccounts
    $scriptpath = $MyInvocation.MyCommand.Path
    $dir = Split-Path $scriptpath
    Push-Location $dir
}

function installDependencies{
    Write-Host "Installing Winget dependencies... New window will launch..."
    .\data\winget-pkg.msixbundle
}

function feelingLuckySetup{
    #computer rename
    $rename = Read-Host -prompt "Rename computer (leave blank to skip)"

    if($rename -ne ""){
          $curName = $Env:COMPUTERNAME
          Rename-Computer -ComputerName "$curName" -NewName "$rename"
    }
    else{
        Write-Host "Rename skipped..."
    }

    #set timezone to est
    Set-TimeZone -Id 'Eastern Standard Time'
    #disable sleep
    PowerCfg /Change standby-timeout-ac 0
    PowerCfg /Change standby-timeout-dc 0
    #enable net discovery
    netsh advfirewall firewall set rule group=”network discovery” new enable=yes
    #disable Ms. Cortana
    $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"     
    if(!(Test-Path -Path $path)) {  
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Windows Search" 
    }  
    Set-ItemProperty -Path $path -Name "AllowCortana" -Value 1  
    Stop-Process -name explorer
    #attempt to disable UAC
    Try{
        reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f}
    Catch{
        Write-Host "User account control could not be disabled. Please disable manually..."
        Start-Sleep 2
        control
    }
    Write-Host "Attempts made to disable sleep, adjust timezone, enable network discovery, disable cortana, and disable UAC."
    Start-Sleep 2
    Write-Host "Installing basic desktop applications..."
    
    winget install mozilla.firefox --accept-package-agreements --accept-source-agreements
    winget install google.chrome --accept-package-agreements --accept-source-agreements
    winget install 7zip.7zip --accept-package-agreements --accept-source-agreements
    winget install adobe.acrobat.reader.64-bit --accept-package-agreements --accept-source-agreements

    Write-Host "If the above resulted in error, try running 'INSTALL DEPENDENCIES' from the Script Hub first."
    Start-Sleep 2
    Write-Host "Microsoft Office Apps for Business will continue to install in the background..."

    .\data\office\setup.exe /configure .\office\standard-365-deploy.xml

    Write-Host "Next Steps: Run all available Windows updates. After the next reboot, remember to install Kaseya VSA Agent and additional required programs."

    Start-Sleep 5
    
    Read-Host "Press <Enter> key to close this window..."
    Exit
}


function exportProfileInformation{
    $curname = $Env:COMPUTERNAME
    Write-Host "`"PC Info`" (currently) includes Mapped Drive data, and Configured Printers."
    $drive = Read-Host -prompt "Enter drive letter to export PC info to"
    $ctr = 0

    New-Item -ItemType Directory -Force -Path $drive':\'$curName | Out-Null
    Get-Printer | Format-List -Property Name,DriverName,PortName,Shared | Out-File -FilePath $drive':\'$curName'-Printers.txt'
    $ctr++

    net use >> $drive'`:\'$curName'-MappedDrives.txt'
    $ctr++



    Write-Host "Exported ($ctr) text files successfully to $drive`:\"
    Start-Sleep 3
}


function exportADUsersList{
    Import-Module ActiveDirectory

    $Groups = (Get-AdGroup -filter * | Where {$_.name -like "**"} | select name -expandproperty name)
    $Table = @()
    $Record = @{
    "Group Name" = ""
    "Name" = ""
    "Username" = ""
    }

    Foreach ($Group in $Groups)
    {

    $Arrayofmembers = Get-ADGroupMember -identity $Group -recursive | select name,samaccountname

    foreach ($Member in $Arrayofmembers)
    {
    $Record."Group Name" = $Group
    $Record."Name" = $Member.name
    $Record."UserName" = $Member.samaccountname
    $objRecord = New-Object PSObject -property $Record
    $Table += $objrecord

    }

    }

    $Table | export-csv "C:\SecurityGroups.csv" -NoTypeInformation
}


function resetWindowsUpdate {
    <#
    .SYNOPSIS
    Reset-WindowsUpdate.ps1 - Resets the Windows Update components
    .DESCRIPTION 
    This script will reset all of the Windows Updates components to DEFAULT SETTINGS.

    .OUTPUTS
    Results are printed to the console. Future releases will support outputting to a log file. 
    #>

    $arch = Get-WMIObject -Class Win32_Processor -ComputerName LocalHost | Select-Object AddressWidth

    Write-Host "1. Stopping Windows Update Services..."
    Stop-Service -Name BITS
    Stop-Service -Name wuauserv
    Stop-Service -Name appidsvc
    Stop-Service -Name cryptsvc

    Write-Host "2. Remove QMGR Data file..."
    Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue

    Write-Host "3. Renaming the Software Distribution and CatRoot Folder..."
    Rename-Item $env:systemroot\SoftwareDistribution SoftwareDistribution.bak -ErrorAction SilentlyContinue
    Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue

    Write-Host "4. Removing old Windows Update log..."
    Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue

    Write-Host "5. Resetting the Windows Update Services to defualt settings..."
    "sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
    "sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"

    Set-Location $env:systemroot\system32

    Write-Host "6. Registering some DLLs..."
    regsvr32.exe /s atl.dll
    regsvr32.exe /s urlmon.dll
    regsvr32.exe /s mshtml.dll
    regsvr32.exe /s shdocvw.dll
    regsvr32.exe /s browseui.dll
    regsvr32.exe /s jscript.dll
    regsvr32.exe /s vbscript.dll
    regsvr32.exe /s scrrun.dll
    regsvr32.exe /s msxml.dll
    regsvr32.exe /s msxml3.dll
    regsvr32.exe /s msxml6.dll
    regsvr32.exe /s actxprxy.dll
    regsvr32.exe /s softpub.dll
    regsvr32.exe /s wintrust.dll
    regsvr32.exe /s dssenh.dll
    regsvr32.exe /s rsaenh.dll
    regsvr32.exe /s gpkcsp.dll
    regsvr32.exe /s sccbase.dll
    regsvr32.exe /s slbcsp.dll
    regsvr32.exe /s cryptdlg.dll
    regsvr32.exe /s oleaut32.dll
    regsvr32.exe /s ole32.dll
    regsvr32.exe /s shell32.dll
    regsvr32.exe /s initpki.dll
    regsvr32.exe /s wuapi.dll
    regsvr32.exe /s wuaueng.dll
    regsvr32.exe /s wuaueng1.dll
    regsvr32.exe /s wucltui.dll
    regsvr32.exe /s wups.dll
    regsvr32.exe /s wups2.dll
    regsvr32.exe /s wuweb.dll
    regsvr32.exe /s qmgr.dll
    regsvr32.exe /s qmgrprxy.dll
    regsvr32.exe /s wucltux.dll
    regsvr32.exe /s muweb.dll
    regsvr32.exe /s wuwebv.dll

    Write-Host "7) Removing WSUS client settings..."
    REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f
    REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f
    REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f

    Write-Host "8) Resetting the WinSock..."
    netsh winsock reset
    netsh winhttp reset proxy

    Write-Host "9) Delete all BITS jobs..."
    Get-BitsTransfer | Remove-BitsTransfer

    Write-Host "10) Attempting to install the Windows Update Agent..."
    if($arch -eq 64){
        wusa Windows8-RT-KB2937636-x64 /quiet
    }
    else{
        wusa Windows8-RT-KB2937636-x86 /quiet
    }

    Write-Host "11) Starting Windows Update Services..."
    Start-Service -Name BITS
    Start-Service -Name wuauserv
    Start-Service -Name appidsvc
    Start-Service -Name cryptsvc

    Write-Host "12) Forcing discovery..."
    wuauclt /resetauthorization /detectnow

    Write-Host "Process complete. Please reboot your computer."
}


function smbDomainJoinFix {
    $getsmb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    $getsmb7 = Get-WindowsFeature FS-SMB1

    Write-Host("ATTENTION: Script is designed for use with Windows XP thru 10. You WILL see an initial error message. If you see this message, but get the below prompt, disregard the single error above.`n")

    $domain = Read-Host -Prompt "Input name of domain to join..."

    if($getsmb.state -eq "Disabled"){
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
        Add-Computer -domainname $domain -restart
    }

    elseif($getsmb.state -eq "Enabled"){
        write-host("smb already enabled")
        Add-Computer -domainname $domain -restart
    }

    elseif($getsmb7.state -eq "Disabled"){
        Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol
        Add-Computer -domainname $domain -restart
    }
}

# ----------------------------------------------------------
# END FUNCTIONS
# BEGIN GUI
# ----------------------------------------------------------


Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Scripthaven                     = New-Object system.Windows.Forms.Form
$Scripthaven.ClientSize          = '635,420'
$Scripthaven.text                = "MHSH Script Haven"
$Scripthaven.BackColor           = "#925656"
$Scripthaven.TopMost             = $false

$eztag                          = New-Object system.Windows.Forms.Label
$eztag.text                     = "Hover a selection for information."
$eztag.AutoSize                 = $true
$eztag.width                    = 25
$eztag.height                   = 10
$eztag.forecolor                = "#FFFFFF"
$eztag.location                 = New-Object System.Drawing.Point(10,10)
$eztag.Font                     = 'Microsoft Sans Serif,13'

$inofficesetuptool               = New-Object system.Windows.Forms.Button
$inofficesetuptool.BackColor     = "#ffffff"
$inofficesetuptool.text          = "In-Office Setup Tool"
$inofficesetuptool.width         = 181
$inofficesetuptool.height        = 30
$inofficesetuptool.location      = New-Object System.Drawing.Point(20,325)
$inofficesetuptool.Font          = 'Microsoft Sans Serif,12'

$onsitesetuptool                 = New-Object system.Windows.Forms.Button
$onsitesetuptool.BackColor       = "#ffffff"
$onsitesetuptool.text            = "Onsite Setup Tool"
$onsitesetuptool.width           = 181
$onsitesetuptool.height          = 30
$onsitesetuptool.location        = New-Object System.Drawing.Point(20,375)
$onsitesetuptool.Font            = 'Microsoft Sans Serif,12'

$smb1domainjoinfix               = New-Object system.Windows.Forms.Button
$smb1domainjoinfix.BackColor     = "#ffffff"
$smb1domainjoinfix.text          = "SMB1 Domain Join Fix"
$smb1domainjoinfix.width         = 181
$smb1domainjoinfix.height        = 30
$smb1domainjoinfix.location      = New-Object System.Drawing.Point(435,375)
$smb1domainjoinfix.Font          = 'Microsoft Sans Serif,12'

$installDep               = New-Object system.Windows.Forms.Button
$installDep.BackColor     = "#ffffff"
$installDep.text          = "Install Dependencies"
$installDep.width         = 181
$installDep.height        = 30
$installDep.location      = New-Object System.Drawing.Point(20,328)
$installDep.Font          = 'Microsoft Sans Serif,11'

$feelingluckysetup               = New-Object system.Windows.Forms.Button
$feelingluckysetup.BackColor     = "#ffffff"
$feelingluckysetup.text          = "New Configuration"
$feelingluckysetup.width         = 181
$feelingluckysetup.height        = 30
$feelingluckysetup.location      = New-Object System.Drawing.Point(20,375)
$feelingluckysetup.Font          = 'Microsoft Sans Serif,11'

$exportpcdata               = New-Object system.Windows.Forms.Button
$exportpcdata.BackColor     = "#ffffff"
$exportpcdata.text          = "Export PC Information"
$exportpcdata.width         = 181
$exportpcdata.height        = 30
$exportpcdata.location      = New-Object System.Drawing.Point(435,325)
$exportpcdata.Font          = 'Microsoft Sans Serif,12'

$netreset               = New-Object system.Windows.Forms.Button
$netreset.BackColor     = "#ffffff"
$netreset.text          = "Network Reset"
$netreset.width         = 181
$netreset.height        = 30
$netreset.location      = New-Object System.Drawing.Point(435,275)
$netreset.Font          = 'Microsoft Sans Serif,12'

$winupdatereset               = New-Object system.Windows.Forms.Button
$winupdatereset.BackColor     = "#ffffff"
$winupdatereset.text          = "Reset Windows Update"
$winupdatereset.width         = 181
$winupdatereset.height        = 30
$winupdatereset.location      = New-Object System.Drawing.Point(435,225)
$winupdatereset.Font          = 'Microsoft Sans Serif,11.5'

$groupinfo               = New-Object system.Windows.Forms.Button
$groupinfo.BackColor     = "#ffffff"
$groupinfo.text          = "Output AD Users"
$groupinfo.width         = 181
$groupinfo.height        = 30
$groupinfo.location      = New-Object System.Drawing.Point(435,175)
$groupinfo.Font          = 'Microsoft Sans Serif,12'

$removeonedrive               = New-Object system.Windows.Forms.Button
$removeonedrive.BackColor     = "#ffffff"
$removeonedrive.text          = "Uninstall OneDrive"
$removeonedrive.width         = 181
$removeonedrive.height        = 30
$removeonedrive.location      = New-Object System.Drawing.Point(435,125)
$removeonedrive.Font          = 'Microsoft Sans Serif,12'

$disablesubcontent               = New-Object system.Windows.Forms.Button
$disablesubcontent.BackColor     = "#ffffff"
$disablesubcontent.text          = "Disable Subscribed Content"
$disablesubcontent.width         = 181
$disablesubcontent.height        = 30
$disablesubcontent.location      = New-Object System.Drawing.Point(435,75)
$disablesubcontent.Font          = 'Microsoft Sans Serif,9.5'

$massmigration               = New-Object system.Windows.Forms.Button
$massmigration.BackColor     = "#ffffff"
$massmigration.text          = "BM Mass Migration"
$massmigration.width         = 181
$massmigration.height        = 30
$massmigration.location      = New-Object System.Drawing.Point(226,375)
$massmigration.Font          = 'Microsoft Sans Serif,12'


# LEAVE COMMENTED UNLESS USING LEGACY VERSION
# . .\data\func.ps1
# LEAVE COMMENTED UNLESS USING LEGACY VERSION


$Scripthaven.controls.AddRange(@($eztag,$installdep,$feelingluckysetup,$massmigration,$disablesubcontent,$removeonedrive,$groupinfo,$winupdatereset,$netreset,$exportpcdata,$smb1domainjoinfix))

$smb1domainjoinfix.Add_Click({smbDomainJoinFix})
$installDep.Add_Click({installDependencies})
$feelingluckysetup.Add_Click({feelingLuckySetup})
$exportpcdata.Add_Click({exportProfileInformation})
$netreset.Add_Click({})
$winupdatereset.Add_Click({resetWindowsUpdate})
$groupinfo.Add_Click({exportADUsersList})
$removeonedrive.Add_Click({removeOneDrive})
$disablesubcontent.Add_Click({disableSubscribedContent})
$massmigration.Add_Click({massWProfileMigration})

$Scripthaven.Add_MouseEnter({$eztag.text = "Hover a selection for information." })

$exportpcdata.Add_MouseEnter({$eztag.text = "Export mapped drive and configured printers information."})
$feelingluckysetup.Add_MouseEnter({$eztag.text = "One-click new PC setup, disables sleep settings and cortana, installs basic applications. Sets timezone to EST."})
$inofficesetuptool.Add_MouseEnter({$eztag.text = "Launch the full in-office setup wizard."})
$onsitesetuptool.Add_MouseEnter({$eztag.text = "Launch the onsite setup/migration wizard."})
$smb1domainjoinfix.Add_MouseEnter({$eztag.text = "Fix for cannot join domain with SMB1 disabled issue. Enables SMB1`nand walks you through joining the domain."})
$netreset.Add_MouseEnter({$eztag.text = "Runs flushdns, release, and renew. 15 second intervals between`nprocessing commands."})
$winupdatereset.Add_MouseEnter({$eztag.text = "Resets all of the Windows Updates components to`nDEFAULT SETTINGS."})
$groupinfo.Add_MouseEnter({$eztag.text = "Outputs a list of all users in an Active Directory and their respective`ngroup permissions. To be run on the DC."})
$removeonedrive.Add_MouseEnter({$eztag.text = "Completely uninstalls OneDrive from the PC."})
$disablesubcontent.Add_MouseEnter({$eztag.text = "Disables all pre-installed bloatware, games, and applications that comes with`nnew PCs."})
$massmigration.Add_MouseEnter({$eztag.text = "Migrates user files (excluding Appdata, Local Settings, etc.) from any`namount of endpoints to one designated location."})

Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$Scripthaven.FormBorderStyle = 'Fixed3D'
$Scripthaven.MaximizeBox = $false
$Scripthaven.ShowDialog() 
