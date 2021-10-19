<#  
.SYNOPSIS  
    Custimization script for Azure Image Builder including Microsoft recommneded configuration to be included in a Windows 10 ms Master Image including Office
.
.DESCRIPTION  
    Customization script to build a WVD Windows 10 personal image
    This script configures the Microsoft recommended configuration for a Win10ms image:
        Article:    Prepare and customize a master VHD image 
                    https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image 
        Article: Install Office on a master VHD image 
                    https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image
.
NOTES  
    File Name  : Win10ms_O365.ps1
    Author     : Mathieu Kessler
    Version    : v0.0.1
.
.EXAMPLE
    This script can be used in confuction with an 
.
.DISCLAIMER
    1 - All configuration settings in this script need to be validated and tested in your own environment.
    2 - Ensure to confirm the documentation online has not been updated and therefor might include different settings
    3 - Where possible also the use of Group Policies can be used.
    4 - The below script uses the Write-Host command to allow you to better troubleshoot the activity from within the Packer logs.
    5 - To get more verbose logging of the script remove the | Out-Null at the end of the PowerShell command
#>

Write-Host '*** WVD AIB CUSTOMIZER PHASE **************************************************************************************************'
Write-Host '*** WVD AIB CUSTOMIZER PHASE ***                                                                                            ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** Script: Win10ms_O365.ps1                                                                   ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE ***                                                                                            ***'
Write-Host '*** WVD AIB CUSTOMIZER PHASE **************************************************************************************************'

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** Stop the custimization when Error occurs ***'
$ErroractionPreference='Stop'

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** Set Custimization Script Variables ***'

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG *** Create temp folder for software packages. ***'
New-Item -Path 'C:\temp' -ItemType Directory -Force | Out-Null

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG *** Create tools folder for software packages. ***'
New-Item -Path 'C:\tools' -ItemType Directory -Force | Out-Null

Write-Host '*** WVB AIB CUSTOMIZER PHASE *** MAP Network drive ***'
net use Z: \\azsane06wevdifslogix01.file.core.windows.net\goldenimageapps /u:azure\azsane06wevdifslogix01 0vnpAiOIMjngtZO01H9RBG+qpyE6IoaRfcNhcSBEyaxB8yafn6ks6o1lq2dlJdOSkkPm44PJDINkSy1r1wObzg==   

Write-Host '*** WVB AIB CUSTOMIZER PHASE *** Copy apps to c:\temp ***'
Copy-item -Path "z:\*" -Destination "C:\temp" -Recurse

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** Set up time zone redirection ***'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEnableTimeZoneRedirection' -Value '1' -PropertyType DWORD -Force | Out-Null

#Write-Host '*** WVD AIB CUSTOMIZER PHASE *** SET OS REGKEY *** Disable Storage Sense ***'
#New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense' -Name 'AllowStorageSenseGlobal' -Value '0' -PropertyType DWORD -Force | Out-Null

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG *** PrintNightmare remediations ***'
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Configure M365 Enterprise ***'
Start-Process -FilePath c:\temp\M365\setup.exe -Args '/configure c:\temp\M365\TEN_Azure_VD_personal.xml'
Start-Sleep -Seconds 900

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install AIP Client ***'
Invoke-Expression -Command 'msiexec /i c:\temp\General\AzInfoProtection_UL.msi /quiet'
Start-Sleep -Seconds 40

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install Java ***'
Start-Process -FilePath c:\temp\Java\jre-8u301-windows-x64.exe -ArgumentList INSTALLCFG="c:\temp\Java\jreinstall.cfg"
Start-Sleep -Seconds 180

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIGURE *** Enabling RDP Shortpath ***'
$WinstationsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations'
New-ItemProperty -Path $WinstationsKey -Name 'fUseUdpPortRedirector' -ErrorAction:SilentlyContinue -PropertyType:dword -Value 1 -Force
New-ItemProperty -Path $WinstationsKey -Name 'UdpPortNumber' -ErrorAction:SilentlyContinue -PropertyType:dword -Value 3390 -Force
Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIGURE *** Configure Windows Firewall for Shortpath ***'
New-NetFirewallRule -DisplayName 'Remote Desktop - Shortpath (UDP-In)'  -Action Allow -Description 'Inbound rule for the Remote Desktop service to allow RDP traffic. [UDP 3390]' -Group '@FirewallAPI.dll,-28752' -Name 'RemoteDesktop-UserMode-In-Shortpath-UDP'  -PolicyStore PersistentStore -Profile Domain, Private -Service TermService -Protocol udp -LocalPort 3390 -Program '%SystemRoot%\system32\svchost.exe' -Enabled:True
Start-Sleep -Seconds 15

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install Chrome ***'
Invoke-Expression -Command 'msiexec /i c:\temp\Chrome\googlechromestandaloneenterprise64.msi /quiet'
Start-Sleep -Seconds 180

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install 7Zip x64 ***'
Invoke-Expression -Command 'msiexec /i c:\temp\General\7z1900-x64.msi /qb /norestart'
Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install VLC x64 ***'
Invoke-Expression -Command 'msiexec /i c:\temp\General\vlc-3.0.16-win64.msi /qb'
Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install Notepad++ x64 ***'
Start-Process -FilePath c:\temp\General\npp.8.1.5.Installer.x64.exe -Args '/S'
Start-Sleep -Seconds 90

#Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** MS LAPS x64 ***'
#Invoke-Expression -Command 'msiexec /i c:\temp\General\LAPS.x64.msi ALLUSERS=1 /qb'
#Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install Adobe DC ***'
Start-Process -FilePath C:\temp\Adobe\AcroRdrDC2100720091_en_US.exe -Args '/sAll /rs /rps /msi /norestart /quiet EULA_ACCEPT=YES' -WorkingDirectory 'C:\temp\Adobe' -Wait
Start-Sleep -Seconds 240

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install Adobe DC Standard ***'
Start-Process -FilePath C:\temp\Adobe\AdobeAcrobatDC\Build\setup.exe -Args '--silent' -WindowStyle Hidden
Start-Sleep -Seconds 320
# Install AIP Plugin (Azure Information Protection)
Invoke-Expression -Command 'msiexec /i c:\temp\Adobe\AdobeAcrobatDC\AIPPlugin2100120135_Acr_DC.msi /qn'
Start-Sleep -Seconds 90
# Remove Shortcuts
Remove-Item "C:\Users\Public\Desktop\Adobe Acrobat DC.lnk"
Remove-Item "C:\Users\Public\Desktop\Adobe Creative Cloud.lnk"
Start-Sleep -Seconds 45

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Install ZOOM VDI 5.8.0 ***'
Invoke-Expression -Command 'msiexec /i c:\temp\General\ZoomInstallerVDI.msi /quiet /qn /norestart /log install.log ZNoDesktopShortCut="true"'
Start-Sleep -Seconds 45

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** DWG TrueView 2022 ***'
Start-Process -FilePath c:\temp\AutoDesk\DWGTrueView_2022_English_64bit_dlm.sfx.exe -Args '-suppresslaunch -d C:\temp'
Start-Sleep -Seconds 180
Start-Process -FilePath C:\Temp\DWGTrueView_2022_English_64bit_dlm\setup.exe -Args '-q'
Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Edge WebRuntime2 ***'
Start-Process -FilePath C:\temp\WebView2Runtime\MicrosoftEdgeWebView2RuntimeInstallerX64.exe -Args '/silent /install' -Wait
Start-Sleep -Seconds 45

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Citrix Workspace App 2107 ***'
Start-Process -FilePath C:\temp\Citrix\CitrixWorkspaceApp.exe -Args '/silent /noreboot'
Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Autodesk Design Review 2018 ***'
Start-Process -FilePath "c:\Program Files\7-Zip\7z.exe" -Args 'x c:\temp\AutoDesk\SetupDesignReview.exe -oc:\temp\designreview'
Start-Sleep -Seconds 180
Start-Process -FilePath c:\temp\designreview\setup.exe -Args '/q /t c:\temp\designreview\Setup.ini'
Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** JT2GO ***'
# Download the installer from the Siemens website. Always check for new versions!!
#Invoke-WebRequest -Uri 'https://dl2.plm.automation.siemens.com/jt2go/installer/JT2Go.zip’ -OutFile ‘c:\temp\JT2Go.zip’
#Start-Process -FilePath “c:\Program Files\7-Zip\7z.exe” -Args ‘x c:\temp\JT2Go.zip -oc:\temp\JT2Go’
#Start-Process -FilePath "c:\temp\JT2Go\JT2GoSetup.exe" -Args ‘/S /qb INSTALLTO=\"C:\Program Files\Siemens\JT2Go\" DT_SHORTCUT=0 DISABLE_INTERNET=1 DISABLE_UPDATES=1 JT2GO_PEP_INIT=1’
#Start-Sleep -Seconds 45

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** BeyondTrust Privilege Management ***'
Invoke-Expression -Command 'msiexec /i c:\temp\General\PrivilegeManagementForWindows_x64.msi /qn /norestart CERT_MODE=2 WEBSERVERMODE=1 WSP_URL=https://defpoint.apps.technipenergies.com/privilegeguardconfig.xml WSP_INTERVAL=180 WSP_LOGON=1 DOWNLOADAUDITMODE=3 POLICYPRECEDENCE="WEBSERVER" WSP_CERT="*.apps.technipenergies.com"'
Start-Sleep -Seconds 45

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** FileOpenClient ***'
Start-Process -FilePath c:\temp\General\GLO_FileOpenClient_1.0.63.979.exe -Args '/Verysilent /norestart /closeapplications' -WindowStyle Hidden
Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** INSTALL *** Filezilla ***'
Start-Process -FilePath c:\temp\Filezilla\FileZilla_setup.exe -Args '/S /user=all'
Start-Sleep -Seconds 90

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CUSTOMIZATION *** TechnipENG backgrounds ***'
Copy-Item "C:\temp\GLO_TechnipEnergiesBranding_1.0\User.png" "C:\ProgramData\Microsoft\User Account Pictures\User.png"
Copy-Item "C:\temp\GLO_TechnipEnergiesBranding_1.0\User-32.png" "C:\ProgramData\Microsoft\User Account Pictures\User-32.png"
Copy-Item "C:\temp\GLO_TechnipEnergiesBranding_1.0\User-40.png" "C:\ProgramData\Microsoft\User Account Pictures\User-40.png"
Copy-Item "C:\temp\GLO_TechnipEnergiesBranding_1.0\User-48.png" "C:\ProgramData\Microsoft\User Account Pictures\User-48.png"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\User-192.png" "C:\ProgramData\Microsoft\User Account Pictures\User-192.png"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\User-200.png" "C:\ProgramData\Microsoft\User Account Pictures\User-200.png"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\User.bmp" "C:\ProgramData\Microsoft\User Account Pictures\User.bmp"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\Guest.bmp" "C:\ProgramData\Microsoft\User Account Pictures\Guest.bmp"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\Guest.png" "C:\ProgramData\Microsoft\User Account Pictures\Guest.png"
#New-Item -ItemType "directory" -Path "C:\windows\System32\oobe"
New-Item -ItemType "directory" -Path "C:\windows\System32\oobe\info"
New-Item -ItemType "directory" -Path "C:\windows\System32\oobe\info\backgrounds"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\wallpaper.jpg" "C:\windows\web\wallpaper\Windows\wallpaper.jpg"
#Rename-Item -Path "C:\Windows\System32\oobe\info\backgrounds\backgrounddefault.jpg" -NewName "backgrounddefault.jpg.old"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\backgrounddefault.jpg" "C:\Windows\System32\oobe\info\backgrounds\backgrounddefault.jpg"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\background1280x1024.jpg" "C:\Windows\System32\oobe\info\backgrounds\background1280x1024.jpg"
Copy-Item "c:\temp\GLO_TechnipEnergiesBranding_1.0\backgrounddefault_3600.jpg" "C:\Windows\System32\oobe\info\backgrounds\backgrounddefault_3600.jpg"
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'LockScreenImage' -Value 'C:\Windows\System32\oobe\info\Backgrounds\BackgroundDefault.jpg' -PropertyType String -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'LockScreenOverlaysDisabled' -Value '1' -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoChangingLockScreen' -Value '1' -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value '1' -PropertyType DWord -Force | Out-Null


Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG *** Update Deprovision.ps1. ***'
#Get-Content -path C:\DeprovisioningScript.ps1 -Raw -replace 'Sysprep.exe /oobe /generalize /quiet /quit','Sysprep.exe /oobe /generalize /quit /mode:vm'
#Set-Content -Path C:\DeprovisioningScript.ps1
Copy-Item "c:\temp\DeprovisioningScript.ps1" "C:\DeprovisioningScript.ps1"
Start-Sleep -Seconds 45

Write-Host '*** WVD AIB CUSTOMIZER PHASE *** CONFIG *** Deleting temp folder. ***'
Get-ChildItem -Path 'C:\temp' -Recurse | Remove-Item -Recurse -Force
Remove-Item -Path 'C:\temp' -Force | Out-Null

Write-Host '*** WVD AIB CUSTOMIZER PHASE ********************* END *************************'
