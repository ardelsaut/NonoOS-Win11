#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string[]]
	$Functions
)
    Start-Transcript -Path "$env:USERPROFILE\Desktop\Log-Installation-Script-Win11.txt" -Force

Clear-Host
$Host.UI.RawUI.WindowTitle = "Sophia Script for Windows 11 v6.0.13 | Made with $([char]::ConvertFromUtf32(0x1F497)) of Windows | $([char]0x00A9) farag & Inestic, 2014$([char]0x2013)2022"
Remove-Module -Name Sophia -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Manifest\Sophia.psd1 -PassThru -Force
Import-LocalizedData -BindingVariable Global:Localization -FileName Sophia -BaseDirectory $PSScriptRoot\Localizations
if ($Functions)
{
	Invoke-Command -ScriptBlock {Checkings}
	foreach ($Function in $Functions)
	{
		Invoke-Expression -Command $Function
	}
	Invoke-Command -ScriptBlock {RefreshEnvironment; Errors}
	exit
}
Checkings -Warning



#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################


# Create a restore point
CreateRestorePoint

# Disable the "Connected User Experiences and Telemetry" service (DiagTrack), and block the connection for the Unified Telemetry Client Outbound Traffic
DiagTrackService -Disable

# Set the diagnostic data collection to minimum
DiagnosticDataLevel -Minimal

# Turn off the Windows Error Reporting
ErrorReporting -Disable

# Change the feedback frequency to "Never"
FeedbackFrequency -Never

# Turn off the diagnostics tracking scheduled tasks
ScheduledTasks -Disable

# Do not use sign-in info to automatically finish setting up device after an update
# SigninInfo -Disable
# SigninInfo -Enable

# Do not let websites provide locally relevant content by accessing language list
LanguageListAccess -Disable

# Do not let apps show me personalized ads by using my advertising ID
AdvertisingID -Disable

# Hide the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested
WindowsWelcomeExperience -Hide
# WindowsWelcomeExperience -Show

# Get tips and suggestions when I use Windows (default value)
# WindowsTips -Enable
WindowsTips -Disable

# Hide from me suggested content in the Settings app
SettingsSuggestedContent -Hide

# Turn off automatic installing suggested apps
AppsSilentInstalling -Disable

# Disable suggestions on how I can set up my device
WhatsNewInWindows -Disable

# Don't let Microsoft use your diagnostic data for personalized tips, ads, and recommendations
TailoredExperiences -Disable

# Disable Bing search in the Start Menu
BingSearch -Disable

# Show the "This PC" icon on Desktop
ThisPC -Show
# ThisPC -Hide

# Enable the Windows 10 File Explorer
Windows10FileExplorer -Enable
# Windows10FileExplorer -Disable

# Do not use item check boxes
# CheckBoxes -Disable
CheckBoxes -Enable

# Show hidden files, folders, and drives
# HiddenItems -Enable
HiddenItems -Disable

# Show the file name extensions
FileExtensions -Show

# Show folder merge conflicts
MergeConflicts -Show

# Open File Explorer to "This PC"
OpenFileExplorerTo -ThisPC
# OpenFileExplorerTo -QuickAccess

# Disable the File Explorer compact mode (default value)
FileExplorerCompactMode -Disable

# Do not show sync provider notification within File Explorer
OneDriveFileExplorerAd -Hide

# When I snap a window, do not show what I can snap next to it
# SnapAssist -Disable
SnapAssist -Enable

# Show snap layouts when I hover over a windows's maximaze button (default value)
SnapAssistFlyout -Enable

# Show the file transfer dialog box in the detailed mode
FileTransferDialog -Detailed
# FileTransferDialog -Compact

# Display the recycle bin files delete confirmation dialog
RecycleBinDeleteConfirmation -Enable

# Hide recently used files in Quick access
QuickAccessRecentFiles -Hide
QuickAccessFrequentFolders -Hide

# Set the taskbar alignment to the left
TaskbarAlignment -Left
# TaskbarAlignment -Center

# Hide the search button from the taskbar
TaskbarSearch -Hide

# Hide the Task view button from the taskbar
# TaskViewButton -Hide
TaskViewButton -Show

# Hide the widgets icon on the taskbar
TaskbarWidgets -Hide

# Hide the Chat icon (Microsoft Teams) on the taskbar
TaskbarChat -Hide

# Unpin the "Microsoft Edge", "Microsoft Store" shortcuts from the taskbar
UnpinTaskbarShortcuts -Shortcuts Edge, Store

# View the Control Panel icons by large icons
# ControlPanelView -LargeIcons
# ControlPanelView -SmallIcons
ControlPanelView -Category

# Set the default Windows mode to dark
WindowsColorMode -Dark
AppColorMode -Dark

# Hide first sign-in animation after the upgrade
FirstLogonAnimation -Disable

# Set the quality factor of the JPEG desktop wallpapers to maximum
JPEGWallpapersQuality -Max

# Start Task Manager in the expanded mode
TaskManagerWindow -Expanded

# Notify me when a restart is required to finish updating
RestartNotification -Hide

# Do not add the "- Shortcut" suffix to the file name of created shortcuts
# ShortcutsSuffix -Disable
ShortcutsSuffix -Enable

# Use the Print screen button to open screen snipping
# PrtScnSnippingTool -Enable
PrtScnSnippingTool -Disable

# Let me use a different input method for each app window
# AppsLanguageSwitch -Enable
AppsLanguageSwitch -Disable

# When I grab a windows's title bar and shake it, minimize all other windows
AeroShaking -Enable

# Uninstall OneDrive. The OneDrive user folder won't be removed
OneDrive -Uninstall
# OneDrive -Install

# Turn on Storage Sense
StorageSense -Enable
StorageSenseFrequency -Month
# StorageSenseFrequency -Default

# Turn on automatic cleaning up temporary system and app files
StorageSenseTempFiles -Enable

# Disable hibernation. Do not recommend turning it off on laptops
# Hibernation -Disable
Hibernation -Enable

# Change the %TEMP% environment variable path to %SystemDrive%\Temp
# TempFolder -SystemDrive

# Change %TEMP% environment variable path to %LOCALAPPDATA%\Temp (default value)
# TempFolder -Default

# Disable the Windows 260 characters path limit
Win32LongPathLimit -Disable

# Display Stop error code when BSoD occurs
BSoDStopError -Enable

# Choose when to be notified about changes to your computer: never notify
AdminApprovalMode -Never
# AdminApprovalMode -Default

# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
MappedDrivesAppElevatedAccess -Enable

# Turn off Delivery Optimization
DeliveryOptimization -Disable

# Always wait for the network at computer startup and logon for workgroup networks
WaitNetworkStartup -Enable

# Do not let Windows manage my default printer
# WindowsManageDefaultPrinter -Disable
WindowsManageDefaultPrinter -Enable

<#
	Disable the Windows features using the pop-up dialog box
	If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not disable the "Media Features" feature
#>
WindowsFeatures -Disable
# WindowsFeatures -Enable

<#
	Uninstall optional features using the pop-up dialog box
	If you want to leave "Multimedia settings" element in the advanced settings of Power Options do not uninstall the "Media Features" feature
#>
WindowsCapabilities -Uninstall
# WindowsCapabilities -Install

# Receive updates for other Microsoft products
UpdateMicrosoftProducts -Enable

# Set power plan on "Balanced" (default value)
PowerPlan -High
# PowerPlan -Balanced

# Use the latest installed .NET runtime for all apps
LatestInstalled.NET -Enable

# Do not allow the computer to turn off the network adapters to save power
NetworkAdaptersSavePower -Disable
# NetworkAdaptersSavePower -Enable

<#
	Disable the Internet Protocol Version 6 (TCP/IPv6) component for all network connections
	Before invoking the function, a check will be run whether your ISP supports the IPv6 protocol using https://ipv6-test.com
#>
IPv6Component -Disable
# IPv6Component -Enable

# Override for default input method: English
#  InputMethod -English
InputMethod -Default

<#
	Move user folders location to the root of any drive using the interactive menu
	User files or folders won't me moved to a new location. Move them manually
	They're located in the %USERPROFILE% folder by default
#>
# SetUserShellFolderLocation -Root
# SetUserShellFolderLocation -Custom
# SetUserShellFolderLocation -Default

<#
	Run troubleshooter automatically, then notify me
	In order this feature to work the OS level of diagnostic data gathering will be set to "Optional diagnostic data", and the error reporting feature will be turned on
#>
# RecommendedTroubleshooting -Automatically
RecommendedTroubleshooting -Default

# Launch folder windows in a separate process
FoldersLaunchSeparateProcess -Enable
# FoldersLaunchSeparateProcess -Disable

# Disable and delete reserved storage after the next update installation
ReservedStorage -Disable

# Disable help lookup via F1
F1HelpPage -Disable

# Enable Num Lock at startup
NumLock -Enable

# Disable Caps Lock
# CapsLock -Disable
CapsLock -Enable

# Turn off pressing the Shift key 5 times to turn Sticky keys
StickyShift -Disable

# Don't use AutoPlay for all media and devices
Autoplay -Disable

# Disable thumbnail cache removal
ThumbnailCacheRemoval -Disable

# Automatically saving my restartable apps and restart them when I sign back in
# SaveRestartableApps -Enable
SaveRestartableApps -Disable

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
NetworkDiscovery -Enable

# Automatically adjust active hours for me based on daily usage
# ActiveHours -Automatically
ActiveHours -Manually

# Restart as soon as possible to finish updating
# RestartDeviceAfterUpdate -Enable
RestartDeviceAfterUpdate -Disable

# Set Windows Terminal as default terminal app to host the user interface for command-line applications
DefaultTerminalApp -WindowsTerminal
# DefaultTerminalApp -ConsoleHost

<#
	Install the latest supported Microsoft Visual C++ Redistributable 2015—2022 x64
	https://docs.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
#>
InstallVCRedistx64

<#
	Enable Windows Subsystem for Linux (WSL), install the latest WSL Linux kernel version, and a Linux distribution using a pop-up form
	The "Receive updates for other Microsoft products" setting will enabled automatically to receive kernel updates

	Установить подсистему Windows для Linux (WSL), последний пакет обновления ядра Linux и дистрибутив Linux, используя всплывающую форму
	Параметр "При обновлении Windows получать обновления для других продуктов Майкрософт" будет включен автоматически в Центре обновлении Windows, чтобы получать обновления ядра
#>
WSL

# Unpin all Start apps
UnpinAllStartApps

# Run the Windows PowerShell shortcut from the Start menu as Administrator
RunPowerShellShortcut -Elevated
# RunPowerShellShortcut -NonElevated

UninstallUWPApps
# RestoreUWPApps

# Download and install "HEVC Video Extensions from Device Manufacturer" to be able to open .heic and .heif formats
HEIF -Install

# Disable Cortana autostarting
CortanaAutostart -Disable

# Disable Microsoft Teams autostarting
TeamsAutostart -Disable

# Check for UWP apps updates
CheckUWPAppsUpdates

# Disable Xbox Game Bar
XboxGameBar -Disable

# Disable Xbox Game Bar tips
XboxGameTips -Disable

# Choose an app and set the "High performance" graphics performance for it. Only if you have a dedicated GPU
SetAppGraphicsPerformance
GPUScheduling -Enable

<#
	Create the "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates
	A native interactive toast notification pops up every 30 days. The task runs every 30 days
#>
CleanupTask -Register
# CleanupTask -Delete

<#
	Create the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder
	The task will wait until the Windows Updates service finishes running. The task runs every 90 days
#>
SoftwareDistributionTask -Register
# SoftwareDistributionTask -Delete

<#
	Create the "Temp" scheduled task for cleaning up the %TEMP% folder
	Only files older than one day will be deleted. The task runs every 60 days
#>
TempTask -Register
# TempTask -Delete

# Enable Microsoft Defender Exploit Guard network protection
# 0NetworkProtection -Enable
NetworkProtection -Disable

# Enable detection for potentially unwanted applications and block them
# PUAppsDetection -Enable
PUAppsDetection -Disable

<#
	Enable sandboxing for Microsoft Defender
	There is a bug in KVM with QEMU: enabling this function causes VM to freeze up during the loading phase of Windows
#>
DefenderSandbox -Enable
DefenderSandbox -Disable

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
DismissSmartScreenFilter

# Enable events auditing generated when a process is created (starts)
# Включить аудит событий, возникающих при создании или запуске процесса
AuditProcess -Enable

<#
	Include command line in process creation events
	In order this feature to work events auditing (ProcessAudit -Enable) will be enabled
#>
CommandLineProcessAudit -Enable

# Do not include command line in process creation events (default value)
EventViewerCustomView -Enable

# Enable logging for all Windows PowerShell modules
PowerShellModulesLogging -Enable

# Enable logging for all PowerShell scripts input to the Windows PowerShell event log
PowerShellScriptsLogging -Enable

# Microsoft Defender SmartScreen doesn't marks downloaded files from the Internet as unsafe
AppsSmartScreen -Disable

# Microsoft Defender SmartScreen marks downloaded files from the Internet as unsafe (default value)
# AppsSmartScreen -Enable

# Disable the Attachment Manager marking files that have been downloaded from the Internet as unsafe
SaveZoneInformation -Disable

<#
	Disable Windows Script Host
	Blocks WSH from executing .js and .vbs files
#>
# WindowsScriptHost -Disable

# Enable Windows Script Host (default value)
# WindowsScriptHost -Enable

# Enable Windows Sandbox
# WindowsSandbox -Enable
# WindowsSandbox -Disable

<#
	Enable DNS-over-HTTPS for IPv4
	The valid IPv4 addresses: 1.0.0.1, 1.1.1.1, 149.112.112.112, 8.8.4.4, 8.8.8.8, 9.9.9.9

	Включить DNS-over-HTTPS для IPv4
	Действительные IPv4-адреса: 1.0.0.1, 1.1.1.1, 149.112.112.112, 8.8.4.4, 8.8.8.8, 9.9.9.9
#>
DNSoverHTTPS -Enable -PrimaryDNS 1.0.0.1 -SecondaryDNS 1.1.1.1

# Disable DNS-over-HTTPS for IPv4 (default value)
# DNSoverHTTPS -Disable

# Show the "Extract all" item in the Windows Installer (.msi) context menu
MSIExtractContext -Show

# Show the "Install" item in the Cabinet (.cab) filenames extensions context menu
CABInstallContext -Show

# Show the "Run as different user" item to the .exe filename extensions context menu
RunAsDifferentUserContext -Show

# Show the "Cast to Device" item in the media files and folders context menu (default value)
CastToDeviceContext -Show

# Hide the "Share" item from the context menu
ShareContext -Hide

# Hide the "Edit with Photos" item from the media files context menu
EditWithPhotosContext -Hide

# Hide the "Create a new video" item in the media files context menu
CreateANewVideoContext -Hide

# Hide the "Print" item from the .bat and .cmd context menu
PrintCMDContext -Hide

# Hide the "Include in Library" item from the folders and drives context menu
IncludeInLibraryContext -Hide

# Hide the "Send to" item from the folders context menu
SendToContext -Hide

# Hide the "Turn on BitLocker" item from the drives context menu
BitLockerContext -Hide

# Hide the "Compressed (zipped) Folder" item from the "New" context menu
CompressedFolderNewContext -Hide

# Enable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
MultipleInvokeContext -Enable

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
UseStoreOpenWith -Hide

# Hide the "Open in Windows Terminal" item in the folders context menu
OpenWindowsTerminalContext -Hide

# Show the "Open in Windows Terminal" (Admin) item in the Desktop and folders context menu
OpenWindowsTerminalAdminContext -Show

# Disable the Windows 10 context menu style (default value)
Windows10ContextMenu -Enable


#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################
#####################################################################################

##################################
# !! Ne Pas Tocuher à l'ordre !! #
##################################

# Nono-Perso
ModulesScriptNonoOS

ConnexionToNas

InstallGit

AutoLogonWin

DossierConfig

####################################

#########################
# Dossier Backup Config # 
#########################

DossierConfigVSCodium

DossierConfigOffice

ActivationWindows

DossierConfigRevo

DossierConfigScriptsMaison

DossierConfigStartisBack

DossierConfigAdobe

DossierConfigSsh

# DossierConfigAppData


####################################


#################################
# Installation des Applications #
#################################
ChocoInstall

InstallByWinGet


####################################


######################
# Activation Windows #
######################
UpdateWindowsByPws

ActivationWindows


####################################






#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################
#####################################################################################################################################################################################################



RefreshEnvironment


Errors


MenuRedemarrage

Stop-Transcript
