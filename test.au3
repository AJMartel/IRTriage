;==========================================================================================================================================
;	Tool:			Incident Respone Triage:    (GUI)
;
;	Version:		0.0.1.7
;
;	Author:			Michael Ahrendt (Nov 2012)
;   Modified by:    Alain Martel (Oct 2015)
;
;	Description:	IRTriage is intended for incident responders who need to gather host data rapidly.
;			The tool will run a plethora of commands automatically based on selection.
;			It has the ability to copy data to an external USB drive as well.
			Data will copy to wherever the script is stored.
;			IRTriage is intended to be run off a flash drive locally on the machine, or via a network location.
;
; 	Tools used:	Fast Dump pro by HBGary
;				-http://www.countertack.com/
;
;		       **Win(32|64)DD from MoonSols (Replaced by Fast Dump pro, code was commented out not removed.)
;				-http://www.moonsols.com/
;
;			Sysinternals Suite from Microsoft and Mark Russinovich
;				-http://technet.microsoft.com/en-us/sysinternals/bb842062
;               -https://download.sysinternals.com/files/sysinternalssuite.zip
;
;           The SleuthKit
;                -http://sourceforge.net/projects/sleuthkit/files/sleuthkit/4.2.0/sleuthkit-4.2.0-win32.zip/download
;
;			RegRipper from Harlan Carvey
;				-https://github.com/keydet89/RegRipper2.8/archive/master.zip
;
;			md5deep and sha1deep from Jesse Kornblum
;				-http://sourceforge.net/projects/md5deep/files/md5deep/md5deep-4.3/md5deep-4.3.zip/download?use_mirror=kent
;
;			7zip Command Line
;				-http://www.7-zip.org/download.html  (standalone console version)
;
;===========================================================================================================================================

#Include <GUIConstantsEx.au3>
#Include <WindowsConstants.au3>
#Include <StaticConstants.au3>
#Include <Date.au3>
#Include <File.au3>

Global 	$tStamp = @YEAR & @MON & @MDAY & @HOUR & @MIN & @SEC
Global	$RptsDir = @ScriptDir & "\" & $tStamp & " - " & @ComputerName
Global	$EvDir = $RptsDir & "\Evidence\"
Global	$MemDir = $EvDir & "Memory\"                                 ;added to make finding the memory image easier
Global 	$HashDir = $RptsDir & "\Evidence"
Global	$JmpLst = $EvDir & "Jump Lists"
Global	$shell = '"' & @ScriptDir & '\Tools\cmd.exe"'
Global 	$shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
Global 	$tools = '"' &@ScriptDir & '\Tools\'
Global 	$RecentPath = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Recent")
Global	$Log = $RptsDir & "\Incident Log.csv"
Global 	$ini_file
Global 	$fcnt
Global  $p_chkc = 1                                                  ;fixed missing value that killed command logging
Global  $r_chk = 0                                                   ;fixed missing value that killed command logging
Global  $r_ini = 0                                                   ;fixed missing value that killed command logging
Global  $Version = "0.0.1.7"                                         ;Added to facilitate display of version info

$ini_file = "IRTriage.ini"

If IsAdmin() = 0 Then MsgBox(64, "Admin", 'Admin rights are required.  Please restart with "RunAs /user:[admin] C:\Dir\To\IRTriage\IRTriage.exe" or Right-Click "Run As Administrator".')

INI_Check($ini_file)

Func INI_Check($ini_file)				;Check the INI file included in triage for functions and whether or not to run them

   Global 	$GUI_ini
   Global 	$md_ini, $tm_ini
   Global 	$sysrrp_ini, $sftrrp_ini, $hkcurrp_ini, $secrrp_ini, $samrrp_ini, $ntusrrp_ini, $usrc_ini
   Global	$VS_PF_ini, $VS_RF_ini, $VS_JmpLst_ini, $VS_EvtCpy_ini, $VS_SYSREG_ini, $VS_SECREG_ini, $VS_SAMREG_ini, $VS_SOFTREG_ini, $VS_USERREG_ini
   Global 	$SysIntAdd_ini
   Global 	$MFT_ini
   Global 	$IPs_ini, $DNS_ini, $Arp_ini, $ConnS_ini, $routes_ini, $ntBIOS_ini, $conn_ini
   Global 	$share_ini, $shfile_ini, $fw_ini, $host_ini, $wrkgrp_ini
   Global 	$pf_ini, $rf_ini, $JL_ini, $evt_ini
   Global 	$proc_ini, $sysinf_ini, $srvs_ini
   Global 	$fassoc_ini, $acctinfo_ini, $hostn_ini
   Global 	$autorun_ini, $st_ini, $logon_ini
   Global 	$NTFS_ini, $mntdsk_ini, $dir_ini, $VolInfo_ini
   Global 	$regrip_ini
   Global 	$md5_ini, $sha1_ini
   Global 	$compress_ini

   $GUI_ini = IniRead($ini_file, "GUI", "GUI", "Yes")
   $md_ini = IniRead($ini_file, "Function", "MemDump", "Yes")
   $tm_ini = IniRead($ini_file, "Function", "TestMem", "Yes")
   $sysrrp_ini = IniRead($ini_file, "Function", "SystemRRip", "Yes")
   $sftrrp_ini = IniRead($ini_file, "Function", "SoftwareRRip", "Yes")
   $hkcurrp_ini = IniRead($ini_file, "Function", "HKCURRip", "Yes")
   $secrrp_ini = IniRead($ini_file, "Function", "SecurityRRip", "Yes")
   $samrrp_ini = IniRead($ini_file, "Function", "SAMRRip", "Yes")
   $ntusrrp_ini = IniRead($ini_file, "Function", "NTUserRRip", "Yes")
   $usrc_ini = IniRead($ini_file, "Function", "Userclass", "Yes")
   $MFT_ini = IniRead($ini_file, "Function", "MFTcopy", "Yes")
   $VS_PF_ini = IniRead($ini_file, "Function", "VSprefetch", "No")
   $VS_RF_ini = IniRead($ini_file, "Function", "VSrecent", "No")
   $VS_JmpLst_ini = IniRead($ini_file, "Function", "VSjumplist", "No")
   $VS_EvtCpy_ini = IniRead($ini_file, "Function", "VSevents", "No")
   $VS_SYSREG_ini = IniRead($ini_file, "Function", "VSsystemreg", "No")
   $VS_SECREG_ini = IniRead($ini_file, "Function", "VSsecurityreg", "No")
   $VS_SAMREG_ini = IniRead($ini_file, "Function", "VSsamreg", "No")
   $VS_SOFTREG_ini = IniRead($ini_file, "Function", "VSsoftware", "No")
   $VS_USERREG_ini = IniRead($ini_file, "Function", "VSuserreg", "No")
   $SysIntAdd_ini = IniRead($ini_file, "Function", "SysIntAdd", "Yes")
   $IPs_ini = IniRead($ini_file, "Function", "IPs", "Yes")
   $DNS_ini = IniRead($ini_file, "Function", "DNS", "Yes")
   $Arp_ini = IniRead($ini_file, "Function", "Arp", "Yes")
   $ConnS_ini = IniRead($ini_file, "Function", "ConnectedSessions", "Yes")
   $routes_ini = IniRead($ini_file, "Function", "Routes", "Yes")
   $ntBIOS_ini = IniRead($ini_file, "Function", "NetBios", "Yes")
   $conn_ini = IniRead($ini_file, "Function", "Connections", "Yes")
   $share_ini = IniRead($ini_file, "Function", "Shares", "Yes")
   $shfile_ini = IniRead($ini_file, "Function", "SharedFiles", "Yes")
   $fw_ini = IniRead($ini_file, "Function", "Firewall", "Yes")
   $host_ini = IniRead($ini_file, "Function", "Hosts", "Yes")
   $wrkgrp_ini = IniRead($ini_file, "Function", "Workgroups", "Yes")
   $pf_ini = IniRead($ini_file, "Function", "Prefetch", "Yes")
   $rf_ini = IniRead($ini_file, "Function", "RecentFolder", "Yes")
   $JL_ini = IniRead($ini_file, "Function", "JumpLists", "Yes")
   $evt_ini = IniRead($ini_file, "Function", "EvtCopy", "Yes")
   $proc_ini = IniRead($ini_file, "Function", "Processes", "Yes")
   $sysinf_ini = IniRead($ini_file, "Function", "SystemInfo", "Yes")
   $srvs_ini = IniRead($ini_file, "Function", "Services", "Yes")
   $fassoc_ini = IniRead($ini_file, "Function", "FileAssociations", "Yes")
   $acctinfo_ini = IniRead($ini_file, "Function", "AccoutInfo", "Yes")
   $hostn_ini = IniRead($ini_file, "Function", "Hostname", "Yes")
   $autorun_ini = IniRead($ini_file, "Function", "AutoRun", "Yes")
   $st_ini = IniRead($ini_file, "Function", "ScheduledTasks", "Yes")
   $logon_ini = IniRead($ini_file, "Function", "LoggedOn", "Yes")
   $NTFS_ini = IniRead($ini_file, "Function", "NTFSInfo", "Yes")
   $VolInfo_ini = IniRead($ini_file, "Function", "VolumeInfo", "Yes")
   $mntdsk_ini = IniRead($ini_file, "Function", "MountedDisk", "Yes")
   $dir_ini = IniRead($ini_file, "Function", "Directory", "Yes")
   $regrip_ini = IniRead($ini_file, "Function", "RegRipper", "Yes")
   $md5_ini = IniRead($ini_file, "Function", "MD5", "Yes")
   $sha1_ini = IniRead($ini_file, "Function", "SHA1", "Yes")
   $compress_ini = IniRead($ini_file, "Function", "Compression", "No")

EndFunc

If $GUI_ini = "Yes" Then
   TriageGUI()
EndIf

If $GUI_ini = "No" Then
   INI2Command()
EndIf

Func TriageGUI()						;Creates a graphical user interface for Triage

   Local 	$filemenu, $fileitem1, $fileitem2
   Local 	$helpmenu, $helpitem1, $helpitem2
   Local 	$iniread, $inidsp
   Local 	$msg, $run, $os
   Global 	$inifile, $tr_tab
   Global 	$Sys_chk, $Proc_chk, $Serv_chk, $FileAssoc_chk, $STsk_chk
   Global 	$Host_chk, $AutoRun_chk, $AcctInfo_chk, $IPs_chk, $CONN_chk
   Global 	$Routes_chk, $ARP_chk, $DNS_chk, $NBT_chk, $nShare_chk
   Global 	$nFiles_chk, $Sessions_chk, $WrkgrpPC_chk
   Global 	$SYSTEM_chk, $SECURITY_chk, $SAM_chk, $SOFTWARE_chk, $HKCU_chk, $HKU_chk, $UsrC_chk
   Global 	$NTFSInfo_chk, $DiskMnt_chk, $Tree_chk, $VolInfo_chk
   Global 	$MemDmp_chk, $JmpLst_chk, $EvtCpy_chk
   Global 	$PF_chk, $RF_chk, $sysint_chk
   Global 	$md5_chk, $sha1_chk, $regrip_chk, $compress_chk
   Global	$VS_PF_chk, $VS_RF_chk, $VS_JmpLst_chk, $VS_EvtCpy_chk, $VS_SYSREG_chk, $VS_SECREG_chk, $VS_SAMREG_chk, $VS_SOFTREG_chk, $VS_USERREG_chk
   Global	$MFTg_chk

   GUICreate("Incident Response Triage: version "& $Version, 810, 300)

	  $font = "Arial"

	  GUISetFont(10, 400, "",$font)

	  $filemenu = GUICtrlCreateMenu("File")

	  $fileitem1 = GUICtrlCreateMenuItem("Select INI File", $filemenu)

	  GUICtrlCreateMenuItem("", $filemenu, 2)

	  $fileitem2 = GUICtrlCreateMenuItem("Exit", $filemenu)

	  $toolsmenu = GUICtrlCreateMenu("Tools")

	  $toolsitem1 = GUICtrlCreateMenuItem("Sysinternals Suite Update", $toolsmenu)

	  $helpmenu = GUICtrlCreateMenu("Help")

	  $helpitem1 = GUICtrlCreateMenuItem("Help", $helpmenu)

	  GUICtrlCreateMenuItem("", $helpmenu, 2)

	  $helpitem2 = GUICtrlCreateMenuItem("About", $helpmenu)

	  $inidsp = StringTrimLeft($ini_file, StringInStr($ini_file, "\", 0, -1))

	  $iniread = GUICtrlCreateLabel("Reading from " & $inidsp & " configuration.", 0, 262, 460, 20, BitOR($SS_SIMPLE, $SS_SUNKEN))

	  $tr_tab = GUICtrlCreateTab(3, 5, 805, 235)

	  GUICtrlCreateTabItem("System Information")

		 $Sys_chk = GUICtrlCreateCheckbox("System Information", 10, 30)
			GUICtrlSetTip($Sys_chk, "Gather information about the type of system under query.")
		 $Proc_chk = GUICtrlCreateCheckbox("Capture Processes", 10, 50)
			GUICtrlSetTip($Proc_chk, "Capture information in regards to the running processes.")
		 $Serv_chk = GUICtrlCreateCheckbox("Capture Services", 10, 70)
			GUICtrlSetTip($Serv_chk, "Gather information about services on the PC.")
		 $FileAssoc_chk = GUICtrlCreateCheckbox("Handles", 10, 90)
			GUICtrlSetTip($FileAssoc_chk, "Search for open file references.")
		 $STsk_chk = GUICtrlCreateCheckbox("Scheduled Tasks Information", 10, 110)
			GUICtrlSetTip($STsk_chk, "Query system for any tasks that may have been scheduled by users.")
		 $Host_chk = GUICtrlCreateCheckbox("Hostname Information", 10, 130)
			GUICtrlSetTip($Host_chk, "Determine the system's hostname.")
		 $AutoRun_chk = GUICtrlCreateCheckbox("AutoRun Information", 10, 150)
			GUICtrlSetTip($AutoRun_chk, "Gather information about system start-up.  Often a source of persistence for intrusions.")
		 $AcctInfo_chk = GUICtrlCreateCheckbox("Account Settings", 10, 170)
			GUICtrlSetTip($AcctInfo_chk, "Get details about user account settings.")

	  GUICtrlCreateTabItem("Network Information")

		 $IPs_chk = GUICtrlCreateCheckbox("IP Configuration", 10, 30)
			GUICtrlSetTip($IPs_chk, "Gather information in relation to Internet Protocol configuration.")
		 $CONN_chk = GUICtrlCreateCheckbox("Active Connections", 10, 50)
			GUICtrlSetTip($CONN_chk, "Get information about current network connections.")
		 $Routes_chk = GUICtrlCreateCheckbox("Connection Routes", 10, 70)
			GUICtrlSetTip($Routes_chk, "Provides information about current network routes.")
		 $ARP_chk = GUICtrlCreateCheckbox("ARP Data", 10, 90)
			GUICtrlSetTip($ARP_chk, "Gather information from the Address Resolution Protocol.")
		 $DNS_chk = GUICtrlCreateCheckbox("DNS Information", 10, 110)
			GUICtrlSetTip($DNS_chk, "Gather information from the Domain Name System.")
		 $NBT_chk = GUICtrlCreateCheckbox("NetBIOS Information", 10, 130)
			GUICtrlSetTip($NBT_chk, "Get information about the Network Basic Input/Output System.")
		 $nShare_chk = GUICtrlCreateCheckbox("Local Network Shares", 10, 150)
			GUICtrlSetTip($nShare_chk, "Determine if any network shares are being hosted on local system.")
		 $nFiles_chk = GUICtrlCreateCheckbox("Open Shared Files", 10, 170)
			GUICtrlSetTip($nFiles_chk, "Determine if any shared files are currently being accessed.")
		 $Sessions_chk = GUICtrlCreateCheckbox("Connected Sessions", 10, 190)
			GUICtrlSetTip($Sessions_chk, "Gather information about any possible connected sessions.")
		 $WrkgrpPC_chk = GUICtrlCreateCheckbox("Workgroup Computers", 10, 210)
			GUICtrlSetTip($WrkgrpPC_chk, "Get information about workgroup PCs.")

	  GUICtrlCreateTabItem("Registry")

		 $SYSTEM_chk = GUICtrlCreateCheckbox("Save SYSTEM registry hive", 10, 30)
			GUICtrlSetTip($SYSTEM_chk, "Collect a copy of the SYSTEM Registry hive.")
		 $SECURITY_chk = GUICtrlCreateCheckbox("Save SECURITY registry hive", 10, 50)
			GUICtrlSetTip($SECURITY_chk, "Collect a copy of the SECURITY Registry hive.")
		 $SAM_chk = GUICtrlCreateCheckbox("Save SAM registry hive", 10, 70)
			GUICtrlSetTip($SAM_chk, "Collect a copy of the System Account Managment registry hive.")
		 $SOFTWARE_chk = GUICtrlCreateCheckbox("Save SOFTWARE registry hive", 10,90)
			GUICtrlSetTip($SOFTWARE_chk, "Collect a copy of the SOFTWARE registry hive.")
		 $HKCU_chk = GUICtrlCreateCheckbox("Save the Current User registry hive", 10, 110)
			GUICtrlSetTip($HKCU_chk, "Collect the NTUSER.DAT registry hive for just the currently logged in user.")
		 $HKU_chk = GUICtrlCreateCheckbox("Save all user registry hives", 10, 130)
			GUICtrlSetTip($HKU_chk, "Collect the NTUSER.DAT registry hive for all users on the system.")

	  GUICtrlCreateTabItem("Disk Information")

		 $NTFSInfo_chk = GUICtrlCreateCheckbox("NTFS Information", 10, 30)
			GUICtrlSetTip($NTFSInfo_chk, "Gather disk information if formatted with New Technology File System.")
		 $DiskMnt_chk = GUICtrlCreateCheckbox("Capture Mounted Disks", 10, 50)
			GUICtrlSetTip($DiskMnt_chk, "Get information about any mounted disks on the live system.")
		 $Tree_chk = GUICtrlCreateCheckbox("Directory Information", 10, 70)
			GUICtrlSetTip($Tree_chk, "Print a listing of files on they system and the directory structure.")
		 $VolInfo_chk = GUICtrlCreateCheckbox("Volume Information", 10, 90)
			GUICtrlSetTip($VolInfo_chk, "Get information about the C Drive volume with Sleuth Kit.")

	  GUICtrlCreateTabItem("Evidence Collection")

		 $MemDmp_chk = GUICtrlCreateCheckbox("Collect Memory Image", 10, 30)
			GUICtrlSetTip($MemDmp_chk, "Create copy of physical memory for later analysis.")
		 $PF_chk = GUICtrlCreateCheckbox("Collect Prefetch Files", 10, 50)
			GUICtrlSetTip($PF_chk, "Gather all prefetch files on the system to determine file execution.")
		 $RF_chk = GUICtrlCreateCheckbox("Collect Recent Folder Files", 10, 70)
			GUICtrlSetTip($RF_chk, "Gather the link files that have been recently used, for each user.")
		 $JmpLst_chk = GUICtrlCreateCheckbox("Collect Jump List Files", 10, 90)
			GUICtrlSetTip($JmpLst_chk, "Gather both Automatic and Custom destination jump lists to gain insight into recent files used, for each user.")
		 $EvtCpy_chk = GUICtrlCreateCheckbox("Collect Event Logs from System.", 10, 110)
			GUICtrlSetTip($EvtCpy_chk, "Copy any event logs on the system.")
		 $UsrC_chk = GUICtrlCreateCheckbox("Collect Profile USRCLASS.dat Files", 10, 130)
			GUICtrlSetTip($UsrC_chk, "Copy the USERCLASS portion of registry for analysis of Windows Shell.")
		 $MFTg_chk = GUICtrlCreateCheckbox("Collect a copy of the MFT", 10, 150)
			GUICtrlSetTip($MFTg_chk, "Collect a copy of the Master File Table for analysis.")

	  GUICtrlCreateTabItem("Volume Shadow Copies (VSCs)")

		 $VS_PF_chk = GUICtrlCreateCheckbox("Collect Prefetch Files from VSCs", 10, 30)
			GUICtrlSetTip($VS_PF_chk, "Gather Prefetch files through Volume Shadow Copies for historical file execution analysis.")
		 $VS_RF_chk = GUICtrlCreateCheckbox("Collect Recent Folder Files from VSCs", 10, 50)
			GUICtrlSetTip($VS_RF_chk, "Gather links for recent folder for each user in Volume Shadow Copies.")
		 $VS_JmpLst_chk = GUICtrlCreateCheckbox("Collect JumpLists from VSCs", 10, 70)
			GUICtrlSetTip($VS_JmpLst_chk, "Gather Jump List information for each user from Volume Shadow Copies.")
		 $VS_EvtCpy_chk = GUICtrlCreateCheckbox("Collect EventLogs from VSCs", 10, 90)
			GUICtrlSetTip($VS_EvtCpy_chk, "Collect Event Logs occuring through history with Volume Shadow Copies.")
		 $VS_SYSREG_chk = GUICtrlCreateCheckbox("Collect SYSTEM hive from VSCs", 10, 110)
			GUICtrlSetTip($VS_SYSREG_chk, "Collect the SYSTEM registry hive through history with Volume Shadow Copies.")
		 $VS_SECREG_chk = GUICtrlCreateCheckbox("Collect SECURITY hive from VSCs", 10, 130)
			GUICtrlSetTip($VS_SECREG_chk, "Collect the SECURITY registry hive through history with Volume Shadow Copies.")
		 $VS_SAMREG_chk = GUICtrlCreateCheckbox("Collect SAM hive from VSCs", 10, 150)
			GUICtrlSetTip($VS_SAMREG_chk, "Collect the System Account Management registry hive through history with Volume Shadow Copies.")
		 $VS_SOFTREG_chk = GUICtrlCreateCheckbox("Collect SOFTWARE hive from VSCs", 10, 170)
			GUICtrlSetTip($VS_SOFTREG_chk, "Collect the SOFTWARE registry hive through history with Volume Shadow Copies.")
		 $VS_USERREG_chk = GUICtrlCreateCheckbox("Collect USER hives from VSCs", 10, 190)
			GUICtrlSetTip($VS_USERREG_chk, "Collect the NTUSER.dat registry hive through history with Volume Shadow Copies.")

	  GUICtrlCreateTabItem("Options")

		 $md5_chk = GUICtrlCreateCheckbox("Hash all collected files with MD5.", 10,30)
			GUICtrlSetTip($md5_chk, "Use MD5DEEP to hash all gathered evidence items.")
		 $sha1_chk = GUICtrlCreateCheckbox("Hash all collected files with SHA1.", 10, 50)
			GUICtrlSetTip($sha1_chk, "Use SHA1DEEP to hash all gathered evidence items.")
		 $regrip_chk = GUICtrlCreateCheckbox("Run RegRipper against collected registry hives.", 10, 70)
			GUICtrlSetTip($regrip_chk, "Use RegRipper to parse all current hive list that were gathered")
		 $compress_chk = GUICtrlCreateCheckbox("Compress all of collected files and information in an archive.", 10, 90)
			GUICtrlSetTip($compress_chk, "Use 7-zip to compress all collected evidence into one zipped archive.")
		 $sysint_chk = GUICtrlCreateCheckbox("Add Registry Entry for SysInternals Suite.", 10, 110)
			GUICtrlSetTip($sysint_chk, "Add registry entry to eliminate any risk of EULA stopping Sysinternals from running properly.")

	  GUICtrlCreateTabItem("") ; end tabitem definition

	  $all = GUICtrlCreateButton("Select All", 480, 244, 80, 30)

	  $none = GUICtrlCreateButton("Select None", 570, 244, 80, 30)

	  $run = GUICtrlCreateButton("Run", 755, 244, 50, 30)

	  _Ini2GUI()

	  GUISetState()

	  While 1

		 $msg = GUIGetMsg()

		 If $msg = $fileitem1 Then
			$ini_file = FileOpenDialog("Choose an INI file:", @WorkingDir, "INI Files (*.ini)")
			INI_Check($ini_file)
			_Ini2GUI()
			GUICtrlSetState($iniread, $GUI_HIDE)
			$inidsp = StringTrimLeft($ini_file, StringInStr($ini_file, "\", 0, -1))
			$iniread = GUICtrlCreateLabel("Reading from " & $inidsp & " configuration.", 0, 262, 350, 20, BitOR($SS_SIMPLE, $SS_SUNKEN))
			GUICtrlSetState($iniread, $GUI_SHOW)
		 EndIf

		 If $msg = $all Then SelectAll()

		 If $msg = $none Then SelectNone()

		 If $msg = $fileitem2 Then ExitLoop

		 If $msg = $toolsitem1 Then

			If FileExists($tools & 'SysinternalsSuite') = 1 Then
			   SysInternalsDL()
			Else
			   $sysdlovr = MsgBox(4, "Info:", "SysinternalsSuite already found.  Would you like to overwrite?")
			   If $sysdlovr = 6 Then SysInternalsDL()
			EndIf

		 EndIf

		 If $msg = $helpitem1 Then ShellExecute('"' & @ScriptDir & '\Triage Help.pdf"')

		 If $msg = $helpitem2 Then MsgBox _
			(64, "About:", "Incident Response Triage: " & @CRLF & @CRLF & "Version: " & $Version & @CRLF & @CRLF & "IRTriage is a utility to help incident responders collect information quickly from a live system.  It is highly customizable to meet the needs of modern investigative processes.")

		 If $msg = $GUI_EVENT_CLOSE Then ExitLoop

		 If $msg = $run Then

			If Not FileExists($RptsDir) Then DirCreate($RptsDir)
			If Not FileExists($EvDir) Then DirCreate($EvDir)
			If Not FileExists($MemDir) Then DirCreate($MemDir)

			If Not FileExists(@ScriptDir & "\Tools\") Then
			   Do
				  DirCreate(@ScriptDir & "\Tools\")
			   Until FileExists(@ScriptDir & "\Tools\")
			EndIf

			If (GUICtrlRead($MemDmp_chk) = 1) Then
			   If Not FileExists(@ScriptDir & "\Tools\FDpro.exe") Then
				   FileInstall(".\Compile\Tools\FDpro.exe", @ScriptDir & "\Tools\", 0)
			   EndIf

;  **Win(32|64)DD from MoonSols**
;			   If @OSArch = "X86" Then
;				  If Not FileExists(@ScriptDir & "\Tools\win32dd.exe") Then
;					 FileInstall(".\Compile\Tools\win32dd.sys", @ScriptDir & "\Tools\", 0)
;					 FileInstall(".\Compile\Tools\win32dd.exe", @ScriptDir & "\Tools\", 0)
;				  EndIf
;			   Else
;				  If Not FileExists(@ScriptDir & "\Tools\win64dd.exe") Then
;					 FileInstall(".\Compile\Tools\win64dd.sys", @ScriptDir & "\Tools\", 0)
;					 FileInstall(".\Compile\Tools\win64dd.exe", @ScriptDir & "\Tools\", 0)
;				  EndIf
;			   EndIf
			   MemDump()
			EndIf

			If Not FileExists($tools) Then
			   Install()
			EndIf

			If FileExists(@ScriptDir & '\Tools\SysinternalsSuite\') = 0 Then
			   $sysintchk = MsgBox(4, "Missing Tools", "Missing the Sysinternals Toolset." & @CRLF & @CRLF & "Would you like to download the latest version and continue?")
			   If $sysintchk = 6 Then SysInternalsDL()
			   If $sysintchk = 7 Then ExitLoop
			EndIf

			   $progGUI = GUICreate("Triage Progress", 250, 70, -1, -1, -1, BitOR($WS_EX_TOPMOST, $WS_EX_OVERLAPPEDWINDOW))

			   $progress = GUICtrlCreateProgress(10, 25, 230, 25)

			   ProgChkCount()

			   If (GUICtrlRead($MemDmp_chk) = 1) Then
				  $fcnt = 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   Else
				  $fcnt = 0
				  GUICtrlSetData($progress, 0)
			   EndIf

			   GUISetState(@SW_SHOW, $progGUI)

			If (GUICtrlRead($PF_chk) = 1) Then
			   Prefetch()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($RF_chk) = 1) Then
			   RecentFolder()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($JmpLst_chk) = 1) Then
			   JumpLists()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($SYSTEM_chk) = 1) Then
			   SystemRRip()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($SOFTWARE_chk) = 1) Then
			   SoftwareRRip()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($HKCU_chk) = 1) Then
			   HKCURRip()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($HKU_chk) = 1) Then
			   NTUserRRip()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($UsrC_chk) = 1) Then
			   UsrclassE()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($SECURITY_chk) = 1) Then
			   SecurityRRip()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($SAM_chk) = 1) Then
			   SAMRRip()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($MFTg_chk) = 1) Then
			   MFTgrab()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			VSC_ChkCount()

			If $r_chk >= 1 Then
			   GetShadowNames()
			   Sleep(6000)
			   MountVSCs()
			   Sleep(6000)
			EndIf

			If FileExists("C:\VSC_1") = 1 Then

			   If (GUICtrlRead($VS_PF_chk) = 1) Then
				  VSC_Prefetch()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_RF_chk) = 1) Then
				  VSC_RecentFolder()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_JmpLst_chk) = 1) Then
				  VSC_JumpLists()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_EvtCpy_chk) = 1) Then
				  VSC_EvtCopy()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_SYSREG_chk) = 1) Then
				  VSC_RegHiv("SYSTEM")
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_SECREG_chk) = 1) Then
				  VSC_RegHiv("SECURITY")
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_SAMREG_chk) = 1) Then
				  VSC_RegHiv("SAM")
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_SOFTREG_chk) = 1) Then
				  VSC_RegHiv("SOFTWARE")
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			   If (GUICtrlRead($VS_USERREG_chk) = 1) Then
				  VSC_NTUser()
				  $fcnt = $fcnt + 1
				  GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			Else
			   MsgBox(11, "VSC", "Problem with Volume Shadow Mounts")
			   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Did NOT execute Volume Shadow Copy Functions." & @CRLF)
			EndIf

			If $r_chk >= 1 Then
			   VSC_rmVSC()
			EndIf

			If (GUICtrlRead($sysint_chk) = 1) Then
			   SysIntAdd()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($IPs_chk) = 1) Then
			   IPs()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($DNS_chk) = 1) Then
			   DNS()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($ARP_chk) = 1) Then
			   Arp()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($NBT_chk) = 1) Then
			   NetBIOS()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($Routes_chk) = 1) Then
			   Routes()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($CONN_chk) = 1) Then
			   Connections()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($Sessions_chk) = 1) Then
			   ConnectedSessions()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($nShare_chk) = 1) Then
			   Shares()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($nFiles_chk) = 1) Then
			   SharedFiles()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($WrkgrpPC_chk) = 1) Then
			   Workgroups()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($Sys_chk) = 1) Then
			   SystemInfo()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($Proc_chk) = 1) Then
			   Processes()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($Serv_chk) = 1) Then
			   Services()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($AcctInfo_chk) = 1) Then
			   AccountInfo()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($AutoRun_chk) = 1) Then
			   AutoRun()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($STsk_chk) = 1) Then
			   ScheduledTasks()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($FileAssoc_chk) = 1) Then
			   FileAssociation()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($Host_chk) = 1) Then
			   Hostname()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($NTFSInfo_chk) = 1) Then
			   NTFSInfo()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($VolInfo_chk) = 1) Then
			   VolInfo()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($DiskMnt_chk) = 1) Then
			   MountedDisk()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($Tree_chk) = 1) Then
			   Directory()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($EvtCpy_chk) = 1) Then
			   EvtCopy()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($md5_chk) = 1) Then
			   MD5()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($sha1_chk) = 1) Then
			   SHA1()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($regrip_chk) = 1) Then
			   RegRipperTools()
			   RegRipper()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			   EndIf

			If (GUICtrlRead($compress_chk) = 1) Then
			   Compression()
			   $fcnt = $fcnt + 1
			   GUICtrlSetData($progress, (($fcnt/$p_chkc)*100))
			EndIf

			GUIDelete($progGUI)

			CommandROSLOG()

			MsgBox(0, "Incident Response Triage: ", "Your selected tasks have completed.")

		 EndIf

	  WEnd

   GUIDelete()

EndFunc

Func _Ini2GUI()							;Correlate the INI into checking the boxes of the GUI to execute the specific functions

   If $sysinf_ini = "Yes" Then
	  GUICtrlSetState($Sys_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Sys_chk, $GUI_UNCHECKED)
   EndIf

   If $proc_ini = "Yes" Then
	  GUICtrlSetState($Proc_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Proc_chk, $GUI_UNCHECKED)
   EndIf

   If $srvs_ini = "Yes" Then
	  GUICtrlSetState($Serv_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Serv_chk, $GUI_UNCHECKED)
   EndIf

   If $fassoc_ini = "Yes" Then
	  GUICtrlSetState($FileAssoc_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($FileAssoc_chk, $GUI_UNCHECKED)
   EndIf

   If $st_ini = "Yes" Then
	  GUICtrlSetState($STsk_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($STsk_chk, $GUI_UNCHECKED)
   EndIf

   If $hostn_ini = "Yes" Then
	  GUICtrlSetState($Host_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Host_chk, $GUI_UNCHECKED)
   EndIf

   If $autorun_ini = "Yes" Then
	  GUICtrlSetState($AutoRun_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($AutoRun_chk, $GUI_UNCHECKED)
   EndIf

   If $acctinfo_ini = "Yes" Then
	  GUICtrlSetState($AcctInfo_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($AcctInfo_chk, $GUI_UNCHECKED)
   EndIf

   If $IPs_ini = "Yes" Then
	  GUICtrlSetState($IPs_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($IPs_chk, $GUI_UNCHECKED)
   EndIf

   If $conn_ini = "Yes" Then
	  GUICtrlSetState($CONN_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($CONN_chk, $GUI_UNCHECKED)
   EndIf

   If $routes_ini = "Yes" Then
	  GUICtrlSetState($Routes_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Routes_chk, $GUI_UNCHECKED)
   EndIf

   If $Arp_ini = "Yes" Then
	  GUICtrlSetState($ARP_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($ARP_chk, $GUI_UNCHECKED)
   EndIf

   If $DNS_ini = "Yes" Then
	  GUICtrlSetState($DNS_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($DNS_chk, $GUI_UNCHECKED)
   EndIf

   If $ntBIOS_ini = "Yes" Then
	  GUICtrlSetState($NBT_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($NBT_chk, $GUI_UNCHECKED)
   EndIf

   If $share_ini = "Yes" Then
	  GUICtrlSetState($nShare_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($nShare_chk, $GUI_UNCHECKED)
   EndIf

   If $shfile_ini = "Yes" Then
	  GUICtrlSetState($nFiles_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($nFiles_chk, $GUI_UNCHECKED)
   EndIf

   If $Conns_ini = "Yes" Then
	  GUICtrlSetState($Sessions_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Sessions_chk, $GUI_UNCHECKED)
   EndIf

   If $wrkgrp_ini = "Yes" Then
	  GUICtrlSetState($WrkgrpPC_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($WrkgrpPC_chk, $GUI_UNCHECKED)
   EndIf

   If $sysrrp_ini = "Yes" Then
	  GUICtrlSetState($SYSTEM_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SYSTEM_chk, $GUI_UNCHECKED)
   EndIf

   If $secrrp_ini = "Yes" Then
	  GUICtrlSetState($SECURITY_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SECURITY_chk, $GUI_UNCHECKED)
   EndIf

   If $samrrp_ini = "Yes" Then
	  GUICtrlSetState($SAM_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SAM_chk, $GUI_UNCHECKED)
   EndIf

   If $sftrrp_ini = "Yes" Then
	  GUICtrlSetState($SOFTWARE_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($SOFTWARE_chk, $GUI_UNCHECKED)
   EndIf

   If $hkcurrp_ini = "Yes" Then
	  GUICtrlSetState($HKCU_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($HKCU_chk, $GUI_UNCHECKED)
   EndIf

   If $ntusrrp_ini = "Yes" Then
	  GUICtrlSetState($HKU_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($HKU_chk, $GUI_UNCHECKED)
   EndIf

   If $NTFS_ini = "Yes" Then
	  GUICtrlSetState($NTFSInfo_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($NTFSInfo_chk, $GUI_UNCHECKED)
   EndIf

   If $usrc_ini = "Yes" Then
	  GUICtrlSetState($UsrC_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($UsrC_chk, $GUI_UNCHECKED)
   EndIf

   If $mntdsk_ini = "Yes" Then
	  GUICtrlSetState($DiskMnt_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($DiskMnt_chk, $GUI_UNCHECKED)
   EndIf

   If $dir_ini = "Yes" Then
	  GUICtrlSetState($Tree_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($Tree_chk, $GUI_UNCHECKED)
   EndIf

   If $JL_ini = "Yes" Then
	  GUICtrlSetState($JmpLst_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($JmpLst_chk, $GUI_UNCHECKED)
   EndIf

   If $evt_ini = "Yes" Then
	  GUICtrlSetState($EvtCpy_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($EvtCpy_chk, $GUI_UNCHECKED)
   EndIf

   If $md5_ini = "Yes" Then
	  GUICtrlSetState($md5_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($md5_chk, $GUI_UNCHECKED)
   EndIf

   If $sha1_ini = "Yes" Then
	  GUICtrlSetState($sha1_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($sha1_chk, $GUI_UNCHECKED)
   EndIf

   If $regrip_ini = "Yes" Then
	  GUICtrlSetState($regrip_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($regrip_chk, $GUI_UNCHECKED)
   EndIf

   If $compress_ini = "Yes" Then
	  GUICtrlSetState($compress_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($compress_chk, $GUI_UNCHECKED)
   EndIf

   If $md_ini = "Yes" Then
	  GUICtrlSetState($MemDmp_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($MemDmp_chk, $GUI_UNCHECKED)
   EndIf

   If $pf_ini = "Yes" Then
	  GUICtrlSetState($PF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($PF_chk, $GUI_UNCHECKED)
   EndIf

   If $rf_ini = "Yes" Then
	  GUICtrlSetState($RF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($RF_chk, $GUI_UNCHECKED)
   EndIf

   If $SysIntAdd_ini = "Yes" Then
	  GUICtrlSetState($sysint_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($sysint_chk, $GUI_UNCHECKED)
   EndIf

   If $MFT_ini = "Yes" Then
	  GUICtrlSetState($MFTg_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($MFTg_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_PF_ini = "Yes" Then
	  GUICtrlSetState($VS_PF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_PF_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_RF_ini = "Yes" Then
	  GUICtrlSetState($VS_RF_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_RF_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_JmpLst_ini = "Yes" Then
	  GUICtrlSetState($VS_JmpLst_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_JmpLst_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_EvtCpy_ini = "Yes" Then
	  GUICtrlSetState($VS_EvtCpy_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_EvtCpy_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SYSREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SYSREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SYSREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SECREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SECREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SECREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SAMREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SAMREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SAMREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_SOFTREG_ini = "Yes" Then
	  GUICtrlSetState($VS_SOFTREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_SOFTREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VS_USERREG_ini = "Yes" Then
	  GUICtrlSetState($VS_USERREG_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VS_USERREG_chk, $GUI_UNCHECKED)
   EndIf

   If $VolInfo_ini = "Yes" Then
	  GUICtrlSetState($VolInfo_chk, $GUI_CHECKED)
   Else
	  GUICtrlSetState($VolInfo_chk, $GUI_UNCHECKED)
   EndIf

EndFunc

Func INI2Command()						;Correlate the INI file into executing the selected functions

   If Not FileExists($RptsDir) Then DirCreate($RptsDir)
   If Not FileExists($EvDir) Then DirCreate($EvDir)

   If Not FileExists(@ScriptDir & "\Tools\FDpro.exe") Then
	   FileInstall(".\Compile\Tools\FDpro.exe", @ScriptDir & "\Tools\", 0)
   EndIf

;  **Win(32|64)DD from MoonSols**
;   If @OSArch = "X86" Then
;	  If Not FileExists(@ScriptDir & "\Tools\win32dd.exe") Then
;		 FileInstall(".\Compile\Tools\win32dd.sys", @ScriptDir & "\Tools\", 0)
;		 FileInstall(".\Compile\Tools\win32dd.exe", @ScriptDir & "\Tools\", 0)
;	  EndIf
;   Else
;	  If Not FileExists(@ScriptDir & "\Tools\win64dd.exe") Then
;		 FileInstall(".\Compile\Tools\win64dd.sys", @ScriptDir & "\Tools\", 0)
;		 FileInstall(".\Compile\Tools\win64dd.exe", @ScriptDir & "\Tools\", 0)
;	  EndIf
;   EndIf

   If $md_ini = "Yes" Then MemDump()

   Install()

   If $pf_ini = "Yes" Then Prefetch()

   If $rf_ini = "Yes" Then RecentFolder()

   If $JL_ini = "Yes" Then JumpLists()

   If $sysrrp_ini = "Yes" Then SystemRRip()

   If $sftrrp_ini = "Yes" Then SoftwareRRip()

   If $hkcurrp_ini = "Yes" Then HKCURRip()

   If $ntusrrp_ini = "Yes" Then NTUserRRip()

   If $usrc_ini = "Yes" Then UsrclassE()

   If $MFT_ini = "Yes" Then MFTgrab()

   If $secrrp_ini = "Yes" Then SecurityRRip()

   If $samrrp_ini = "Yes" Then SAMRRip()

   VSC_IniCount()

	  If $r_ini >= 1 Then
		 GetShadowNames()
		 MountVSCs()
	  EndIf

	  If FileExists("C:\VSC_1") = 1 Then

		 If $VS_PF_ini = "Yes" Then VSC_Prefetch()

		 If $VS_RF_ini = "Yes" Then VSC_RecentFolder()

		 If $VS_JmpLst_ini = "Yes" Then VSC_JumpLists()

		 If $VS_EvtCpy_ini = "Yes" Then VSC_EvtCopy()

		 If $VS_SYSREG_ini = "Yes" Then VSC_RegHiv("SYSTEM")

		 If $VS_SECREG_ini = "Yes" Then VSC_RegHiv("SECURITY")

		 If $VS_SAMREG_ini = "Yes" Then VSC_RegHiv("SAM")

		 If $VS_SOFTREG_ini = "Yes" Then VSC_RegHiv("SOFTWARE")

		 If $VS_USERREG_ini = "Yes" Then VSC_NTUser()

	  Else
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Did NOT execute Volume Shadow Copy Functions." & @CRLF)
	  EndIf

	  If $r_ini >= 1 Then
		 VSC_rmVSC()
	  EndIf

   If $SysIntAdd_ini = "Yes" Then SysIntAdd()

   If $IPs_ini = "Yes" Then IPs()

   If $DNS_ini = "Yes" Then DNS()

   If $Arp_ini = "Yes" Then Arp()

   If $ntBIOS_ini = "Yes" Then NetBIOS()

   If $routes_ini = "Yes" Then Routes()

   If $conn_ini = "Yes" Then Connections()

   If $Conns_ini = "Yes" Then ConnectedSessions()

   If $share_ini = "Yes" Then Shares()

   If $shfile_ini = "Yes" Then SharedFiles()

   If $wrkgrp_ini = "Yes" Then Workgroups()

   If $sysinf_ini = "Yes" Then SystemInfo()

   If $proc_ini = "Yes" Then Processes()

   If $srvs_ini = "Yes" Then Services()

   If $acctinfo_ini = "Yes" Then AccountInfo()

   If $autorun_ini = "Yes" Then AutoRun()

   If $st_ini = "Yes" Then ScheduledTasks()

   If $fassoc_ini = "Yes" Then FileAssociation()

   If $hostn_ini = "Yes" Then Hostname()

   If $NTFS_ini = "Yes" Then NTFSInfo()

   If $VolInfo_ini = "Yes" Then VolInfo()

   If $mntdsk_ini = "Yes" Then MountedDisk()

   If $dir_ini = "Yes" Then Directory()

   If $evt_ini = "Yes" Then EvtCopy()

   If $regrip_ini = "Yes" Then
	  RegRipperTools()
	  RegRipper()
   EndIf

   If $md5_ini = "Yes" Then MD5()

   If $sha1_ini = "Yes" Then SHA1()

   If $compress_ini = "Yes" Then Compression()

   CommandROSLOG()

EndFunc

Func MemDump()

   Local $dmpN = @ComputerName & @YEAR & @MON & @MDAY & @HOUR & @MIN & @SEC & @MSEC & '.bin'
   Local $dmpl = @ComputerName & @YEAR & @MON & @MDAY & @HOUR & @MIN & @SEC & @MSEC & '.txt'     ;Added Memory Dump Log
   Local $memFL = '-mem -md5 -o "' & $MemDir & $dmpN & '" -log "' & $MemDir & $dmpL & '"'

   $windd = "FDpro.exe"

;  **Win(32|64)DD from MoonSols**
;  Local $memFL = '/a /f "' & $MemDir & $dmpN & '"'
;
;  If @OSArch = "X86" Then
;		 $windd = "win32dd.exe"
;	  Else
;		 $windd = "win64dd.exe"
;	  EndIf

   ShellExecuteWait($windd, $memFL, '.\Tools\')

   ProcessClose($windd)

   	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $windd & $memFL & @CRLF)

   ProcessWaitClose($windd)

EndFunc

Func Processes()						;Gather running process information
   Local $proc1 = $shellex & ' tasklist /V /FO CSV > "' & $RptsDir & '\Processes.csv"'
   Local $proc2 = $shellex & ' .\Tools\SysinternalsSuite\pslist -accepteula >> "' & $RptsDir & '\Processes.txt"'
   Local $proc3 = $shellex & ' .\Tools\SysinternalsSuite\pslist -t -accepteula >> "' & $RptsDir & '\ProcessTree.txt"'

   RunWait($proc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $proc1 & @CRLF)
   RunWait($proc2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $proc2 & @CRLF)
   RunWait($proc3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $proc3 & @CRLF)
EndFunc

Func IPs()								;Gather network address for the computer
   Local $ip1 = $shellex & ' ipconfig /all > "' & $RptsDir & '\IPConfigInfo.txt"'
   Local $ip2 = $shellex & ' netsh int ip show config > "' & $RptsDir & '\IPInterfaceInfo.txt"'

   RunWait($ip1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $ip1 & @CRLF)
   RunWait($ip2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $ip2 & @CRLF)
EndFunc

Func Connections()						;Discover any network connections on the PC
   Local $Conn1 = $shellex & ' netstat -nao > "' & $RptsDir & '\NetworkConnections.txt"'
   Local $Conn2 = $shellex & ' netstat -naob >> "' & $RptsDir & '\NetworkConnectionsProcesses.txt"'

   RunWait($Conn1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $Conn1 & @CRLF)
   RunWait($Conn2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $Conn2 & @CRLF)
EndFunc

Func Routes()							;Gather list of active routes
   Local $route1 = $shellex & ' route PRINT > "' & $RptsDir & '\RoutesPrint.txt"'
   Local $route2 = $shellex & ' netstat -r >> "' & $RptsDir & '\RoutesNetstat.txt"'
   RunWait($route1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $route1 & @CRLF)
   RunWait($route2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $route2 & @CRLF)
EndFunc

Func NetBIOS()							;Get NetBIOS information
   Local $nbt1 = $shellex & ' nbtstat.exe -A 127.0.0.1 > "' & $RptsDir & '\NBTstat.txt"'

   RunWait($nbt1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $nbt1 & @CRLF)
EndFunc

Func Arp()								;Gather information regarding ARP
   Local $arp1 = $shellex & ' arp -a > "' & $RptsDir & '\ARPTable.txt"'

   RunWait($arp1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $arp1 & @CRLF)
EndFunc

Func DNS()								;Gather DNS information
   Local $dns1 = $shellex & ' ipconfig /displaydns > "' & $RptsDir & '\DNSInfo.txt"'
   Local $dns2 = $shellex & ' nslookup host server >> "' & $RptsDir & '\DNSnslookup.txt"'

   RunWait($dns1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $dns1 & @CRLF)
   RunWait($dns2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $dns2 & @CRLF)
EndFunc

Func Shares()							;Gather information on any shared folders
   Local $share1 = $shellex & ' net share > "' & $RptsDir & '\LocalShares.txt"'

   RunWait($share1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $share1 & @CRLF)
EndFunc

Func SharedFiles()						;Gather information on any shared files
   Local $sfile1 = $shellex & ' net file > "' & $RptsDir & '\OpenSharedFiles.txt"'

   RunWait($sfile1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sfile1 & @CRLF)
EndFunc

Func ConnectedSessions()				;Gather information on any connected sessions
   Local $ConnSes = $shellex & ' net Session > "' & $RptsDir & '\Sessions.txt"'

   RunWait($ConnSes, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $ConnSes & @CRLF)
EndFunc

Func Firewall()							;Get the firewall information
   Local $fw1 = $shellex & ' netsh firewall show state > "' & $RptsDir & '\FirewallConfig.txt"'
   Local $fw2 = $shellex & ' netsh advfirewall show allprofiles >> "' & $RptsDir & '\FirewallConfig.txt"'

   RunWait($fw1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $fw1 & @CRLF)
   RunWait($fw2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $fw2 & @CRLF)
EndFunc

Func Hosts()							;Gather the HOST file
   Local $host1 = $shellex & ' type %systemroot%\System32\Drivers\etc\hosts > "' & $RptsDir & '\HostsFile.txt"'

   RunWait($host1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $host1 & @CRLF)
EndFunc

Func Workgroups()						;Gather possible information on PC Workgroups
   Local $wkgrp1 = $shellex & ' net view > "' & $RptsDir & '\NetView.txt"'

   RunWait($wkgrp1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $wkgrp1 & @CRLF)
EndFunc

Func SystemInfo()						;Gather valuable information regarding type of PC
   Local $sysinfo1 = $shellex & ' .\Tools\SysinternalsSuite\PsInfo -accepteula -s -d > "' & $RptsDir & '\SystemDetails.txt"'
   Local $sysinfo2 = $shellex & ' systeminfo >> "' & $RptsDir & '\SystemInfo.txt"'
   Local $sysinfo3 = $shellex & ' set >> "' & $RptsDir & '\SystemVariables.txt"'

   RunWait($sysinfo1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sysinfo1 & @CRLF)
   RunWait($sysinfo2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sysinfo2 & @CRLF)
   RunWait($sysinfo3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sysinfo3 & @CRLF)
EndFunc

Func Services()							;Pertinent services information
   Local $serv1 = $shellex & ' .\Tools\SysinternalsSuite\psservice -accepteula > "' & $RptsDir & '\ServiceProcesses.txt"'
   Local $serv2 = $shellex & ' sc queryex > "' & $RptsDir & '\ServiceQuery.txt"'
   Local $serv3 = $shellex & ' net start >> "' & $RptsDir & '\ServicesStarted.txt"'

   RunWait($serv1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $serv1 & @CRLF)
   RunWait($serv2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $serv2 & @CRLF)
   RunWait($serv3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $serv3 & @CRLF)
EndFunc

Func FileAssociation()					;Get information on file associations
   Local $fa1 = $shellex & ' .\Tools\SysinternalsSuite\handle -a -accepteula c > "' & $RptsDir & '\Handles.txt"'

   RunWait($fa1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $fa1 & @CRLF)
EndFunc

Func AccountInfo()						;Gather information pertaining to the user accounts
   Local $acctinfo1 = $shellex & ' net accounts > "' & $RptsDir & '\AccountDetails.txt"'

   RunWait($acctinfo1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $acctinfo1 & @CRLF)
EndFunc

Func Hostname()							;Gather information on the hostname
   Local $hostn1 = $shellex & ' whoami > "' & $RptsDir & '\Hostname.txt"'
   Local $hostn2 = $shellex & ' hostname >> "' & $RptsDir & '\Hostname.txt"'

   RunWait($hostn1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $hostn1 & @CRLF)
   RunWait($hostn2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $hostn2 & @CRLF)
EndFunc

Func Prefetch()							;Copy any prefecth data while maintaining metadata
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $pf1 = $shellex & ' ' & $robocopy & ' "' & @WindowsDir & '\Prefetch" "' & $EvDir & '\Prefetch" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\PrefetchCopyLog.txt"'

   If Not FileExists($EvDir & "\Prefetch") Then DirCreate($EvDir & "\Prefetch")

   ShellExecuteWait($robocopy, ' "' & @WindowsDir & '\Prefetch" "' & $EvDir & '\Prefetch" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\PrefetchCopyLog.txt"', $tools, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $pf1 & @CRLF)
EndFunc

Func RecentFolder()						;Send information to the recent folder copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")

   While 1

	  $profs = FileFindNextFile($usr)

		 If @error then ExitLoop

	  $uDir = $uPath & $profs

	  $uATB = FileGetAttrib($uDir)

	  If StringInStr($uATB, "D") Then _RobocopyRF($udir, $profs)

   WEnd
EndFunc

Func _RobocopyRF($path, $output)		;Copy Recent folder from all profiles while maintaining metadata

   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($EvDir & '\Recent LNKs\' & $output) Then DirCreate($EvDir & '\Recent LNKs\' & $output)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

	  If $OS = "Users" Then
			$recPATH = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent"'
		 Else
			$recPATH = '"' & $path & '\Recent"'
		 EndIf

   Local $recF1 = $robocopy & " " & $recPATH & ' "' & $EvDir & '\Recent LNKs\' & $output & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Recent LNKs\' & $output & '_Recent_Copy.txt"'

   RunWait($recF1, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $recF1 & @CRLF)
EndFunc

Func JumpLists()						;Provide info to the Jumplist copy function
   Local $usr
   Local $profs
   Local $uDir
   Local $uATB
   Local $uPath
   Local $OS
   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   If $OS = "Users" Then
		 $uPath = "C:\Users\"
	  Else
	   $uPath = "C:\Documents and Settings\"
	EndIf

	  $usr = FileFindFirstFile($uPath & "*.*")

	  While 1

		 $profs = FileFindNextFile($usr)

			If @error then ExitLoop

		 $uDir = "C:\Users\" & $profs

		 $uATB = FileGetAttrib($uDir)

		 If StringInStr($uATB, "D") Then _RobocopyJL($udir, $profs)

	  WEnd
EndFunc

Func _RobocopyJL($path, $output)		;Copy Jumplist information while maintaining metadata

   Local $robocopy
   Local $robocmd
   Local $autodest
   Local $customdest
   Local $shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
   Local $autodest = $EvDir & '\Jump Lists\' & $output & '\Automatic'
   Local $customdest = $EvDir & '\Jump Lists\' & $output & '\Custom'

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($autodest) Then DirCreate($autodest)
   If Not FileExists($customdest) Then DirCreate($customdest)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   $autoexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"'
   $customexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"'

   Local $jla1 = $robocopy & " " & $autoexe1 & ' "' & $autodest & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Auto_Copy.txt"'
   Local $jlc1 = $robocopy & " " & $customexe1 & ' "' & $customdest & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & '\Jump Lists\' & $output & '_JumpList_Custom_Copy.txt"'

   RunWait($jla1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $jla1 & @CRLF)
   RunWait($jlc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $jlc1 & @CRLF)

EndFunc

Func AutoRun()							;Information regarding startup
   Local $autorun1 = $shellex & ' .\Tools\SysinternalsSuite\autorunsc.exe -accepteula > "' & $RptsDir & '\AutoRunInfo.txt"'
   Local $autorun2 = $shellex & ' wmic startup list full > "' & $RptsDir & '\StartUpWMIInfo.txt"'
   Local $autorun3 = $shellex & ' .\Tools\SysinternalsSuite\autorunsc.exe -accepteula -a * -s -c > "' & $RptsDir & '\AutoRunInfo.csv"'

   RunWait($autorun1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $autorun1 & @CRLF)
   RunWait($autorun2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $autorun2 & @CRLF)
   RunWait($autorun3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $autorun3 & @CRLF)
EndFunc

Func LoggedOn()							;Gather information on users logged on
   Local $logon1 = $shellex & ' .\Tools\SysinternalsSuite\PsLoggedon -accepteula > "' & $RptsDir & '\LoggedOn.txt"'
   Local $logon2 = $shellex & ' .\Tools\SysinternalsSuite\logonsessions -accepteula -c >> "' & $RptsDir & '\LoggedOnUsers.txt"'

   RunWait($logon1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $logon1 & @CRLF)
   RunWait($logon2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $logon2 & @CRLF)
EndFunc

Func NTFSInfo()							;Gather information regarding NTFS
   Local $ntfs1 = $shellex & ' .\Tools\SysinternalsSuite\ntfsinfo c > "' & $RptsDir & '\NTFSInfo.txt"'
   Local $ntfs2 = $shellex & ' fsutil fsinfo ntfsinfo C: >> "' & $RptsDir & '\NTFSInfo.txt"'

   RunWait($ntfs1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $ntfs1 & @CRLF)
   RunWait($ntfs2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $ntfs2 & @CRLF)
EndFunc

Func VolInfo()							;Gather volume information with the Sleuth Kit
	  Local $vol1 = $shellex & ' fsutil fsinfo volumeinfo C: >> "' & $RptsDir & '\VolumeInfo.txt"'

   RunWait($vol1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $vol1 & @CRLF)
EndFunc

Func MountedDisk()						;Mounted Disk Information
   Local $md1 = $shellex & ' .\Tools\SysinternalsSuite\diskext -accepteula > "' & $RptsDir & '\DiskMounts.txt"'

   RunWait($md1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $md1 & @CRLF)
EndFunc

Func Directory()						;Get list of directory structure
   Local $dir1 = $shellex & ' tree c:\ /f /a > "' & $RptsDir & '\DirectoryInfo.txt"'

   RunWait($dir1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $dir1 & @CRLF)
EndFunc

Func ScheduledTasks()					;List any scheduled tasks
   Local $schedtask1 = $shellex & ' schtasks /query /FO CSV /V > "' & $RptsDir & '\ScheduledTasks.csv"'

   RunWait($schedtask1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $schedtask1 & @CRLF)
EndFunc

Func SystemRRip()						;Copy the SYSTEM HIV for analysis
   Local $sysrip

   If @OSVersion = "WIN_XP" Then
	  $sysrip = $shellex & ' REG SAVE HKLM\SYSTEM "' & $EvDir & 'SYSTEM_' & @ComputerName & '.hiv"'
   Else
	  $sysrip = $shellex & ' REG SAVE HKLM\SYSTEM "' & $EvDir & 'SYSTEM_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($sysrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sysrip & @CRLF)
EndFunc

Func SecurityRRip()						;Copy the SECURITY HIV for analysis
   Local $secrip

   If @OSVersion = "WIN_XP" Then
	  $secrip = $shellex & ' REG SAVE HKLM\SECURITY "' & $EvDir & 'SECURITY_' & @ComputerName & '.hiv"'
   Else
	  $secrip = $shellex & ' REG SAVE HKLM\SECURITY "' & $EvDir & 'SECURITY_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($secrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $secrip & @CRLF)
EndFunc

Func SAMRRip()							;Copy the SAM HIV for analysis
   Local $samrip

   If @OSVersion = "WIN_XP" Then
	  $samrip = $shellex & ' REG SAVE HKLM\SAM "' & $EvDir & 'SAM_' & @ComputerName & '.hiv"'
   Else
	  $samrip = $shellex & ' REG SAVE HKLM\SAM "' & $EvDir & 'SAM_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($samrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $samrip & @CRLF)
EndFunc

Func SoftwareRRip()						;Copy the SOFTWARE HIV for analysis
   Local $softrip

   If @OSVersion = "WIN_XP" Then
	  $softrip = $shellex & ' REG SAVE HKLM\SOFTWARE "' & $EvDir & 'SOFTWARE_' & @ComputerName & '.hiv"'
   Else
	  $softrip = $shellex & ' REG SAVE HKLM\SOFTWARE "' & $EvDir & 'SOFTWARE_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($softrip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $softrip & @CRLF)
EndFunc

Func HKCURRip()							;Copy the HKCU HIV for analysis
   Local $hkcurip

   If @OSVersion = "WIN_XP" Then
	  $hkcurip = $shellex & ' REG SAVE HKCU "' & $EvDir & '\HKCU_' & @ComputerName & '.hiv"'
   Else
	  $hkcurip = $shellex & ' REG SAVE HKCU "' & $EvDir & '\HKCU_' & @ComputerName & '.hiv" /y'
   EndIf

   RunWait($hkcurip, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $hkcurip & @CRLF)
EndFunc

Func NTUserRRip()						;Copy all NTUSER.dat files from each profile
   Local $s_Out = ""

  $h_Proc = Run(@ComSpec & " /c " & "REG QUERY HKU", "", @SW_HIDE, 0x08)

   While 1
	  $sTemp = StdoutRead($h_Proc)
		 $s_Out &= $sTemp
		 If @error Then ExitLoop
   WEnd

   $aLines = StringRegExp($s_Out, "(?m:^)\h*\S.+(?:\v|$)+", 3)

   If Not @error Then
	  For $i = 0 To UBound($aLines) - 1
		 $s_Val = $aLines[$i]
		 $s_Val = StringStripWS($s_Val, 2)

			Local $nturip

			If @OSVersion = "WIN_XP" Then
			   $nturip = $shellex & ' REG SAVE ' & $s_Val & ' "' & $EvDir & '\' & @ComputerName &'_USER_' & $i+1 & '.dat"'
			Else
			   $nturip = $shellex & ' REG SAVE ' & $s_Val & ' "' & $EvDir & '\' & @ComputerName &'_USER_' & $i+1 & '.dat" /y'
			EndIf

			RunWait($nturip, "", @SW_HIDE)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $nturip & @CRLF)
	  Next
   EndIf
EndFunc

Func MD5()								;Special thanks to Jesse Kornblum for his amazing hashing tools
   Local $md51 = $shellex & ' .\Tools\md5deep -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\MD5Hashes.txt"'
   Local $md52 = $shellex & ' .\Tools\md5deep64 -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\MD5Hashes.txt"'

   If @OSArch = "X86" Then
	  $arch = "32"
   Else
	  $arch = "64"
   EndIf

   If $arch = "32" Then
	  RunWait($md51, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $md51 & @CRLF)
   EndIf

   If $arch = "64" Then
	  RunWait($md52, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $md52 & @CRLF)
   EndIf
EndFunc

Func SHA1()								;Special thanks to Jesse Kornblum for his amazing hashing tools
   Local $sha11 = $shellex & ' .\Tools\sha1deep -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\SHA1Hashes.txt"'
   Local $sha12 = $shellex & ' .\Tools\sha1deep64 -rbtk "' & $HashDir & '" >> "' & $RptsDir & '\SHA1Hashes.txt"'

   If @OSArch = "X86" Then
	  $arch = "32"
   Else
	  $arch = "64"
   EndIf

   If $arch = "32" Then
	  RunWait($sha11, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sha11 & @CRLF)
   EndIf

   If $arch = "64" Then
	  RunWait($sha12, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sha12 & @CRLF)
   EndIf
EndFunc

Func Compression()						;Special thanks to the 7-Zip team such a great tool
   ShellExecuteWait(".\Tools\7za.exe" , 'a -mx9 -r "' & $RptsDir & '" *.txt *.hiv *.raw *.lnk *.dat *.pf *.evt *.evtx *.automaticDestinations-ms *.customDestinations-ms *.csv *.dmp', $tools, "", @SW_HIDE)
EndFunc

Func RegRipper()						;Special thanks to Harlan Carvey for his excellent tool.

   Local $syshiv = 'SYSTEM_' & @ComputerName & '.hiv'
   Local $softhiv = 'SOFTWARE_' & @ComputerName & '.hiv'
   Local $samhiv = 'SAM_' & @ComputerName & '.hiv'
   Local $sechiv = 'SECURITY_' & @ComputerName & '.hiv'
   Local $hkcuhiv = 'HKCU_' & @ComputerName & '.hiv'
   Local $sysexe1 = $shellex & ' .\Tools\RegRipper\rip.exe -r "' & $EvDir & $syshiv & '" -f system > "' & $EvDir & 'SYSTEM_Ripped_Report.txt"'
   Local $softexe1 = $shellex & ' .\Tools\RegRipper\rip.exe -r "' & $EvDir & $softhiv & '" -f software > "' & $EvDir & 'SOFTWARE_Ripped_Report.txt"'
   Local $samexe1 = $shellex & ' .\Tools\RegRipper\rip.exe -r "' & $EvDir & $samhiv & '" -f sam > "' & $EvDir & 'SAM_Ripped_Report.txt"'
   Local $secexe1 = $shellex & ' .\Tools\RegRipper\rip.exe -r "' & $EvDir & $sechiv & '" -f security > "' & $EvDir & 'SECURITY_Ripped_Report.txt"'
   Local $ntuexe1 = $shellex & ' .\Tools\RegRipper\rip.exe -r "' & $EvDir & $hkcuhiv & '" -f NTUSER > "' & $EvDir & 'NTUSER_Ripped_Report.txt"'

   RunWait($sysexe1, "", @SW_HIDE)
   	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $sysexe1 & @CRLF)
   RunWait($softexe1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $softexe1 & @CRLF)
   RunWait($samexe1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $samexe1 & @CRLF)
   RunWait($secexe1, "", @SW_HIDE)
 	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $secexe1 & @CRLF)
   RunWait($ntuexe1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $ntuexe1 & @CRLF)

	  Local $dat = FileFindFirstFile($EvDir & "*.dat")

	  While 1

		 Local $nxtdat = FileFindNextFile($dat)
		 Local $ntuexe2 = $shellex & ' .\Tools\RegRipper\rip.exe -r "' & $EvDir & $nxtdat & '" -f NTUSER > "' & $EvDir & $nxtdat & '_Ripped_Report.txt"'

		 If @Error Then ExitLoop

		 RunWait($ntuexe2, "", @SW_HIDE)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $ntuexe2 & @CRLF)

	  WEnd

EndFunc

Func SysIntAdd()						;Add registry key to accept Sysinternals
   Local $RegAdd1 = $shellex & ' REG ADD HKCU\Software\Sysinternals\NTFSInfo /v EulaAccepted /t REG_DWORD /d 1 /f'

   RunWait($RegAdd1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $RegAdd1 & @CRLF)
EndFunc

Func EvtCopy()							;Copy all event logs from local machine
   Local $OS
   Local $evtdir
   Local $evtext
   Local $LogDir = $EvDir & 'Logs'
   Local $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local $robo7 = '"' & @ScriptDir & '\Tools\robo7.exe"'

   Local $evtc1 = $shellex & ' .\Tools\SysinternalsSuite\psloglist.exe -accepteula -s Application > "' & $RptsDir & '\ApplicationLog.csv"'
   Local $evtc2 = $shellex & ' .\Tools\SysinternalsSuite\psloglist.exe -accepteula -s System > "' & $RptsDir & '\SystemLog.csv"'
   Local $evtc3 = $shellex & ' .\Tools\SysinternalsSuite\psloglist.exe -accepteula -s Security > "' & $RptsDir & '\SecurityLog.csv"'

   RunWait($evtc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $evtc1 & @CRLF)

   RunWait($evtc2, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $evtc2 & @CRLF)

   RunWait($evtc3, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $evtc3 & @CRLF)

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Docs" Then $evtdir = '"C:\Windows\system32\config"'
   If $OS = "Users" Then $evtdir = '"C:\Windows\system32\winevt\Logs"'

   If $OS = "Docs" Then $evtext = "evt"
   If $OS = "Users" Then $evtext = "evtx"

   If Not FileExists($LogDir) Then DirCreate($LogDir)

   If $OS = "Docs" Then $EvtCmd = $robocopy & " " & $evtdir & ' "' & $LogDir & '" *.' & $evtext & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\EventLogCopy.txt"'
   If $OS = "Users" Then $EvtCmd = $robo7 & " " & $evtdir & ' "' & $LogDir & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $RptsDir & '\EventLogCopy.txt"'

   RunWait($EvtCmd, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Copied ." & $evtext & " files from " & $evtdir & "." & @CRLF)
EndFunc

Func UsrclassE()  						;Search for profiles and initiate the copy of USRCLASS.dat

   Local $OS, $uPath, $usr, $profs, $uDir, $uPath, $uATB

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   If $OS = "Users" Then $uPath = "C:\Users\"
   If $OS = "Docs" Then $uPath = "C:\Documents and Settings\"

   $usr = FileFindFirstFile($uPath & "*.*")

   While 1

	  $profs = FileFindNextFile($usr)

		 If @error then ExitLoop

	  $uDir = $uPath & "\" & $profs

	  $uATB = FileGetAttrib($uDir)

	  If StringInStr($uATB, "D") Then _Usrclass($profs)

   WEnd

EndFunc

Func _Usrclass($prof)					;Performs the function of copying the USRCLASS.dat

   Local $profUsrCls = '/users/' & $prof & '/appdata/local/microsoft/windows/usrclass.dat'

   If FileExists($profUsrCls) = 1 Then

		Local $usrce = $shellex & ' .\Tools\sleuthkit-4.2.0\bin\ifind.exe -n /users/' & $prof & '/appdata/local/microsoft/windows/usrclass.dat \\.\C: > MFTEntries.log'

		RunWait($usrce)

			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $usrce & @CRLF)

		$MFTlog = FileReadLine("MFTEntries.log")

		Local $catusrce = $shellex & ' .\Tools\sleuthkit-4.2.0\bin\icat.exe \\.\c: ' & $MFTlog & ' > "' & $EvDir & $prof & '-usrclass.dat1"'

		RunWait($catusrce, "", @SW_HIDE)

			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $catusrce & @CRLF)

		FileDelete("MFTEntries.log")

   Else
		FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB& "File NOT Found."&@TAB& $profUsrCls & @CRLF)
   EndIf

EndFunc

Func MFTgrab()							;Use iCat to rip a file from NTFS file system

   Local $MFTc = $shellex & ' .\Tools\sleuthkit-4.2.0\bin\icat.exe \\.\c: 0 > "' & $EvDir & '$MFTcopy"'

   RunWait($MFTc, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $MFTc & @CRLF)
   EndFunc

Func GetShadowNames()					;Query WMIC for list of Volume Shadow Copy mount points

   Local	$strComputer = "."
   Local	$objWMIService = ObjGet("winmgmts:" _
			   & "{impersonationLevel=impersonate}!\\" & $strComputer & "\root\cimv2")
   Local	$colAdapters = $objWMIService.ExecQuery _
			   ("Select * from Win32_ShadowCopy")

   $n = 1
   $str = ''
   For $objList In $colAdapters
	  $str &= $objList.DeviceObject & @CRLF
   Next

   FileWrite("VSCmnts.txt", $str)

EndFunc

Func MountVSCs()						;Mount any Volume Shadow Copies found on the PC

   Local $v = 1

   Do
	  $mntpt = FileReadLine("VSCmnts.txt", $v)
	  If $mntpt = "" Then ExitLoop
	  $mntvsccmd = @ComSpec & ' /c mklink /D C:\VSC_' & $v & " " & $mntpt & "\"
	  Run($mntvsccmd, "", @SW_HIDE)
	  $v = $v + 1
   Until $v = _FileCountLines("VSCmnts.txt") + 1

EndFunc

Func VSC_Prefetch()						;Copy Prefetch data from any Volume Shadow Copies

   Local $robocopy = '"' & @ScriptDir & '\Tools\Robocopy.exe"'
   Local $v = 1
   Local $vscpf1 = $shellex & ' ' & $robocopy & ' "C:\VSC_' & $v & '\Windows\Prefetch" "' & $EvDir & '\VSC_' & $v & '\Prefetch" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & 'VSC_' & $v & '\VSC_' & $v & ' Prefetch Copy Log.txt"'

   Do
	  If FileExists("C:\VSC_" & $v) = 1 Then
		 If Not FileExists($EvDir & "\VSC_" & $v &"\Prefetch") Then DirCreate($EvDir & "\VSC_" & $v &"\Prefetch")
			ShellExecuteWait($robocopy, ' "C:\VSC_' & $v & '\Windows\Prefetch" "' & $EvDir & '\VSC_' & $v & '\Prefetch" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & 'VSC_' & $v & '\VSC_' & $v & ' Prefetch Copy Log.txt"', $tools)
			   FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $vscpf1 & @CRLF)
		 $v = $v + 1
	  Else
		 ExitLoop
	  EndIf
   Until FileExists("C:\VSC_" & $v) = 0

EndFunc

Func VSC_RecentFolder()					;Send information to the recent folder copy function (Volume Shadow Copy version)
   Global	$vrfc = 1
   Local 	$usr
   Local 	$profs
   Local 	$uDir
   Local 	$uATB
   Local 	$uPath
   Local 	$OS
   Local 	$robocopy
   Local 	$robocmd
   Local 	$robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local 	$uPath

   Do
	  If FileExists("C:\VSC_" & $vrfc) = 1 Then
	  $upath = "C:\VSC_" & $vrfc & "\Users\"
		 $usr = FileFindFirstFile($uPath & "*.*")
			While 1
			   $profs = FileFindNextFile($usr)
			   If @error then ExitLoop
			   $uDir = $uPath & "\" & $profs
			   $uATB = FileGetAttrib($uDir)
			   If StringInStr($uATB, "D") Then VSC_RobocopyRF($udir, $profs)
			WEnd
		 $vrfc = $vrfc + 1
	  Else
		 ExitLoop
	  EndIf
   Until FileExists("C:\VSC_" & $vrfc) = 0

EndFunc

Func VSC_RobocopyRF($path, $output)		;Copy Recent folder from all profiles while maintaining metadata (Volume Shadow Copy version)

   Local $robocopy
   Local $robocmd

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_XP" Then $OS = "Docs"
   If @OSVersion = "WIN_VISTA" Then $OS = "Users"
   If @OSVersion = "WIN_XPe" Then $OS = "Docs"
   If @OSVersion = "WIN_2003" Then $OS = "Docs"
   If @OSVersion = "WIN_2008" Then $OS = "Users"
   If @OSVersion = "WIN_2008R2" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output) Then DirCreate($EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

	  If $OS = "Users" Then
			$recPATH = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent"'
		 Else
			$recPATH = '"' & $path & '\Recent"'
		 EndIf

   Local $vscrf1 = $robocopy & " " & $recPATH & ' "' & $EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & 'VSC_' & $vrfc & '\Recent LNKs\' & $output & '_RecentFolder_Copy.txt"'

   RunWait($vscrf1, "", @SW_HIDE)
		 FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $vscrf1 & @CRLF)
	  EndFunc

Func VSC_JumpLists()					;Provide info to the Jumplist copy function (Volume Shadow Copy version)
   Global 	$vjlc = 1
   Local 	$usr
   Local 	$profs
   Local 	$uDir
   Local 	$uATB
   Local 	$uPath
   Local 	$OS
   Local 	$robocopy
   Local 	$robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   Do
	  If FileExists("C:\VSC_" & $vjlc) = 1 Then

	  $uPath = "C:\VSC_" & $vjlc & "\Users\"

	  $usr = FileFindFirstFile($uPath & "*.*")

	  While 1

		 $profs = FileFindNextFile($usr)

			If @error then ExitLoop

		 $uDir = "C:\VSC_" & $vjlc& "\Users\" & $profs

		 $uATB = FileGetAttrib($uDir)

		 If StringInStr($uATB, "D") Then VSC_RobocopyJL($udir, $profs)

	  WEnd

	  $vjlc = $vjlc + 1

   	  Else
		 ExitLoop
	  EndIf

   Until FileExists("C:\VSC_" & $vjlc) = 0

EndFunc

Func VSC_RobocopyJL($path, $output)		;Copy Jumplist information while maintaining metadata (Volume Shadow Copy version)

   Local $robocopy
   Local $robocmd
   Local $autodest
   Local $customdest
   Local $shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
   Local $autodest = $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Automatic'
   Local $customdest = $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Custom'

   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($autodest) Then DirCreate($autodest)
   If Not FileExists($customdest) Then DirCreate($customdest)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   $autoexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"'
   $customexe1 = '"' & $path & '\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"'

   Local $vscjla1 = $robocopy & " " & $autoexe1 & ' "' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Automatic" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '_JumpList_Auto_Copy.txt"'
   Local $vscjlc1 = $robocopy & " " & $customexe1 & ' "' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '\Custom" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vjlc & '\Jump Lists\' & $output & '_JumpList_Custom_Copy.txt"'

   RunWait($vscjla1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $vscjla1 & @CRLF)
   RunWait($vscjlc1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $vscjlc1 & @CRLF)

EndFunc

Func VSC_EvtCopy()						;Copy all event logs from local machine (Volume Shadow Copy version)
   Global 	$vevc = 1
   Local 	$OS
   Local 	$evtdir
   Local 	$evtext
   Local 	$LogDir = $EvDir & "VSC_" & $vevc & '\Logs'
   Local 	$robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'
   Local 	$robo7 = '"' & @ScriptDir & '\Tools\robo7.exe"'
   Local 	$evtdir = '"C:\VSC_' & $vevc & '\Windows\system32\winevt\Logs"'
   Local 	$evtext = "evtx"

   Do

	  If FileExists("C:\VSC_" & $vevc) = 1 Then

		 If Not FileExists($LogDir) Then DirCreate($LogDir)

		 Local $VSC_EvtCmd = $robo7 & ' "C:\VSC_' & $vevc & '\Windows\system32\winevt\Logs" "' & $EvDir & "VSC_" & $vevc & '\Logs' & '" /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vevc & '\EventLogCopy.txt"'

		 RunWait($VSC_EvtCmd, "", @SW_HIDE)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Copied ." & $evtext & " files from " & $evtdir & "." & @CRLF)

		 $vevc = $vevc + 1

	  Else
		 ExitLoop
	  EndIf

   Until FileExists("C:\VSC_" & $vevc) = 0

EndFunc

Func VSC_RegHiv($hiv)					;Copy Registry Hive from Volume Shadow Copy
   Local $v = 1
   Local $robo7 = '"' & @ScriptDir & '\Tools\robo7.exe"'

   Do

	  If FileExists("C:\VSC_" & $v) = 1 Then

		 Local $vhivout = $EvDir & "VSC_" & $v & "\Registry"
		 Local $vhivfile = "C:\VSC_" & $v & "\Windows\System32\Config"

		 If Not FileExists($vhivout) Then DirCreate($vhivout)

		 Local $vsc_syshivc = $robo7 & ' "' & $vhivfile & '" "' & $vhivout & '" ' & $hiv & ' /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $vhivout & '\SYSTEM_Log_Copy.txt"'

		 RunWait($vsc_syshivc, "", @SW_HIDE)
			FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $vsc_syshivc & @CRLF)

		 $v = $v + 1

		 Else
			ExitLoop
		 EndIf

   Until FileExists("C:\VSC_" & $v) = 0

   EndFunc

Func VSC_NTUser()						;Copy NTUSER.dat from Volume Shadow Copy
   Global 	$vntc = 1
   Local 	$usr
   Local 	$profs
   Local 	$uDir
   Local 	$uATB
   Local 	$uPath
   Local 	$OS
   Local 	$robocopy
   Local 	$robocmd

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   Do
	  If FileExists("C:\VSC_" & $vntc) = 1 Then

	  $uPath = "C:\VSC_" & $vntc & "\Users\"

	  $usr = FileFindFirstFile($uPath & "*.*")

	  While 1

		 $profs = FileFindNextFile($usr)

			If @error then ExitLoop

		 $uDir = "C:\VSC_" & $vntc& "\Users\" & $profs

		 $uATB = FileGetAttrib($uDir)

		 If StringInStr($uATB, "D") Then VSC_RobocopyNTU($udir, $profs)

	  WEnd

	  $vntc = $vntc + 1

   	  Else
		 ExitLoop
	  EndIf

   Until FileExists("C:\VSC_" & $vntc) = 0

EndFunc

Func VSC_RobocopyNTU($path, $output)	;Copy function for NTUSER.DAT (Volume Shadow Copy version)

   Local $robocopy
   Local $robocmd
   Local $shellex = '"' & @ScriptDir & '\Tools\cmd.exe" /c'
   Local $ntudest = $EvDir & "VSC_" & $vntc & '\Registry\' & $output


   If @OSVersion = "WIN_7" Then $OS = "Users"
   If @OSVersion = "WIN_8" Then $OS = "Users"
   IF @OSVersion = "WIN_10" Then $OS = "Users"

   If Not FileExists($ntudest) Then DirCreate($ntudest)

   $robocopy = '"' & @ScriptDir & '\Tools\robocopy.exe"'

   $ntl = '"' & $path & '"'

   Local $vscntu1 = $robocopy & " " & $ntl & ' "' & $EvDir & "VSC_" & $vntc & '\Registry\' & $output & '" NTUSER.DAT /copyall /ZB /TS /r:4 /w:3 /FP /NP /log:"' & $EvDir & "VSC_" & $vntc & '\Registry\' & $output & '\' & $output & '_NTUSER_Copy.txt"'

   RunWait($vscntu1, "", @SW_HIDE)
	  FileWriteLine($Log, @YEAR&"-"&@MON&"-"&@MDAY&@TAB&@HOUR&":"&@MIN&":"&@SEC&":"&@MSEC&@TAB&"Executed command:" &@TAB& $vscntu1 & @CRLF)

EndFunc

Func SysInternalsDL()					;Function to download that latest version of Sysinternals

   GUICreate("Sysinternals", 120, 30)

   GUICtrlCreateLabel("Update in Progress", 10, 5)

   GUISetState()

   $SysFile = @ScriptDir & '\SysinternalsSuite.zip'

   $sysintl = InetGet("https://download.sysinternals.com/files/SysinternalsSuite.zip", $SysFile, 1, 1)

   If Not FileExists(@ScriptDir & "\Tools\") Then
			   Do
				  DirCreate(@ScriptDir & "\Tools\")
			   Until FileExists(@ScriptDir & "\Tools\")
			EndIf

			   FileInstall(".\Compile\Tools\7za.exe", @ScriptDir & "\Tools\", 0)

   Do
	  Sleep(500)
   Until InetGetInfo($sysintl, 2)

   $sysunzip = '7za.exe e "' & $SysFile & '" -o"' & @ScriptDir & '\Tools\SysinternalsSuite" -y'

   RunWait($sysunzip, "", @SW_HIDE)

   FileDelete($SysFile)
   FileDelete("7za.exe")

   GUIDelete()

   MsgBox(64, "Sysinternals", "The Sysinternals Suite has been downloaded and extracted for use." & @CRLF & @CRLF & "Sysinternals was created by Mark Russinovich and is owned by Microsoft")

EndFunc

Func VSC_IniCount()						;Count the number of VSC functions selected in the INI

   If $VS_PF_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_RF_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_JmpLst_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_EvtCpy_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SYSREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SECREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SAMREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_SOFTREG_ini = "Yes" Then $r_ini = $r_ini + 1

   If $VS_USERREG_ini = "Yes" Then $r_ini = $r_ini + 1

   EndFunc

Func VSC_ChkCount()						;Count the number of VSC functions selected within the GUI

   If (GUICtrlRead($VS_PF_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_RF_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_JmpLst_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_EvtCpy_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SYSREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SECREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SAMREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_SOFTREG_chk) = 1) Then $r_chk = $r_chk + 1

   If (GUICtrlRead($VS_USERREG_chk) = 1) Then $r_chk = $r_chk + 1

EndFunc

Func VSC_rmVSC()						;Remove the mounted VSC directories
   Local $v = 1

   Do
	  Local $vscdir = "C:\VSC_" & $v
	  Local $dirchk = FileExists($vscdir)

	  If $dirchk = 1 Then
		 DirRemove($vscdir)
		 ConsoleWrite($v)
		 $v = $v + 1
	  Else
		 ExitLoop
	  EndIf
   Until $dirchk = 0

   FileDelete("VSCmnts.txt")

EndFunc

Func ProgChkCount()						;Count number of functions executing for GUI Progress Bar

   If (GUICtrlRead($MemDmp_chk) = 1) Then
	  $p_chkc = 1
   Else
	  $p_chkc = 0
   EndIf

   If (GUICtrlRead($PF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($RF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($JmpLst_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SYSTEM_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SOFTWARE_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($HKCU_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($HKU_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($UsrC_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SECURITY_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($SAM_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($MFTg_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_PF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_RF_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_JmpLst_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_EvtCpy_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SYSREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SECREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SAMREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_SOFTREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VS_USERREG_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($sysint_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($IPs_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($DNS_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($ARP_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($NBT_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Routes_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($CONN_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Sessions_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($nShare_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($nFiles_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($WrkgrpPC_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Sys_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Proc_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Serv_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($AcctInfo_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($AutoRun_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($STsk_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($FileAssoc_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Host_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($NTFSInfo_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($VolInfo_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($DiskMnt_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($Tree_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($EvtCpy_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($md5_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($sha1_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($regrip_chk) = 1) Then $p_chkc = $p_chkc + 1
   If (GUICtrlRead($compress_chk) = 1) Then $p_chkc = $p_chkc + 1

EndFunc

Func SelectAll()						;Function to select all functions within a GUI

   GUICtrlSetState($MemDmp_chk, $GUI_CHECKED)
   GUICtrlSetState($PF_chk, $GUI_CHECKED)
   GUICtrlSetState($RF_chk, $GUI_CHECKED)
   GUICtrlSetState($JmpLst_chk, $GUI_CHECKED)
   GUICtrlSetState($SYSTEM_chk, $GUI_CHECKED)
   GUICtrlSetState($SOFTWARE_chk, $GUI_CHECKED)
   GUICtrlSetState($HKCU_chk, $GUI_CHECKED)
   GUICtrlSetState($HKU_chk, $GUI_CHECKED)
   GUICtrlSetState($UsrC_chk, $GUI_CHECKED)
   GUICtrlSetState($SECURITY_chk, $GUI_CHECKED)
   GUICtrlSetState($SAM_chk, $GUI_CHECKED)
   GUICtrlSetState($MFTg_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_PF_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_RF_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_JmpLst_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_EvtCpy_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SYSREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SECREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SAMREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_SOFTREG_chk, $GUI_CHECKED)
   GUICtrlSetState($VS_USERREG_chk, $GUI_CHECKED)
   GUICtrlSetState($sysint_chk, $GUI_CHECKED)
   GUICtrlSetState($IPs_chk, $GUI_CHECKED)
   GUICtrlSetState($DNS_chk, $GUI_CHECKED)
   GUICtrlSetState($ARP_chk, $GUI_CHECKED)
   GUICtrlSetState($NBT_chk, $GUI_CHECKED)
   GUICtrlSetState($Routes_chk, $GUI_CHECKED)
   GUICtrlSetState($CONN_chk, $GUI_CHECKED)
   GUICtrlSetState($Sessions_chk, $GUI_CHECKED)
   GUICtrlSetState($nShare_chk, $GUI_CHECKED)
   GUICtrlSetState($nFiles_chk, $GUI_CHECKED)
   GUICtrlSetState($WrkgrpPC_chk, $GUI_CHECKED)
   GUICtrlSetState($Sys_chk, $GUI_CHECKED)
   GUICtrlSetState($Proc_chk, $GUI_CHECKED)
   GUICtrlSetState($Serv_chk, $GUI_CHECKED)
   GUICtrlSetState($AcctInfo_chk, $GUI_CHECKED)
   GUICtrlSetState($AutoRun_chk, $GUI_CHECKED)
   GUICtrlSetState($STsk_chk, $GUI_CHECKED)
   GUICtrlSetState($FileAssoc_chk, $GUI_CHECKED)
   GUICtrlSetState($Host_chk, $GUI_CHECKED)
   GUICtrlSetState($NTFSInfo_chk, $GUI_CHECKED)
   GUICtrlSetState($VolInfo_chk, $GUI_CHECKED)
   GUICtrlSetState($DiskMnt_chk, $GUI_CHECKED)
   GUICtrlSetState($Tree_chk, $GUI_CHECKED)
   GUICtrlSetState($EvtCpy_chk, $GUI_CHECKED)
   GUICtrlSetState($md5_chk, $GUI_CHECKED)
   GUICtrlSetState($sha1_chk, $GUI_CHECKED)
   GUICtrlSetState($regrip_chk, $GUI_CHECKED)
   GUICtrlSetState($compress_chk, $GUI_CHECKED)

EndFunc

Func SelectNone()						;Function to deselect all functions within the GUI

   GUICtrlSetState($MemDmp_chk, $GUI_UNCHECKED)
   GUICtrlSetState($PF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($RF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($JmpLst_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SYSTEM_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SOFTWARE_chk, $GUI_UNCHECKED)
   GUICtrlSetState($HKCU_chk, $GUI_UNCHECKED)
   GUICtrlSetState($HKU_chk, $GUI_UNCHECKED)
   GUICtrlSetState($UsrC_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SECURITY_chk, $GUI_UNCHECKED)
   GUICtrlSetState($SAM_chk, $GUI_UNCHECKED)
   GUICtrlSetState($MFTg_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_PF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_RF_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_JmpLst_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_EvtCpy_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SYSREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SECREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SAMREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_SOFTREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VS_USERREG_chk, $GUI_UNCHECKED)
   GUICtrlSetState($sysint_chk, $GUI_UNCHECKED)
   GUICtrlSetState($IPs_chk, $GUI_UNCHECKED)
   GUICtrlSetState($DNS_chk, $GUI_UNCHECKED)
   GUICtrlSetState($ARP_chk, $GUI_UNCHECKED)
   GUICtrlSetState($NBT_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Routes_chk, $GUI_UNCHECKED)
   GUICtrlSetState($CONN_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Sessions_chk, $GUI_UNCHECKED)
   GUICtrlSetState($nShare_chk, $GUI_UNCHECKED)
   GUICtrlSetState($nFiles_chk, $GUI_UNCHECKED)
   GUICtrlSetState($WrkgrpPC_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Sys_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Proc_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Serv_chk, $GUI_UNCHECKED)
   GUICtrlSetState($AcctInfo_chk, $GUI_UNCHECKED)
   GUICtrlSetState($AutoRun_chk, $GUI_UNCHECKED)
   GUICtrlSetState($STsk_chk, $GUI_UNCHECKED)
   GUICtrlSetState($FileAssoc_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Host_chk, $GUI_UNCHECKED)
   GUICtrlSetState($NTFSInfo_chk, $GUI_UNCHECKED)
   GUICtrlSetState($VolInfo_chk, $GUI_UNCHECKED)
   GUICtrlSetState($DiskMnt_chk, $GUI_UNCHECKED)
   GUICtrlSetState($Tree_chk, $GUI_UNCHECKED)
   GUICtrlSetState($EvtCpy_chk, $GUI_UNCHECKED)
   GUICtrlSetState($md5_chk, $GUI_UNCHECKED)
   GUICtrlSetState($sha1_chk, $GUI_UNCHECKED)
   GUICtrlSetState($regrip_chk, $GUI_UNCHECKED)
   GUICtrlSetState($compress_chk, $GUI_UNCHECKED)

EndFunc

Func CommandROSLOG()					;Copy the log data from ReactOS command prompt

   Local $ROSlog = @ScriptDir & "\Commands.log"

   If FileExists($ROSlog) = 1 Then
	  FileMove($ROSlog, $RptsDir)
   EndIf

   EndFunc

Func Install()							;Function to install binary files necessary for execution if not already present

			If Not FileExists(@ScriptDir & "\Tools\") Then
			   Do
				  DirCreate(@ScriptDir & "\Tools\")
			   Until FileExists(@ScriptDir & "\Tools\")
			EndIf

			   FileInstall(".\Compile\Tools\7za.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\7za64.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\cmd.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\md5deep.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\md5deep64.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\robo7.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\robocopy.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\sha1deep.exe", @ScriptDir & "\Tools\", 0)
			   FileInstall(".\Compile\Tools\sha1deep64.exe", @ScriptDir & "\Tools\", 0)

			If Not FileExists(@ScriptDir & "\Tools\sleuthkit-4.2.0\bin\") Then
				Do
					DirCreate(@ScriptDir & "\Tools\sleuthkit-4.2.0\bin\")
				Until FileExists(@ScriptDir & "\Tools\sleuthkit-4.2.0\bin\")
			 EndIf

			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\blkcalc.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\blkcat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\blkls.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\blkstat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\fcat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\ffind.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\fls.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\fsstat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\hfind.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\icat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\ifind.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\ils.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\img_cat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\img_stat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\istat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\jcat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\jls.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\libewf.dll", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\libtsk_jni.dll", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\mactime.pl", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\mmcat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\mmls.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\mmstat.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\msvcp100.dll", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\msvcr100.dll", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\tsk_comparedir.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\tsk_gettimes.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\tsk_loaddb.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\tsk_recover.exe", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\bin\zlib.dll", @ScriptDir & "\Tools\sleuthkit-4.2.0\bin\", 0)

			If Not FileExists(@ScriptDir & "\Tools\sleuthkit-4.2.0\lib\") Then
				Do
					DirCreate(@ScriptDir & "\Tools\sleuthkit-4.2.0\lib\")
				Until FileExists(@ScriptDir & "\Tools\sleuthkit-4.2.0\lib\")
			 EndIf

			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\lib\libtsk.lib", @ScriptDir & "\Tools\sleuthkit-4.2.0\lib\", 0)
			   FileInstall(".\Compile\Tools\sleuthkit-4.2.0\lib\libtsk_jni.lib", @ScriptDir & "\Tools\sleuthkit-4.2.0\lib\", 0)

 			If Not FileExists(@ScriptDir & "\Tools\SysinternalsSuite\") Then
 			   Do
 				  DirCreate(@ScriptDir & "\Tools\SysinternalsSuite\")
 			   Until FileExists(@ScriptDir & "\Tools\SysinternalsSuite\")
 			EndIf
 			   FileInstall(".\Compile\Tools\SysinternalsSuite\autorunsc.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
 			   FileInstall(".\Compile\Tools\SysinternalsSuite\diskext.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
			   FileInstall(".\Compile\Tools\SysinternalsSuite\handle.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
			   FileInstall(".\Compile\Tools\SysinternalsSuite\logonsessions.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
			   FileInstall(".\Compile\Tools\SysinternalsSuite\ntfsinfo.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
			   FileInstall(".\Compile\Tools\SysinternalsSuite\PsInfo.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
			   FileInstall(".\Compile\Tools\SysinternalsSuite\pslist.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
 			   FileInstall(".\Compile\Tools\SysinternalsSuite\PsLoggedon.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
 			   FileInstall(".\Compile\Tools\SysinternalsSuite\psloglist.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)
 			   FileInstall(".\Compile\Tools\SysinternalsSuite\PsService.exe", @ScriptDir & "\Tools\SysinternalsSuite\", 0)

EndFunc

Func RegRipperTools()

			If Not FileExists(@ScriptDir & "\Tools\RegRipper\") Then
			   Do
				  DirCreate(@ScriptDir & "\Tools\RegRipper\")
			   Until FileExists(@ScriptDir & "\Tools\RegRipper\")
			EndIf
			   FileInstall(".\Compile\Tools\RegRipper2.8\p2x588.dll", @ScriptDir & "\Tools\RegRipper\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\rip.exe", @ScriptDir & "\Tools\RegRipper\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\rip.pl", @ScriptDir & "\Tools\RegRipper\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\rr.exe", @ScriptDir & "\Tools\RegRipper\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\rr.pl", @ScriptDir & "\Tools\RegRipper\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\shelltimes.pl", @ScriptDir & "\Tools\RegRipper\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\time.pl", @ScriptDir & "\Tools\RegRipper\", 0)

			If Not FileExists(@ScriptDir & "\Tools\RegRipper\plugins\") Then
			   Do
				  DirCreate(@ScriptDir & "\Tools\RegRipper\plugins\")
			   Until FileExists(@ScriptDir & "\Tools\RegRipper\plugins\")
			EndIf

			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\acmru.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\adoberdr.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ahaha.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\aim.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\all", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\amcache.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\aports.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\appcertdlls.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\appcompatcache.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\appcompatcashe_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\appcompatflags.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\appinitdlls.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\applets.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\applets_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\apppaths.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\apppaths_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\appspecific.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ares.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\arpcache.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\assoc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\at.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\at_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\attachmgr.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\attachmgr_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\audiodev.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\auditfail.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\auditpol.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\auditpol_xp.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\autoendtasks.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\autorun.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\backuprestore.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\banner.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\baseline.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\bho.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\bitbucket.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\bitbucket_user.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\brisv.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\btconfig.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\bthport.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cached.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cashed_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cain.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ccleaner.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cdstaginginfo.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\clampi.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\clampitm.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\clsid.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cmd_shell.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cmd_shell_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cmd_shell_u.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cmdproc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cmdproc_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\codeid.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\comdlg32.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\comfoo.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\compdesc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\compname.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\controlpanel.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\cpldontload.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\crashcontrol.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ctrlpnl.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\dcom.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ddm.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ddo.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\decaf.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\defbrowser.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\del.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\del_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\dependency_walker.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\devclass.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\dfrg.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\diag_sr.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\direct.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\direct_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\disablelastaccess.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\disablesr.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\dllsearch.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\dnschanger.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\domains.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\drivers32.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\drwatson.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\emdmgmt.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\environment.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\esent.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\entos.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\eventlog.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\eventlogs.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\fileexts.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\filehistory.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\fileless.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\findexes.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\fw_config.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\gauss.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\gpohist.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\gpohist_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\gthist.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\gtwhitelist.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\handler.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\haven_and_hearth.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\hibernate.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ide.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\identities.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ie_main.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ie_settings.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ie_version.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ie_zones.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\iejava.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\imagedev.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\imagefile.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\init_dlls.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\inprocserver.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\installedcomp.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\installer.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\internet_explorer_cu.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\internet_settings_cu.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\itempos.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\javafx.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\javasoft.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\kankan.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\kb950582.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\kbdcrash.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\knowndev.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\landesk.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\landesk_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\latentbot.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\lazyshell.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\legacy.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\legacy_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\licenses.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\listsoft.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\liveContactsGUID.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\load.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\logonusername.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\lsa_packages.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\lsasecrets.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\macaddr.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\malware.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\menuorder.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mixer.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mixer_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mmc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mmc_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mmo.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mndmru.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mndmru_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mountdev.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mountdev2.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mp2.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mp3.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mpmru.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mrt.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\msis.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\mspaper.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\muicache.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\muicache_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\nero.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\netassist.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\netsvcs.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\network.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\networkcards.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\networklist.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\networklist_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\networkuid.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\nic.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\nic_mst2.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\nic2.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\nolmhash.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ntuser", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ntusernetwork.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\null.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\odysseus.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\officedocs.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\officedocs2010.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\officedocs2010_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\oisc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\olsearch.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\opencandy.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\osversion.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\osversion_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\outlook.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\outlook2.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\pagefile.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\pending.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\phdet.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\photo.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\polacdms.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\policies_u.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\port_dev.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\prefetch.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\printermru.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\printers.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\privoxy.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\productpolicy.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\processor_architecture.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\product.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\productpolicy.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\producttype.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\product.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\profilelist.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\profiler.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\proxysettings.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\publishingwizard.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\putty.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\rdphint.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\rdpnla.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\rdpport.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\reading_locations.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\realplayer6.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\realvnc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\recentdocs.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\recentdocs_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\regback.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\regin.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\regtime.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\regtime_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\removdev.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\renocide.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\revton.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\rlo.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\rootkit_revealer.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\routes.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\runmru.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\runmru_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\safeboot.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\sam", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\samparse.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\samparse_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\schedagent.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\secctr.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\secrets", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\secrets_tln", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\security", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\securityproviders", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\services.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\sevenzip.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\sfc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shares.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shellbags.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shellbags_test.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shellbags_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shellbags_xp.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shellexec.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shellext.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shellfolders.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shelloverlay.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shutdown.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\shutdowncount.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\sizes.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\skype.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\snapshot.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\snapshot_viewer.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\soft_run.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\software", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\spp_clients.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\sql_lastconnect.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\srun_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ssh_host_keys.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\ssid.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\startmenuinternetapps_cu.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\startmenuinternetapps_lm.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\startpage.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\startup.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\stillimage.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\susclient.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\svc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\svc_plus.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\svc_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\svcdll.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\svchost.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\sysinternals.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\sysinternals_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\system", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\systemindex", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\teamviewer", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\termcert.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\termserv.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\timezone.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\tracing", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\tracing_tln", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\trappoll", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\trustrecords", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\trustrecords_tln", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\tsclient.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\tsclient_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\typedpaths.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\typedurls.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\typedurls_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\typedurlstime.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\typedurlstime_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\uac.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\uninstall.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\uninstall_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\unreadmail.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\urlzone.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\urun_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\usb.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\usbdevices.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\usbstor.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\usbstor2.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\usbstor3.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\user_run.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\user_win.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\userassist.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\userassist_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\userinfo.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\userlocsvc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\userclass.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\vawtrak.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\virut.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\vista_bitbucket.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\vmplayer.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\vmware_vsphere_client.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\vnchooksapplicationprefs.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\vncviewer.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\volinfocache.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\wallpaper.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\warcraft3.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\wbem.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\win_cv.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winbackup.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winevt.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winlogon.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winlogon_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winlogon_u.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winnt_cv.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winrar.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winrar_tln.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winrar2.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winscp.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winscp_sessionst.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winver.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winvnc.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\winzip.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\wordwheelquery.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\wpdbusenum.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\xpedition.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\yahoo_cu.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)
			   FileInstall(".\Compile\Tools\RegRipper2.8\plugins\yahoo_lm.pl", @ScriptDir & "\Tools\RegRipper\plugins\", 0)

EndFunc
