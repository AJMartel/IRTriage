#Include <GUiConstants.au3>

;Create GUI
$Main = GUICreate('Case Log', 300, 280)

Opt("GUICoordMode",1)
$CaseNumber = GUICtrlCreateInput('',100,20,160)
$CaseNumberLabel = GUICtrlCreateLabel('Case Number',20,23)
$Examiner = GUICtrlCreateInput('',100,50,160)
$ExaminerLabel = GUICtrlCreateLabel('Examiner',20,53)
$TargetSystem = GUICtrlCreateInput(@ComputerName,100,80,160)
$TargetSystemLabel = GUICtrlCreateLabel('Computername',20,83)
$UserAccount = GUICtrlCreateInput(@UserName,100,110,160)
$UserAccountLabel = GUICtrlCreateLabel('Login Account',20,113)
$ScriptDrive = GUICtrlCreateInput(@ScriptDir,100,140,160)
$ScriptDriveLabel = GUICtrlCreateLabel('Save Drive',20,143)
$TimeZone = GUICtrlCreateInput('',100,170,160)
$TimeZoneLabel = GUICtrlCreateLabel('Time Zone',20,173)
$StartTime = GUICtrlCreateInput(@YEAR&'/'&@MON&'/'&@MDAY&' '&@HOUR&':'&@MIN&':'&@SEC,100,200,160)
$StartTimeLabel = GUICtrlCreateLabel('Start Time',20,203)
$Button_1 = GUICtrlCreateButton ("OK", 170, 240, 0, 0, 0x0001)
$Button_2 = GUICtrlCreateButton ("Exit", 225, 240, 0, 0)
;$checkbox = GUICtrlCreateCheckbox("Save", 20, 240)

GUISetState ()
; Run the GUI until the dialog is closed
While 1
    $msg = GUIGetMsg()
    Select
        Case $msg = $GUI_EVENT_CLOSE
            Exit
        Case $msg = $Button_1
;            $check = GUICtrlRead($checkbox)
            GLOBAL $collectCaseNumber = GUICtrlRead($CaseNumber)
            GLOBAL $collectExaminer = GUICtrlRead($Examiner)
            GLOBAL $collectTargetSystem = GUICtrlRead($TargetSystem)
            GLOBAL $collectUserAccount = GUICtrlRead($UserAccount)
            GLOBAL $collectScriptDrive = GUICtrlRead($ScriptDrive)
            GLOBAL $collectTimeZone = GUICtrlRead($TimeZone)
            GLOBAL $collectStartTime = GUICtrlRead($StartTime)
 ;           If $check = $GUI_CHECKED Then
                IniWrite("Collection.log", "AcquisitionLog", "Case", $collectCaseNumber)
                IniWrite("Collection.log", "AcquisitionLog", "Examiner", $collectExaminer)
                IniWrite("Collection.log", "AcquisitionLog", "Computername", $collectTargetSystem)
                IniWrite("Collection.log", "AcquisitionLog", "LoginAccount", $collectUserAccount)
				IniWrite("Collection.log", "AcquisitionLog", "SaveDrive", $collectScriptDrive)
                IniWrite("Collection.log", "AcquisitionLog", "TimeZone", $collectTimeZone)
                IniWrite("Collection.log", "AcquisitionLog", "StartTime", $collectStartTime)
;            EndIf
            ExitLoop
        Case $msg = $Button_2
            Exit
    EndSelect
Wend