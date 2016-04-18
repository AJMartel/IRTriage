;Coded by UEZ Build 2010-06-30, tweaked by KaFu ;-)
;https://www.autoitscript.com/forum/topic/116468-choosedisplay-log-file-in-real-time/?do=findComment&comment=812827
;Modified by Alain Martel for IRTriage.

#include <File.au3>
#include <GUIConstantsEx.au3>
#include <GuiEdit.au3>
#include <Misc.au3>
#include <WindowsConstants.au3>

analystMsgr()

Func analystMsgr()

Opt("GUIOnEventMode", 1)

Global $iMemo, $new_line, $PreviousStringLenght
Local $width = 1024
Local $height = 600
Local $msgPosition = 578 - 26
Local $msgWidth = $width - 31
Local $msgHeight = $height - $msgPosition - 26

    Local Const $sMessage = "Select a folder"
    ; Display an open dialog to select a file.
    Global $sFileSelectFolder = FileSelectFolder($sMessage, @ScriptDir)
    If @error Then
        ; Display the error message.
        MsgBox($MB_SYSTEMMODAL, "", "You must select a folder!")
		Exit
    EndIf

Local $file = $sFileSelectFolder & "\AnalystMsg.txt"

Global $hGUI = GUICreate("IRTriage Analyst Messager", $width, $height, -1, -1, Default, $WS_EX_TOPMOST)
$iMemo = GUICtrlCreateEdit("", 0, 0, $width, $height, $ES_AUTOVSCROLL + $WS_VSCROLL + $WS_HSCROLL + $ES_READONLY)
$InputControl = GUICtrlCreateEdit("",5,$msgPosition,$msgWidth,$msgHeight, BitOR($ES_WANTRETURN,$ES_AUTOVSCROLL))

GUICtrlSetLimit(-1, 0x7FFFFFFF)
GUICtrlSetFont($iMemo, 9, 400, 0, "Courier New")
GUISetState()

$hFile = FileOpen($file)
$txt = FileRead($hFile)

GUICtrlSetData($iMemo, $txt, 1)
_GUICtrlEdit_LineScroll($iMemo, 1, 0xfffffff)
FileClose($hFile)

$fs = FileGetSize($file)

GUISetOnEvent($GUI_EVENT_CLOSE, "_ExitAnalystMsgr")

While Sleep(1000)
    $fs_new = FileGetSize($file)
    If $fs < $fs_new Then
        $hFile = FileOpen($file,128)
        ConsoleWrite($fs_new - $fs & @crlf)
        FileSetPos($hFile, -($fs_new - $fs), 2)
        $new_line = FileRead($hFile)
        FileClose($hFile)
        GUICtrlSetData($iMemo, $new_line, 1)
        $fs = $fs_new
    EndIf

    $ControlRead = GUICtrlRead($InputControl) ;Read data from the control

    If StringRight($ControlRead,2) = @CRLF Then ; if the last characters are {ENTER} then do things

        If _IsPressed(10) Then ;Checks if {SHIFT} is pressed so you can still use multiple enters

            $PreviousStringLenght = StringLen($ControlRead) ;Capture the lenght of the string, to see when something has changed

        ElseIf $PreviousStringLenght <> StringLen($ControlRead) Then ;on next occasion, where {SHIFT} is not pressed, check if the String lenght has changed. If so, then do this

            $ControlRead = StringTrimRight($ControlRead,2) ; Delete the {ENTER} from the end
            GUICtrlSetData($InputControl,$ControlRead) ; This is optional data, but I've done this so that the user will not see that the enter is not really captured
			FileWriteLine($file, $ControlRead & @CRLF) ; Write data to file
;            MsgBox(0, "Test data", $ControlRead) ; Do something with the data, in this case display it in the MsgBox
			Guictrlsetdata($InputControl,"") ; Clear the Data in the input box

        EndIf

    EndIf

WEnd
EndFunc

Func _ExitAnalystMsgr()
    GUIDelete($hGUI)
    Exit
EndFunc   ;==>_ExitAnalystMsgr

