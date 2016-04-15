;Coded by UEZ Build 2010-06-30, tweaked by KaFu ;-)
;https://www.autoitscript.com/forum/topic/116468-choosedisplay-log-file-in-real-time/?do=findComment&comment=812827

#include <GUIConstantsEx.au3>
#include <WindowsConstants.au3>
#include <File.au3>
#include <GuiEdit.au3>
#include <Misc.au3>

Opt("GUIOnEventMode", 1)

Global $iMemo, $new_line
$width = 1024
$height = 600
$hGUI = GUICreate("IRTriage Analyst Messager", $width, $height, -1, -1, Default, $WS_EX_TOPMOST)
$iMemo = GUICtrlCreateEdit("", 0, 0, $width, $height, $ES_AUTOVSCROLL + $WS_VSCROLL + $WS_HSCROLL + $ES_READONLY)
GUICtrlSetLimit(-1, 0x7FFFFFFF)
GUICtrlSetFont($iMemo, 9, 400, 0, "Courier New")
GUISetState()
If $CmdLine[0] > 0 And FileExists($CmdLine[1]) Then
    $file = $CmdLine[1]
Else
    ;$file = @ScriptDir & "\AnalystMsg.txt"
    $file = @ScriptDir & "\test.txt"
EndIf
$hFile = FileOpen($file)
$txt = FileRead($hFile)

GUICtrlSetData($iMemo, $txt, 1)
_GUICtrlEdit_LineScroll($iMemo, 1, 0xfffffff)
FileClose($hFile)

$fs = FileGetSize($file)

GUISetOnEvent($GUI_EVENT_CLOSE, "_Exit")

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
WEnd

Func _Exit()
    GUIDelete($hGUI)
    Exit
EndFunc   ;==>_Exit

