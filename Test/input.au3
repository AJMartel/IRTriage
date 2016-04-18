#include <GUIConstantsEx.au3>
#include <WindowsConstants.au3>
#include <File.au3>
#include <GuiEdit.au3>
#include <Misc.au3>

Dim $PreviousStringLenght
Local $width = 1024
Local $height = 600
Local $msgPosition = 578 - 5
Local $msgWidth = $width - 10
Local $msgHeight = $height - $msgPosition - 5
Local $file = @ScriptDir & "\test.txt"

; Set up a basic test GUI
GUICreate("Analyst Message", $width,$height)
$InputControl = GUICtrlCreateEdit("",5,$msgPosition,$msgWidth,$msgHeight, BitOR($ES_WANTRETURN,$ES_AUTOVSCROLL))

GUISetState()

; Start the main loop
While 1
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

    If GUIGetMsg() = -3 Then Exit ; Checks to see whether the GUI's close button has been pressed
WEnd
