; -----------------------------------------------------------------------------
; CRC Checksum Machine Code UDF
; Purpose: Provide The Machine Code Version of CRC32 Algorithm In AutoIt
; Author: Ward
;		http://www.autoitscript.com/forum/topic/121985-autoit-machine-code-algorithm-collection/
; -----------------------------------------------------------------------------
#Include <Memory.au3>
#include <File.au3>

Global $_CRC32_CodeBuffer, $_CRC32_CodeBufferMemory
Global $_CRC16_CodeBuffer, $_CRC16_CodeBufferMemory

Global $BufferSize = 0x80000, $szDrive, $szDir, $szFName, $szExt, $iFileSize, $sFileTime
Global $Filename = FileOpenDialog("Open File", "", "Any File (*.*)")
If $Filename = "" Then Exit

#Region version
Global $sVersion = FileGetVersion($Filename)
ConsoleWrite($Filename & " ver " & $sVersion & @CR)
Local $sHeaderLine
; get version for non-compiled script (get the script version (#AutoIt3Wrapper_Res_Fileversion=1.0.1.0)
If $sVersion = "0.0.0.0" And StringInStr($Filename,".au3") > 0 Then
	For $i = 2 to 15
		$sHeaderLine = FileReadLine($Filename, $i)
		If StringLeft($sHeaderLine, 10) = "#EndRegion" Then ExitLoop ; not found
		If StringInStr($sHeaderLine, "FileVersion") > 0 Then
			$sVersion = StringTrimLeft($sHeaderLine, 29)
			$sVersion = StringTrimRight($sVersion, 1)
			ExitLoop
		EndIf
	Next
EndIf
#EndRegion version
ConsoleWrite($Filename & " ver " & $sVersion & @CR)

Global $CRC32 = 0, $Data
Global $FileSize = FileGetSize($Filename)
Global $FileHandle = FileOpen($Filename, 16)

For $i = 1 To Ceiling($FileSize / $BufferSize)
	$Data = FileRead($FileHandle, $BufferSize)
	$CRC32 = _CRC32($Data, BitNot($CRC32))
Next
FileClose($FileHandle)

$iFileSize = FileGetSize($Filename)
$sFileTime = FileGetTime ($Filename, 0, 1)
$sFileTime = StringMid($sFileTime, 1, 4) & "/" & StringMid($sFileTime, 5, 2) & "/" & StringMid($sFileTime, 7, 2) & " " & StringMid($sFileTime, 9, 2) & ":" & StringMid($sFileTime, 11, 2)

_PathSplit($Filename, $szDrive, $szDir, $szFName, $szExt)

ClipPut ("[" & $szFName & $szExt & "]" & @CRLF & _
	"version=" & $sVersion & @CRLF & _
	"date=" & $sFileTime & @CRLF & _
	"Filesize=" & $iFileSize & @CRLF & _
	"CRC=" & Hex($CRC32, 8) & @CRLF & _
	"download=https://github.com/AJMartel/" & $szFName & "/raw/master/" & $szFName & $szExt & @CRLF & _
	"changes=https://github.com/AJMartel/" & $szFName & "/raw/master/Changes.txt" & @CRLF) ; set in clipboard
MsgBox(0, "Copied to clipboard", "[" & $szFName & $szExt & "]" & @CRLF & _
	"version=" & $sVersion & @CRLF & _
	"date=" & $sFileTime & @CRLF & _
	"Filesize=" & $iFileSize & @CRLF & _
	"CRC=" & Hex($CRC32, 8) & @CRLF & _
	"download=https://github.com/AJMartel/" & $szFName & "/raw/master/" & $szFName & $szExt & @CRLF & _
	"changes=https://github.com/AJMartel/" & $szFName & "/raw/master/Changes.txt" & @CRLF)

Func _CRC32_Exit()
	$_CRC32_CodeBuffer = 0
	_MemVirtualFree($_CRC32_CodeBufferMemory, 0, $MEM_RELEASE)
EndFunc	;==>_CRC32_Exit

Func _CRC32($Data, $Initial = -1, $Polynomial = 0xEDB88320)
	If Not IsDllStruct($_CRC32_CodeBuffer) Then
		If @AutoItX64 Then
			Local $Opcode = '0xC80004004989CA680001000059678D41FF516A0859D1E873034431C8E2F75989848DFCFBFFFFE2E589D14489C04D85D2741B67E318418A1230C2480FB6D2C1E80833849500FCFFFF49FFC2E2E8F7D0C9C3'
		Else
			Local $Opcode = '0xC8000400538B5514B9000100008D41FF516A0859D1E8730231D0E2F85989848DFCFBFFFFE2E78B5D088B4D0C8B451085DB7416E3148A1330C20FB6D2C1E80833849500FCFFFF43E2ECF7D05BC9C21000'
		EndIf
		$Opcode = Binary($Opcode)

		$_CRC32_CodeBufferMemory = _MemVirtualAlloc(0, BinaryLen($Opcode), $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)
		$_CRC32_CodeBuffer = DllStructCreate("byte[" & BinaryLen($Opcode) & "]", $_CRC32_CodeBufferMemory)
		DllStructSetData($_CRC32_CodeBuffer, 1, $Opcode)
		OnAutoItExitRegister("_CRC32_Exit")
	EndIf

	$Data = Binary($Data)
	Local $InputLen = BinaryLen($Data)
	Local $Input = DllStructCreate("byte[" & $InputLen & "]")
	DllStructSetData($Input, 1, $Data)

	Local $Ret = DllCall("user32.dll", "uint", "CallWindowProc", "ptr", DllStructGetPtr($_CRC32_CodeBuffer), _
													"ptr", DllStructGetPtr($Input), _
													"uint", $InputLen, _
													"uint", $Initial, _
													"uint", $Polynomial)

	Return $Ret[0]
EndFunc	;==>_CRC32