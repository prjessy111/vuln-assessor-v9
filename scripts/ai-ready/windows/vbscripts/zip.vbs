'Get command-line arguments.
WScript.Echo "AI_RAW_HELPER_CONTEXT"
WScript.Echo "helper=zip.vbs"
WScript.Echo "data_role=packaging_helper"
WScript.Echo "judgment_mode=not_applicable"
WScript.Echo "verdict_source=none"
WScript.Echo "RAW_HELPER_OUTPUT_BEGIN"

Set objArgs = WScript.Arguments
InputFolder = objArgs(0)
ZipFile = objArgs(1)

WScript.Echo "collection_status=packaging"
WScript.Echo "input_folder=" & InputFolder
WScript.Echo "zip_file=" & ZipFile

Set objFSO = CreateObject("Scripting.FileSystemObject")
InputFolder = objFSO.GetAbsolutePathName(InputFolder)
ZipFile = objFSO.GetAbsolutePathName(ZipFile)

'Create empty ZIP file.
objFSO.CreateTextFile(ZipFile, True).Write "PK" & Chr(5) & Chr(6) & String(18, vbNullChar)

Set objShell = CreateObject("Shell.Application")

Set inputNamespace = objShell.NameSpace(InputFolder)
Set zipNamespace = objShell.NameSpace(ZipFile)

If inputNamespace Is Nothing Then
  WScript.Echo "collection_status=packaging_failed"
  WScript.Echo "error=input folder namespace unavailable"
  WScript.Quit 0
End If

If zipNamespace Is Nothing Then
  WScript.Echo "collection_status=packaging_failed"
  WScript.Echo "error=zip namespace unavailable"
  WScript.Quit 0
End If

Set source = inputNamespace.Items

zipNamespace.CopyHere(source)

'Sleep
wScript.Sleep 2000
WScript.Echo "collection_status=packaging_complete"
