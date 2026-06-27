Option Explicit
On Error Resume Next

Dim strComputer, objWMIService, colItems, objItem

WScript.Echo "AI_RAW_HELPER_CONTEXT"
WScript.Echo "helper=ftp_path.vbs"
WScript.Echo "data_role=raw_helper_output"
WScript.Echo "judgment_mode=raw_evidence_only"
WScript.Echo "verdict_source=none"
WScript.Echo "schema=ftp_virtual_dir_path"
WScript.Echo "RAW_HELPER_OUTPUT_BEGIN"

strComputer = "."
Set objWMIService = GetObject _
    ("winmgmts:{authenticationLevel=pktPrivacy}\\" _
        & strComputer & "\root\microsoftiisv2")

If Err.Number <> 0 Then
    WScript.Echo "collection_status=unavailable"
    WScript.Echo "error_number=" & Err.Number
    WScript.Echo "error_description=" & Err.Description
    WScript.Echo "note=IIS FTP WMI namespace is unavailable or FTP service is not installed."
    WScript.Quit 0
End If

Set colItems = objWMIService.ExecQuery _
    ("Select * from IIsFtpVirtualDirSetting")

If Err.Number <> 0 Then
    WScript.Echo "collection_status=query_failed"
    WScript.Echo "error_number=" & Err.Number
    WScript.Echo "error_description=" & Err.Description
    WScript.Quit 0
End If

WScript.Echo "collection_status=success"

For Each objItem in colItems
    Wscript.Echo "ftp_virtual_dir_path=" & objItem.Path
Next
