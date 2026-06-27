Option Explicit
On Error Resume Next

Dim xhr

WScript.Echo "AI_RAW_HELPER_CONTEXT"
WScript.Echo "helper=iis_internal.vbs"
WScript.Echo "data_role=raw_helper_output"
WScript.Echo "judgment_mode=raw_evidence_only"
WScript.Echo "verdict_source=none"
WScript.Echo "schema=localhost_http_probe"
WScript.Echo "RAW_HELPER_OUTPUT_BEGIN"

Set xhr = WScript.CreateObject("MSXML2.ServerXMLHTTP")
xhr.SetTimeouts 3000,3000,3000,3000
xhr.Open "GET", "http://127.0.0.1:80/", False
xhr.Send

If Err.Number <> 0 Then
    WScript.Echo "collection_status=unavailable"
    WScript.Echo "target_url=http://127.0.0.1:80/"
    WScript.Echo "error_number=" & Err.Number
    WScript.Echo "error_description=" & Err.Description
    WScript.Quit 0
End If

WScript.Echo "collection_status=success"
WScript.Echo "target_url=http://127.0.0.1:80/"
WScript.Echo "http_status=" & xhr.Status
WScript.Echo "response_text_prefix=" & Left(Replace(Replace(xhr.ResponseText, vbCr, " "), vbLf, " "), 500)
WScript.Quit 0
