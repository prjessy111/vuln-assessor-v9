WScript.Echo "AI_RAW_HELPER_CONTEXT"
WScript.Echo "helper=internet.vbs"
WScript.Echo "data_role=raw_helper_output"
WScript.Echo "judgment_mode=raw_evidence_only"
WScript.Echo "verdict_source=none"
WScript.Echo "schema=target_url,port,tcp_http_probe_result"
WScript.Echo "RAW_HELPER_OUTPUT_BEGIN"

address = "www.google.com"
WScript.Echo "target_url=http://www.google.com port=80 tcp_http_probe_result=" & TCPPing( address, 80)

address = "www.naver.com"
WScript.Echo "target_url=http://www.naver.com port=80 tcp_http_probe_result=" & TCPPing( address, 80)

Function TCPPing( address, port )
  Set xhr = WScript.CreateObject("MSXML2.ServerXMLHTTP")
  xhr.SetTimeouts 8000,8000,8000,8000
  On Error Resume Next
  xhr.Open "GET", "http://" & address & ":" & port, False
  xhr.Send
  Select Case Err.Number
    ' ok, tcp connect but no web response, 401 auth failure
    Case 0,  -2147012744, -2147024891
      msg = "Internet OK"
    Case -2147012867
      msg = "Connection Rejected"
    Case -2147012894
      msg = "Timed out"
    Case -2147012889
      msg = "Could not resolve address"
    Case -2147467259
      msg = "Cannot test that port with this tool"
    Case Else
      msg = "Unknown error " & Err.Number
  End Select
  On Error Goto 0
  Set xhr = Nothing
  TCPPing = msg
End Function
