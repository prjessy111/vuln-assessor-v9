OPTION EXPLICIT
On Error Resume Next

DIM strServer, strServerType, strServerMetaType
DIM objService

strServer = "localhost"
strServerType = "Web"
strServerMetaType = "W3SVC"

IF WScript.Arguments.Length >= 1 THEN
    strServerType = WScript.Arguments( 0 )

    IF UCASE( strServerType ) = "FTP" THEN
        strServerType = "Ftp"
        strServerMetaType = "MSFTPSVC"
    ELSE
        strServerType = "Web"
        strServerMetaType = "W3SVC"
    END IF
END IF

WScript.Echo "AI_RAW_HELPER_CONTEXT"
WScript.Echo "helper=site_status.vbs"
WScript.Echo "data_role=raw_helper_output"
WScript.Echo "judgment_mode=raw_evidence_only"
WScript.Echo "verdict_source=none"
WScript.Echo "target_service=" & strServerType
WScript.Echo "schema=site_id,comment,state,log_dir,ip,port,host"
WScript.Echo "RAW_HELPER_OUTPUT_BEGIN"

SET objService = GetObject( "IIS://" & strServer & "/" & strServerMetaType )
IF Err.Number <> 0 THEN
    WScript.Echo "collection_status=unavailable"
    WScript.Echo "error_number=" & Err.Number
    WScript.Echo "error_description=" & Err.Description
    WScript.Echo "note=IIS metabase provider is unavailable or the target service is not installed."
    WScript.Quit 0
END IF

WScript.Echo "collection_status=success"
EnumServersites objService


SUB EnumServersites( objService )
    DIM objServer, strBindings

    FOR EACH objServer IN objService
        IF objServer.Class = "IIs" & strServerType & "Server" THEN
            WScript.Echo _
                "record_type=iis_site_status" & VbCrLf & _
                "Site ID = " & objServer.Name & VbCrLf & _
                "Comment = """ & objServer.ServerComment & """ " & VbCrLf & _
                "State   = " & State2Desc( objServer.ServerState ) & VbCrLf & _
                "LogDir  = " & objServer.LogFileDirectory & _
                ""

            ' Enumerate the HTTP bindings (ServerBindings) and
            ' SSL bindings (SecureBindings) for HTTPS only
            strBindings = EnumBindings( objServer.ServerBindings )

            IF strServerType = "Web" THEN
                strBindings = strBindings & _
                EnumBindings( objServer.SecureBindings )
            END IF

            IF NOT strBindings = "" THEN
                WScript.Echo "IP Address" & VbTab & _
                             "Port" & VbTab & _
                             "Host" & VbCrLf & _
                             strBindings
            END IF
        END IF
    NEXT

END SUB

FUNCTION EnumBindings( objBindingList )
    DIM i, strIP, strPort, strHost
    DIM reBinding, reMatch, reMatches
    SET reBinding = NEW RegExp
    reBinding.Pattern = "([^:]*):([^:]*):(.*)"

    FOR i = LBOUND( objBindingList ) TO UBOUND( objBindingList )
        ' objBindingList( i ) is a string looking like IP:Port:Host
        SET reMatches = reBinding.Execute( objBindingList( i ) )
        FOR EACH reMatch in reMatches
            strIP = reMatch.SubMatches( 0 )
            strPort = reMatch.SubMatches( 1 )
            strHost = reMatch.SubMatches( 2 )

            ' Do some pretty processing
            IF strIP = "" THEN strIP = "All Unassigned"
            IF strHost = "" THEN strHost = "*"
            IF LEN( strIP ) < 8 THEN strIP = strIP & VbTab

            EnumBindings = EnumBindings & _
                           strIP & VbTab & _
                           strPort & VbTab & _
                           strHost & VbTab & _
                           ""
        NEXT

        EnumBindings = EnumBindings & VbCrLf
    NEXT

END FUNCTION

FUNCTION State2Desc( nState )
    SELECT CASE nState
    CASE 1
        State2Desc = "Starting (MD_SERVER_STATE_STARTING)"
    CASE 2
        State2Desc = "Started (MD_SERVER_STATE_STARTED)"
    CASE 3
        State2Desc = "Stopping (MD_SERVER_STATE_STOPPING)"
    CASE 4
        State2Desc = "Stopped (MD_SERVER_STATE_STOPPED)"
    CASE 5
        State2Desc = "Pausing (MD_SERVER_STATE_PAUSING)"
    CASE 6
        State2Desc = "Paused (MD_SERVER_STATE_PAUSED)"
    CASE 7
        State2Desc = "Continuing (MD_SERVER_STATE_CONTINUING)"
    CASE ELSE
        State2Desc = "Unknown state"
    END SELECT

END FUNCTION
