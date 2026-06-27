OPTION EXPLICIT
On Error Resume Next

DIM CRLF, TAB
DIM strServer
DIM objWebService

TAB  = CHR( 9 )
CRLF = CHR( 13 ) & CHR( 10 )

IF WScript.Arguments.Length = 1 THEN
    strServer = WScript.Arguments( 0 )
ELSE
    strServer = "localhost"
END IF

WScript.Echo "AI_RAW_HELPER_CONTEXT"
WScript.Echo "helper=enum_site.vbs"
WScript.Echo "data_role=raw_helper_output"
WScript.Echo "judgment_mode=raw_evidence_only"
WScript.Echo "verdict_source=none"
WScript.Echo "schema=site_id<TAB>comment<TAB>state<TAB>log_dir<TAB>path<TAB>ip<TAB>port<TAB>host"
WScript.Echo "RAW_HELPER_OUTPUT_BEGIN"

SET objWebService = GetObject( "IIS://" & strServer & "/W3SVC" )
IF Err.Number <> 0 THEN
    WScript.Echo "collection_status=unavailable"
    WScript.Echo "error_number=" & Err.Number
    WScript.Echo "error_description=" & Err.Description
    WScript.Echo "note=IIS Web service metadata is unavailable or IIS is not installed."
    WScript.Quit 0
END IF

WScript.Echo "collection_status=success"
EnumWebsites objWebService

SUB EnumWebsites( objWebService )
    DIM objWebServer, objWeb, strBindings, strBaseInfo

    FOR EACH objWebServer IN objWebService
        IF objWebserver.Class = "IIsWebServer" THEN
            set objWeb = getObject(objWebServer.adsPath & "/Root")

            strBaseInfo = _
                objWebserver.Name & TAB & _
                objWebServer.ServerComment & TAB  & _
                State2Desc( objWebserver.ServerState ) & TAB & _
                objWebServer.LogFileDirectory & Tab & _
                objWeb.Path & Tab 

            ' Enumerate the HTTP bindings (ServerBindings) and
            ' SSL bindings (SecureBindings)
            EnumBindings objWebServer.ServerBindings, strBaseInfo
            EnumBindings objWebServer.SecureBindings, strBaseInfo

        END IF
    NEXT

END SUB

SUB EnumBindings( objBindingList, strBaseInfo  )
    DIM i, strIP, strPort, strHost
    DIM reBinding, reMatch, reMatches
    SET reBinding = NEW RegExp
    reBinding.Pattern = "([^:]*):([^:]*):(.*)"

    FOR i = LBOUND( objBindingList ) TO UBOUND( objBindingList )
        ' objBindingList( i ) is a string looking like IP:Port:Host
        SET reMatches = reBinding.Execute( objBindingList( i ) )
        FOR EACH reMatch IN reMatches
            strIP = reMatch.SubMatches( 0 )
            strPort = reMatch.SubMatches( 1 )
            strHost = reMatch.SubMatches( 2 )

            ' Do some pretty processing
            IF strIP = "" THEN strIP = "All Unassigned"
            IF strHost = "" THEN strHost = "*"
            IF LEN( strIP ) < 8 THEN strIP = strIP & TAB

            WScript.Echo   strBaseInfo  & _
                           strIP & TAB & _
                           strPort & TAB & _
                           strHost 
        NEXT

    NEXT

END SUB

FUNCTION State2Desc( nState )
    SELECT CASE nState
    CASE 1
        State2Desc = "Starting"
    CASE 2
        State2Desc = "Started"
    CASE 3
        State2Desc = "Stopping"
    CASE 4
        State2Desc = "Stopped"
    CASE 5
        State2Desc = "Pausing"
    CASE 6
        State2Desc = "Paused"
    CASE 7
        State2Desc = "Continuing"
    CASE ELSE
        State2Desc = "Unknown"
    END SELECT

END FUNCTION
