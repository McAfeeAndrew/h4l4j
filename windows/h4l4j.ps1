function write_customprops() {
    param(
        [string]$Value
    )

    # Find path to McAfee Agent
    # Read information from 64 bit
    if ((Get-WmiObject win32_operatingsystem | Select-Object osarchitecture).osarchitecture -like "64*") {
        #64bit code here
        Write-Output "64-bit OS"
        $path_to_agent = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Network Associates\ePolicy Orchestrator\Agent" -Name "Installed Path")."Installed Path"
        $Command_maconfig = $path_to_agent+'\..\MACONFIG.exe'
        $Command_cmdagent = $path_to_agent+'\..\CMDAGENT.exe'
    } else {
        #32bit code here
        Write-Output "32-bit OS"
        $path_to_agent = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Network Associates\ePolicy Orchestrator\Agent" -Name "Installed Path")."Installed Path"
        $Command_maconfig = $path_to_agent+'\MACONFIG.exe'
        $Command_cmdagent = $path_to_agent+'\CMDAGENT.exe'
    }
     
    $path_to_agent
    #$path_to_agent32 = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Network Associates\ePolicy Orchestrator\Agent" -Name "Installed Path")."Installed Path"
    $Parms = " -custom -prop8 "
    $Parms = $Parms+'"'+$Value+'"'
    #$Parms
    #$Command_maconfig
    #& $Command_maconfig @($Parms)
    try {
        $process_status = Start-Process  $Command_maconfig -ArgumentList $Parms -NoNewWindow -PassThru -Wait        
    }
    catch {
        "Error running $Command_maconfig"
        Add-Content $g_temp_status_file "Error running $Command_maconfig"
    }
   
    # Perform CMDAGENT.EXE -p
    # Collect and Send Props
    #%comspec% /c "%agent_path%\cmdagent.exe" -p
    #& $Command_cmdagent @('-p')
    try {
        $process_status = Start-Process  $Command_cmdagent -ArgumentList '-p' -NoNewWindow -PassThru -Wait
    }
    catch {
        "Error running $Command_cmdagent"
        Add-Content $g_temp_status_file "Error running $Command_cmdagent"
    }
}

