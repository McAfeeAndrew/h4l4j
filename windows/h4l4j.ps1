#requires -Version 5.0 -Modules Storage -RunAsAdministrator
<#
   .SYNOPSIS
   Log4j vulnerabilities affected version scanner

   .DESCRIPTION
   Scan for CVE-2021-44228 and/or CVE-2021-45046 effected versions of Log4j
   Modified for deployment via McAFee ePO and reporting results back on a custom property from managed devices
   Original script based heavily on the work by hochwald.net/hellstorm.de

   .PARAMETER AutoFix - DISABLED, you need to enable this if you want to take the risk!
   Apply mitigation by removing the affected class from JAR archive file?

   PLEASE ENSURE ON YOUR OWN THAT THIS WILL NOT BREAK YOUR APPLICATION!!!
   PLEASE ENSURE THAT YOU HAVE BACKUPS OR SNAPSHOTS YOU CAN RELY ON!!!
   DON'T BLAME THE AUTHOR(S) IF IT BREAKS YOUR SYSTEM!!!

   .PARAMETER WorkDirectory
   Where to store working files.
   Default: 'C:\temp\log4j-vscan'

   .PARAMETER Prop
   Which custom prop to report back to ePO on (1-8)
   Required

   .EXAMPLE
   PS C:\> .\Find-Log4jVulnerabilities.ps1 \Prop 3

   .LINK
   https://hochwald.net

   .LINK
   https://www.hellstorm.de/index.php/de/4-log4j-exploit-scanner-und-entferner%C3%BC

   .NOTES
   Reworked version of the .\Find-Log4j.ps1 file from hellstorm.de
   It is based on Version 1.2 of Hellstorm.De's great work

   Those parts are Copyright (c) 2021 by hellstorm.de
   The new parts for ePO/custom props are Copyright (c) 2022 by McAfee Enterprise
#>
[CmdletBinding(ConfirmImpact = 'Low')]
param
(
    [Parameter(ValueFromPipeline,
    ValueFromPipelineByPropertyName)]
    [Alias('Fix')]
    [switch]
    $AutoFix,
    [Parameter(ValueFromPipeline,
    ValueFromPipelineByPropertyName)]
    [Alias('Property')]
    [Int32]
    $Prop,
    [Parameter(ValueFromPipeline,
    ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [Alias('TempDirectory')]
    [string]
    $WorkDirectory = 'C:\temp\log4j-vscan'
)

$g_ISO_Date_with_time = Get-Date -format "yyyy-MM-dd HH:mm:ss"
$Agent_log_dest="C:\ProgramData\McAfee\Agent\logs\" # Read this value from registry
Write-Host $g_ISO_Date_with_time" h4l4j start "$args


function write_customprops() {
    param(
        [Int32]$prop,
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
    $Parms = " -custom -prop" + $prop
    $Parms = $Parms+' "'+$Value+'"'
    try {
        $process_status = Start-Process  $Command_maconfig -ArgumentList $Parms -NoNewWindow -PassThru -Wait        
    }
    catch {
        "Error running $Command_maconfig"
        Add-Content $g_temp_status_file "Error running $Command_maconfig"
    }
   
    # Perform CMDAGENT.EXE -p
    # Collect and Send Props
    try {
        $process_status = Start-Process  $Command_cmdagent -ArgumentList '-p' -NoNewWindow -PassThru -Wait
    }
    catch {
        "Error running $Command_cmdagent"
        Add-Content $g_temp_status_file "Error running $Command_cmdagent"
    }
}

function download_hashes() {
    param(
        [string]
        $DownloadDirectory,
        [string]
        $Url = 'https://raw.githubusercontent.com/McAfeeAndrew/h4l4j/main/hashes-pre-cve.txt'
    )
    Invoke-WebRequest -Uri $Url -OutFile $DownloadDirectory
}

# Generate random temp directory
$RandomString = [IO.Path]::GetRandomFileName()
$TempDirectory = ('temp-{0}' -f ($RandomString))

# Create working directory if not exist
if (-not (Test-Path -Path $WorkDirectory -ErrorAction SilentlyContinue))
{
    $null = (New-Item -Path $WorkDirectory -ItemType 'directory' -Force -Confirm:$false -ErrorAction SilentlyContinue)
}

# Create temp dir
if (-not (Test-Path -Path (Join-Path -Path $WorkDirectory -ChildPath $TempDirectory) -ErrorAction SilentlyContinue))
{
    $null = (New-Item -Path $WorkDirectory -Name $TempDirectory -ItemType 'directory' -Force -Confirm:$false -ErrorAction SilentlyContinue)
}

# Working files/dir, can be, but shouldn't be changed
$TeampArchive = ('{0}\{1}\tmp.zip' -f ($WorkDirectory), ($TempDirectory))
$FiedArchive = ('{0}\{1}\new.zip' -f ($WorkDirectory), ($TempDirectory))
$UnpackedDirectory = ('{0}\{1}\unpacked' -f ($WorkDirectory), ($TempDirectory))

# Logging file, normally stored in workdir
$LogFile = ('{0}\Log4j-Scan-Results-{1}.txt' -f ($WorkDirectory), (Get-Date -Format 'MM-dd-yyyy_HH-mm-ss'))

# confirm valid prop
if (($Prop -eq $null) -or ($Prop -lt 1) -or ($Prop -gt 8)) {
    "error: missing Prop argument - Default to 8"
    Write-Verbose -Message ('Need to specify Prop between -p 1..8 inclusive - Default to 8 ')
    #exit
    $prop=8
}

$Messages = @()

# Download the hashes
$HashesFile = ('{0}\{1}\hashes.txt' -f ($WorkDirectory), ($TempDirectory))
$HashesFile
download_hashes -DownloadDirectory $HashesFile


# Get all local disk drives
$AllFixedDisks = (Get-Volume -ErrorAction SilentlyContinue | Where-Object -FilterScript {
        (($_.DriveType -eq 'Fixed') -and ($_.DriveLetter -ne $null))
})

$found44228 = 0
$found45046 = 0
$foundOutdated = 0
$foundUnsafe = 0
$foundExploit = 0

foreach ($FixedDisk in $AllFixedDisks.DriveLetter)
{
    Write-Verbose -Message ('Scanning drive {0}...' -f $FixedDisk)

    # Search all local drives for log4j* files
    Get-ChildItem -Path ('{0}:\' -f $FixedDisk) -Filter 'log4j*.jar' -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object -Process {
        $isclean = $false
        $JARArchiveFile = $_.FullName

        Write-Verbose -Message ('Scann {0}' -f $JARArchiveFile)

        # if a JAR archive is found, copy to temp directiry
        Copy-Item -Path $JARArchiveFile -Destination $TeampArchive

        # Uncompress the JAR archive
        Expand-Archive -Path $TeampArchive -DestinationPath $UnpackedDirectory

        # Get version from Manifest file
        (Get-Content -Path ('{0}\META-INF\MANIFEST.MF' -f ($UnpackedDirectory)) -ErrorAction SilentlyContinue | ForEach-Object -Process {
            if ($_ -match 'Implementation-Version')
            {
                $ver = $_ -replace '^.*: ', ''
            }
        })

        # Split version string into separate numbers to compare them
        $vertok = $ver -split '\.'

        # Guess it is unsave until we know better
        $unsafe = $true

        # Handle CVE-2021-44228 and CVE-2021-45046
        if (($vertok[0].ToInt32($null) -eq 2) -and ($vertok[1].ToInt32($null) -le 15))
        {
        # CVE-2021-44228
            Write-Verbose -Message ('Potential CVE-2021-44228 effected Version found: {0}' -f ($ver))
            $found44228 = $found44228 + 1
        }
        elseif (($vertok[0].ToInt32($null) -eq 2) -and ($vertok[1].ToInt32($null) -le 16))
        {
            # CVE-2021-45046
            Write-Verbose -Message ('Potential CVE-2021-45046 effected Version found: {0}' -f ($ver))
            $found45046 = 0
        }
        elseif ($vertok[0].ToInt32($null) -eq 1)
        {
            # Legacy warning
            Write-Verbose -Message ('Outdated Version: {0}' -f ($ver))
            $foundOutdated = 1
        }
        else
        {
            # Any other version
            Write-Verbose -Message ('Safe Version: {0}' -f ($ver))

            # Skip the next steps
            $unsafe = $false
        }

        # If we found a potentially risky CVE-2021-44228 and/or CVE-2021-45046 version
        if ($unsafe)
        {
        # Look for JndiLookup class and notify user/logfile
            $foundUnsafe = $foundUnsafe + 1
            Get-ChildItem -Path $UnpackedDirectory -Filter 'JndiLookup.class' -Recurse -ErrorAction SilentlyContinue | ForEach-Object -Process {
                Write-Verbose -Message ('POTENTIAL EXPLOIT:  Found in {0}' -f $_.FullName)

                ('POTENTIAL AFFECTED: {0}' -f ($JARArchiveFile)) | Out-File -Append -FilePath $LogFile

                Write-Verbose -Message 'You should download Log4j 2.17.0 (or later): https://logging.apache.org/log4j/2.x/download.html'
            }

            # Delete JndiLookup class if $fix is $true
            # if ($AutoFix)
            # {
            #    Get-ChildItem -Path $UnpackedDirectory -Filter 'JndiLookup.class' -Recurse -ErrorAction SilentlyContinue | ForEach-Object -Process {
            #       Write-Verbose -Message ('Removing {0}...' -f $_.FullName)

            #       $null = (Remove-Item -Path $($_.FullName) -Force -Confirm:$false -ErrorAction SilentlyContinue)

            #       ('REMOVED: {0}' -f $_.FullName) | Out-File -Append -FilePath $LogFile
            #    }

            #    # Write new JAR archive file
            #    (Compress-Archive -Path ('{0}\*' -f ($UnpackedDirectory)) -DestinationPath $FiedArchive -Force -Confirm:$false -ErrorAction SilentlyContinue)

            #    # Restore the new JAR archive
            #    (Copy-Item -Path $FiedArchive -Destination $JARArchiveFile -Force -Confirm:$false)

            #    # cleanup
            #    $null = (Remove-Item -Path $FiedArchive -Force -Confirm:$false -ErrorAction SilentlyContinue)
            # }
        }

        # Further cleanup
        $null = (Remove-Item -Path $TeampArchive -Force -Confirm:$false -ErrorAction SilentlyContinue)
        $null = (Remove-Item -Recurse -Path $UnpackedDirectory -Force -Confirm:$false -ErrorAction SilentlyContinue)
    }
}

$result_messages = @()
if ($found44228 -gt 0) {
    $result_messages = $result_messages + "found $($found44228) potential CVE-2021-44228 versions"
}
if ($found45046 -gt 0) {
    $result_messages = $result_messages + "found $($found45046) potential CVE-2021-45046 versions"
}
if ($foundExploit -gt 0) {
    $result_messages = $result_messages + "found $($foundExploit) potential exploits"
}
if ($foundOutdated -gt 0) {
    $result_messages = $result_messages + "found $($foundOutdated) outdated versions"
}
if ($foundUnsafe -gt 0) {
    $result_messages = $result_messages + "found $($foundUnsafe) unsafe versions"
}
if ($result_messages.Count -lt 1) {
    $result_messages = "Nothing found"
}

$result_message_str=""
$result_message_str = $result_messages -join ", "
$result_message_str = "H4L4J "+$g_ISO_Date_with_time+": "+$result_message_str+" - Check Log: "+$LogFile 
write_customprops -prop $prop -value $result_message_str

$g_ISO_Date_with_time = Get-Date -format "yyyy-MM-dd HH:mm:ss"
try
{
    Copy-Item $LogFile $Agent_log_dest  -errorAction stop
    Write-Host $g_ISO_Date_with_time" Success copy "$LogFile" to "$Agent_log_dest
}
catch
{
    Write-Host $g_ISO_Date_with_time" Failure copy "$LogFile" to "$Agent_log_dest
}

# End status
Write-Host $g_ISO_Date_with_time" h4l4j done"


#
# Final Cleanup
$null = (Remove-Item -Recurse -Path ('{0}\{1}' -f ($WorkDirectory), ($TempDirectory)) -Force -Confirm:$false -ErrorAction SilentlyContinue)
