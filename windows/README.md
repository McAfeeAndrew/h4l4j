# h4l4j
EEDK packages for ePO to help locate vulnerable log4j in your environment


ePO Package ready
Include a small CMD file needed for the ePO package to launch the PS1 file.
The log4j search does reuqire the servers to be able to reach Internet
The search can take 5-10 minutes and maybe more. Make sure that if the task takes more than 20 minutes the time.out must be chanegs in the "Run CLient Task" now options in ePO

If the Agent Self Protection function is disabled during the scanning with h4l4j the log file will be placed in the C:\Programdata\McAfee>agent\logs\ directory where it can be pulled from ePO using Single System Troubleshooting.


Example of Custom Prop in ePO from an ePO server with Update 11 (note Update 12 has been released):

Custom 8: H4L4J 2022-01-16 17:25:45: found 9 potential CVE-2021-44228 versions, found 1 outdated versions, found 13 unsafe versions - Check Log: C:\temp\log4j-vscan\Log4j-Scan-Results-01-16-2022_17-25-45.txt

Log4j-Scan-Results-01-16-2022_17-25-45.txt

POTENTIAL AFFECTED: C:\Program Files (x86)\McAfee\ePolicy Orchestrator\Installer\Core\lib\log4j-core-2.14.1.jar

POTENTIAL AFFECTED: C:\Program Files (x86)\McAfee\ePolicy Orchestrator\Server\lib\log4j-core-2.14.1.jar

POTENTIAL AFFECTED: C:\Program Files (x86)\McAfee\ePolicy Orchestrator\updates\LatestBuild\ePOUpdater\resources\app\release\tomcat\server\lib\log4j-core-2.14.1.jar


Example from a Windows Server with Minecraft
Custom 8: H4L4J 2022-01-16 17:25:45: found 5 potential CVE-2021-44228 versions, found 5 unsafe versions - Check Log: C:\temp\log4j-vscan\Log4j-Scan-Results-01-16-2022_17-25-45.txt

POTENTIAL AFFECTED: D:\Minecraft\Forge\libraries\org\apache\logging\log4j\log4j-core\2.14.1\log4j-core-2.14.1.jar
POTENTIAL AFFECTED: D:\Minecraft\server\libraries\org\apache\logging\log4j\log4j-core\2.14.1\log4j-core-2.14.1.jar



C:\Windows\TEMP\EEDK_Debug.log file contains the output of the execution of the .CMD and .PS1 file. This file can be good for troubleshooting.


## Process

WORK IN PROGRESS
TO:DO
Make an offline version of the scanner.
