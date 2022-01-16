# h4l4j
EEDK packages for ePO to help locate vulnerable log4j in your environment


ePO Package ready
Include a small CMD file needed for the ePO package to launch the PS1 file.
The log4j search does reuqire the servers to be able to reach Internet

Example of Custom Prop in ePO:
Custom 8 	H4L4J 2022-01-16 17:25:45: found 9 potential CVE-2021-44228 versions, found 1 outdated versions, found 13 unsafe versions - Check Log: C:\temp\log4j-vscan\Log4j-Scan-Results-01-16-2022_17-25-45.txt

If the Agent Self Protection function is disabled during the scanning with h4l4j the log file will be placed in the C:\Programdata\McAfee>agent\logs\ directory where it can be pulled from ePO using Single System Troubleshooting.

## Process

WORK IN PROGRESS
TO:DO
Make an offline version of the scanner.
