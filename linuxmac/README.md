# h4l4j - Linux/Mac
EEDK packages for ePO to help locate vulnerable log4j in your environment

## Process

command line:
```bash 
./h4l4j_online.sh 
```

## Credit for prior work

The original script was based on https://github.com/rubo77/log4j_checker_beta/


Will provide status back to ePO in custom Prop 7
Example like:
H4L4J 2022-01-15 17:05:00: No files containing 'log4j' No dpkg log4j packages. Java is NOT installed.

Will write the log file to: '/var/McAfee/agent/logs/h4l4j.log'
This make it possible to pull the log file from ePO using Single System Troublshooting.
