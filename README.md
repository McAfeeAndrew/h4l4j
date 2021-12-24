# h4l4j
EEDK packages for ePO to help locate vulnerable log4j in your environment

## Use with McAfee ePO

These EEDK packages have been built to help organisations that do not yet have an EDR capability to hunt for vulnerable machines in their infrastructure.

This approach uses the power of EEDK deployments on ePO to push a search request/script to all your targetted (or all) endpoints, execute the search and create a log of instances discovered on each endpoint.

Then custom attributes are also reported back to ePO for each instance indicating the level of potential exposure that has been tentatively uncovered.

This is a great first step and additional observation tool to help you focus on more risky/vulnerable/higher priority systems first.

## Structure

The repo is split into 2 sections, one for windows using Powershell and the other for Mac/Linux using shell scripting.

To use each script, please refer to the README.md in the respective sub folder.

## Work in Progress

These scripts are a work in progress, if you have any suggested improvements, please fork the repo and submit a pull request.
