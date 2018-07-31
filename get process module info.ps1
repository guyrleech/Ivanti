﻿#requires -version 3.0
<#
    Get metadata and digital signature info for selected process modules

    If interrogating x86 then need to run in x86 powershell and x64 for x64 process

    Modification History:

    31/07/18  GRL  Added file owner field
                   -process parameter can take comma separated list of process names

    @guyrleech 2018
#>

<#
.SYNOPSIS

Interrogate a running process and list its loaded modules, optionally filtering those where the full path matches a pattern, e.g. c:\users
Primarily written to help find consistent metadata and digital certificates when adding rules to AppSense/Ivanti Application Manager/Control

.PARAMETER processes

A comma separated list of the names of running processes to interrogate. For 32 bit processes, a 32 bit PowerShell instance must be used

.PARAMETER filePattern

A regular expression to match module file names so only those are included

.PARAMETER csv

Path of a csv file to write the results to. Will fail if already exists. If not specified then output will be to an on screen grid view

.PARAMETER thisSessionOnly

Only look at processes in the current session

.PARAMETER sessionId

Only look at processes in the session id specified

.PARAMETER selectors

The properties to return.

.EXAMPLE

& '.\get process module info.ps1' -process onedrive -filePattern '^c:\\users'

Show modules for onedrive.exe which are contained within the c:\users folder

.EXAMPLE

& '.\get process module info.ps1' -process onedrive,outlook,excel -csv c:\temp\onedrive.modules.csv

Get all modules for all running instances of onedrive.exe, outlook.exe and excel.exe and write to the file c:\temp\onedrive.modules.csv

#>

[CmdletBinding()]

Param
(
    [Parameter(Mandatory=$true)]
    [string[]]$processes ,
    [string]$filePattern ,
    [string]$csv ,
    [switch]$thisSessionOnly ,
    [int]$sessionId ,
    [string[]]$selectors = @( 'FileName' , 'FileVersion' , 'FileVersionRaw' , 'ProductVersionRaw' , 'FileDescription' , 'CompanyName' , 'InternalName' , 'Comments' ) 
)

[hashtable]$modules = @{}
[int]$thisSessionId = -1

if( $thisSessionOnly )
{
    $thisSessionId = Get-Process -id $pid | Select -ExpandProperty SessionId
}
elseif( $PSBoundParameters[ 'sessionid' ] )
{
    $thisSessionId = $sessionId
}

ForEach( $process in $processes )
{
    Get-Process -name $process | Where-Object { $thisSessionId -lt 0 -or $_.SessionId -eq $thisSessionId } | Select -ExpandProperty modules | select -ExpandProperty filename| Where-Object { $_ -match $filePattern } | ForEach-Object `
    {
        $module = Get-ItemProperty -Path $_
        $result = $module.VersionInfo | Select -Property $selectors 
        Add-Member -InputObject $result -NotePropertyMembers `
        @{
            'Process' = $process
            'File Owner' = ( Get-Acl -Path $_ | Select -ExpandProperty Owner )
        }
        $signing = Get-AuthenticodeSignature -FilePath $module.FullName -ErrorAction SilentlyContinue
        if( $signing )
        {
            [bool]$datesValid = $true
            if( (Get-Date) -lt $signing.SignerCertificate.NotBefore )
            {
                $datesValid = $false
            }
            if( (Get-Date) -gt $signing.SignerCertificate.NotAfter )
            {
                $datesValid = $false
            }
            Add-Member -InputObject $result -NotePropertyMembers `
            @{
                'Signing Status' = $signing.Status
                'Signing Status Message' = $signing.StatusMessage
                'Signature Type' = $signing.SignatureType
                'Certificate Subject' = $signing.SignerCertificate.Subject
                'Certificate Vendor' = ( ( ($signing.SignerCertificate.Subject -split 'CN=')[1] -split ',')[0] )
                'Certificate Issuer' = $signing.SignerCertificate.Issuer
                'Certificate Starts' = $signing.SignerCertificate.NotBefore
                'Certificate Expires' = $signing.SignerCertificate.NotAfter
                'Certificate In Date' = $datesValid
            }
        }
        try
        {
            $modules.Add( $_ , $result )
        }
        catch{} ## duplicate
    }
}

[string]$status = "Got $($modules.Count) modules for process $($processes -join ',') matching $filePattern"

Write-Verbose $status

if( $PSBoundParameters[ 'csv' ] )
{
    $modules.GetEnumerator() | Select -ExpandProperty Value | Export-Csv -Path $csv -NoTypeInformation -NoClobber
}
else
{
    $selected = $modules.GetEnumerator() | Select -ExpandProperty Value | Out-GridView -Title $status -PassThru
    if( $selected -and $selected.Count )
    {
        $selected | clip.exe
    }
}

