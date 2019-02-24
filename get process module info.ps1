#requires -version 3.0
<#
    Get metadata and digital signature info for selected process modules

    If interrogating x86 then need to run in x86 powershell and x64 for x64 process

    Modification History:

    31/07/18  GRL  Added file owner field
                   -process parameter can take comma separated list of process names
    
    07/02/19  GRL  Added separate folder field
                   Added ability to query folders rather than processes

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
    [Parameter(Mandatory=$true,ParameterSetName='Process')]
    [string[]]$processes ,
    [Parameter(Mandatory=$true,ParameterSetName='Folders')]
    [string[]]$folders ,
    [Parameter(Mandatory=$false,ParameterSetName='Folders')]
    [switch]$recurse ,
    [Parameter(Mandatory=$false,ParameterSetName='Folders')]
    [string[]]$fileTypes = @( '*.exe' , '*.dll' , ' *.ocx' ),
    [string]$filePattern ,
    [string]$hashAlgorithm = 'SHA1' ,
    [int]$hashLength = 8MB ,
    [switch]$nonSessionZero ,
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

[hashtable]$runningModules = @{}

[array]$files = @(
    if( ! [string]::IsNullOrEmpty( $processes ) )
    {
        ForEach( $process in $processes )
        {
            Get-Process -name $process | Where-Object { $thisSessionId -lt 0 -or $_.SessionId -eq $thisSessionId } | Select -ExpandProperty modules | select -ExpandProperty filename| Where-Object { $_ -match $filePattern } | ForEach-Object `
            {
                $fileName = $_
                
                $processes = $runningModules[ $fileName ]
                if( $processes )
                {
                    if( $processes -notcontains $process )
                    {
                        $runningModules.Set_Item( $fileName , $processes + $process )
                    }
                }
                else
                {
                    $runningModules.Add( $fileName , $process )
                }

                $fileName
            }
        }
    }
    else
    {
        ForEach( $folder in $folders )
        {
            $processList = @( Get-Process | Where-Object { $thisSessionId -lt 0 -or $_.SessionId -eq $thisSessionId } )

            [hashtable]$fileParams = @{
                'Path' = $folder
                'File' = $true
                'Force' = $true
                'Recurse' = $recurse
                'ErrorAction' = 'SilentlyContinue'
                'Include' = $fileTypes }

            Get-ChildItem @fileParams | Where-Object { $_.FullName -match $filePattern } | Select -ExpandProperty FullName

            ## Find all processes currently using any module in this folder so we can report it
            $processList | ForEach-Object `
            {
                $process = $_
                $process.modules | select -ExpandProperty filename| Where-Object { $_.StartsWith( $folder ) } | ForEach-Object `
                {
                    $processes = $runningModules[ $_ ]
                    if( $processes )
                    {
                        if( $processes -notcontains $process.Name )
                        {
                            $runningModules.Set_Item( $_ , $processes + $process.Name )
                        }
                    }
                    else
                    {
                        $runningModules.Add( $_ , $process.Name )
                    }
                }
            }
        }
    } )

ForEach( $file in $files )
{
    $module = Get-ItemProperty -Path $file
    if( $module.Length -and ( $module.Attributes -band [System.IO.FileAttributes]::Offline ) -ne [System.IO.FileAttributes]::Offline )
    {
        $result = $module.VersionInfo | Select -Property $selectors 
        Add-Member -InputObject $result -NotePropertyMembers `
        @{
            'Folder' = Split-Path -Path $file
            'Process' = $runningModules[ $file ] -join ','
            'File Owner' = ( Get-Acl -Path $file | Select -ExpandProperty Owner )
        }
        try
        {
            $signing = Get-AuthenticodeSignature -FilePath $module.FullName -ErrorAction SilentlyContinue
        }
        catch
        {
            $signing = $null
        }
        if( $signing -and $signing.Status -ne 'NotSigned' )
        {
            [bool]$datesValid = $true
            try
            {
                if( (Get-Date) -lt $signing.SignerCertificate.NotBefore )
                {
                    $datesValid = $false
                }
                if( (Get-Date) -gt $signing.SignerCertificate.NotAfter )
                {
                    $datesValid = $false
                }
            }
            catch
            {
                $datesValid = $false
            }
            [string]$vendor = $null
            if( $signing.SignerCertificate.Subject -match '^CN=("?[^"]*"?),' )
            {
                $vendor = $Matches[1]
            }
            else
            {
                $vendor = ( ( ($signing.SignerCertificate.Subject -split 'CN=')[1] -split ',')[0] )
            }
            Add-Member -InputObject $result -NotePropertyMembers `
            @{
                'Signed' = 'Yes'
                'Signing Status' = $signing.Status
                'Signing Status Message' = $signing.StatusMessage
                'Signature Type' = $signing.SignatureType
                'Certificate Subject' = $signing.SignerCertificate.Subject
                'Certificate Vendor' = $vendor
                'Certificate Issuer' = $signing.SignerCertificate.Issuer
                'Certificate Starts' = $signing.SignerCertificate.NotBefore
                'Certificate Expires' = $signing.SignerCertificate.NotAfter
                'Certificate In Date' = $datesValid
            }
        }
        else
        {
            Add-Member -InputObject $result -MemberType NoteProperty -Name 'Signed' -Value 'No'
        }
        if( Get-Command -Name Get-FileHash -ErrorAction SilentlyContinue )
        {
            $fileStream = New-Object -TypeName System.IO.FileStream -ArgumentList ($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            $fileReader = New-Object -TypeName System.IO.BinaryReader -ArgumentList $fileStream
            [byte[]]$readBytes = $fileReader.ReadBytes( $hashLength )
            $tempFileName = [System.IO.Path]::GetTempFileName()
            $fileReader.Dispose()
            $fileStream.Dispose()
            
            $fileWriter = New-Object System.IO.FileStream($tempFileName, [System.IO.FileMode]'Create', [System.IO.FileAccess]'Write')
            $fileWriter.Write( $readBytes , 0 , $readBytes.Count )
            $fileWriter.Dispose()

            Add-Member -InputObject $result -MemberType NoteProperty -Name 'Partial Hash' -Value (Get-FileHash -Path $tempFileName -Algorithm $hashAlgorithm | Select -ExpandProperty 'Hash')
            Remove-Item -Path $tempFileName -Force
        }
        try
        {
            $modules.Add( $file , $result )
        }
        catch{} ## duplicate
    }
}

[string]$status = "Got $($modules.Count) modules "
if( $PSBoundParameters[ 'processes' ] )
{
    $status += "for process $($processes -join ',')"
}
else
{
    $status += "for folders `"$($folders -join '",')`""
}

if( ! [string]::IsNullOrEmpty( $filePattern ) )
{
    $status += " matching $filePattern"
}

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
