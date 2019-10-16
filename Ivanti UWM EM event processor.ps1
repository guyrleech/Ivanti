#requires -version 3
<#
    Get Ivanti UWM EM event log entries and split into sortable table for durations

    @guyrleech 2019

    Modification History:

    16/10/19   GRL  Initial public release
#>

<#
.SYNOPSIS

Get Ivanti UWM EM event log entries and split into sortable table for durations

.PARAMETER computerName

The computer whose AppSense event log is to be queried

.PARAMETER start

The start time/date to process event logs from

.PARAMETER end

The end time/date to process event logs to

.PARAMETER duration

How long to process events for. Must be used with -start. Specify with s,m,h,d,w,y for seconds,minutes,hours,days,weeks and years respectively, e.g. 4h for 4 hours

.PARAMETER last

Process events for the last period where the period is specified as something like 4h where s,m,h,d,w,y are for seconds,minutes,hours,days,weeks and years respectively

.PARAMETER user

Only process events for the specified user

.PARAMETER csv

The path to a csv file which will have the results saved to it. The save will fail if the file already exists

.PARAMETER triggerOnly

Only show events for the trigger summary rather than all events

.PARAMETER delimiter

Specify the delimiter for the csv file, e.g. a semicolon for Dutch users

.PARAMETER noGridView

Do not display an onscreen grid view but instead output the results to the pipeline

.EXAMPLE

& '.\Ivanti UWM EM event processor.ps1' -last 4h

Show all AppSense EM events for the last 4 hours on the local machine for all users

.EXAMPLE

& '.\Ivanti UWM EM event processor.ps1' -start "09:00 10/10/19" -duration 1h -user fred -computername xa02 -triggerOnly

Show trigger duration summaries from computer xa02 for user fred from 0900 for 1 hour on 10th October 2019

#>
[CmdletBinding()]

Param
(
    [string]$computerName ,
	[string]$start ,
	[string]$end ,
	[string]$duration ,
    [string]$last ,
    [string]$user ,
    [string]$csv ,
    [switch]$triggerOnly ,
    [string]$delimiter = ',' ,
    [switch]$noGridView ,
    ## Shouldn't be any need to change these!
    [string]$providerName = 'AppSense Environment Manager.' ,
    [int[]]$successEventIds = @( 9405 , 9407 , 9409 , 9413 , 9420 , 9422 , 9424 , 9426 , 9428 , 9430 , 9432 , 9434 , 9436 , 9438 , 9440 , 9442 , 9662 ) ,
    [int[]]$failEventIds  = @( 9406 , 9408 , 9410 , 9414 , 9421 , 9423 , 9425 , 9427 , 9429 , 9431 , 9433 , 9435 , 9437 , 9439 , 9441 , 9443 )
)

if( $PSBoundParameters[ 'last' ] )
{
    if( $PSBoundParameters[ 'start' ] -or $PSBoundParameters[ 'end' ] )
    {
        Throw 'Cannot use -start or -end with -last'
    }

    ## see what last character is as will tell us what units to work with
    [int]$multiplier = 0
    switch( $last[-1] )
    {
        's' { $multiplier = 1 }
        'm' { $multiplier = 60 }
        'h' { $multiplier = 3600 }
        'd' { $multiplier = 86400 }
        'w' { $multiplier = 86400 * 7 }
        'y' { $multiplier = 86400 * 365 }
        default { Throw "Unknown multiplier `"$($last[-1])`"" }
    }
    Remove-Variable -Name 'End'
    [datetime]$script:end = Get-Date
    if( $last.Length -le 1 )
    {
        $secondsAgo = $multiplier
    }
    else
    {
        $secondsAgo = ( ( $last.Substring( 0 , $last.Length - 1 ) -as [decimal] ) * $multiplier )
    }
    
    Remove-Variable -Name 'Start'
    [datetime]$script:start = $end.AddSeconds( -$secondsAgo )

}
elseif( $PSBoundParameters[ 'start' ] )
{
    ## Check time formats as bad ones get stripped by query so search whole event log
    $parsed = New-Object -TypeName 'DateTime'
    if( ! [datetime]::TryParse( $start , [ref]$parsed ) )
    {
        Throw "Invalid start time/date `"$start`""
    }
    else
    {
        Remove-Variable -Name 'Start'
        [datetime]$script:start = $parsed
    }

    if( $PSBoundParameters[ 'duration' ] )
    {
        if( $PSBoundParameters[ 'end' ] )
        {
            Throw 'Cannot use both -duration and -end'
        }
        [int]$multiplier = 0
        switch( $duration[-1] )
        {
            's' { $multiplier = 1 }
            'm' { $multiplier = 60 }
            'h' { $multiplier = 3600 }
            'd' { $multiplier = 86400 }
            'w' { $multiplier = 86400 * 7 }
            'y' { $multiplier = 86400 * 365 }
            default { Throw "Unknown multiplier `"$($duration[-1])`"" }
        }
        if( $duration.Length -le 1 )
        {
            $secondsDuration = $multiplier
        }
        else
        {
            $secondsDuration = ( ( $duration.Substring( 0 , $duration.Length - 1 ) -as [decimal] ) * $multiplier )
        }
        [datetime]$end = $parsed.AddSeconds( $secondsDuration )
    }
    elseif( ! $PSBoundParameters[ 'end' ] )
    {
        Remove-Variable -Name 'End'
        [datetime]$script:end = Get-Date
    }
    elseif( ! [datetime]::TryParse( $end , [ref]$parsed ) )
    {
        Throw "Invalid end time/date `"$start`""
    }
    else
    {
        Remove-Variable -Name 'End'
        [datetime]$script:end = $parsed
    }
}
## else ## no start

if( $start -gt $end )
{
    Throw "Start $(Get-Date -Date $start -Format G) is after end $(Get-Date -Date $end -Format G)"
}

if( $start -gt (Get-Date) )
{
    Write-Warning "Start $(Get-Date -Date $start -Format G) is in the future by $([math]::Round(($start - (Get-Date)).TotalHours,1)) hours"
}

[hashtable]$filterHashtable = @{ 'ProviderName' = $providerName }

if( $start )
{
    $filterHashtable.Add( 'StartTime' , $start )
}

if( $end )
{
    $filterHashtable.Add( 'EndTime' , $end )
}

if( $PSBoundParameters[ 'user' ] )
{
    if( $user.IndexOf( '\' ) -le 0 )
    {
        $user = $env:USERDOMAIN + '\' + $user
    }
    $sid = (New-Object System.Security.Principal.NTAccount( $user )).Translate([System.Security.Principal.SecurityIdentifier]).value
    if( $sid )
    {
        $filterHashtable.Add( 'UserId' , $sid )
    }
    else
    {
        Throw "Failed to get SID for user $user"
    }
}

[hashtable]$eventArguments = @{ 'FilterHashTable' = $filterHashtable }

if( $PSBoundParameters[ 'computerName' ] )
{
    $eventArguments.Add( 'ComputerName' , $computerName )
}

[int]$timeOffset = [int]::MaxValue

## Can't add $eventids to filter as makes filter too big
[array]$results = @( Get-WinEvent @eventArguments | . { Process `
{
    $event = $PSItem
    [bool]$successEvent = $event.Id -in $successEventIds
    [bool]$failEvent = ! $successEvent -and $event.Id -in $failEventIds

    if( $successEvent -or $failEvent )
    {
        [string]$username = ([System.Security.Principal.SecurityIdentifier]($event.UserId)).Translate([System.Security.Principal.NTAccount]).Value
        if( [string]::IsNullOrEmpty( $username ) )
        {
            $username = $event.UserId
        }

        ## events for trigger completion only have 5 properties and are in a different order
        [int]$startOffset = $(if( $event.Properties.Count -eq 5 ) { 1 } else { 0 } )

        ## Times are not necessarily local time it seems but not UTC
        if( $timeOffset -eq [int]::MaxValue )
        {
            $timeOffSet = ($event.TimeCreated).Hour - (Get-Date -Date $event.Properties[3 - $startOffSet].Value).Hour
        }
        
        [datetime]$eventStart = (Get-Date -Date $event.Properties[0 + $startOffSet].Value).AddHours( $timeOffset )
        [datetime]$eventEnd   = (Get-Date -Date $event.Properties[3 - $startOffset].Value).AddHours( $timeOffset )

        if( $eventStart -gt $eventEnd )
        {
            [datetime]$swap = $eventStart
            $eventStart = $eventEnd
            $eventEnd = $swap
        }

        if( ! $triggerOnly -or ( $triggerOnly -and $startOffset ) )
        {
            [pscustomobject][ordered]@{
                'User' = $username
                'Created' = $event.TimeCreated
                'Start' = $eventStart
                'End'   = $eventEnd
                'Node'  = $event.Properties[1 - $startOffset].Value
                'Success' = $(if( $successEvent ) { 'Yes' } else { 'No' })
                'Event Id' = $event.Id -as [int]
                'Text'  = $(if( $event.Properties.Count -gt 5 ) { $event.Properties[2].Value })
                'Duration (ms)' = $event.Properties[4 - $startOffset].Value -as [int]
                ## Where there is an error code, the properties count is 8 rather than 6
                'Error Code' = $(if( $event.Properties.Count -gt 6 ) { $event.Properties[5].Value -as [int] })
                'Error' = $(if( $event.Properties.Count -gt 7 ) { $event.Properties[6].Value.Trim() })
            }
        }
    }
    ## else not an event we are interested in
}})

if( $results -and $results.Count )
{
    if( $PSBoundParameters[ 'csv' ] )
    {
        $results | Export-Csv -Path $csv -NoClobber -NoTypeInformation -Delimiter $delimiter
    }
    elseif( $noGridView )
    {
        $results
    }
    else
    {
        [string]$title = "$($results.Count) events"
        if( $filterHashtable[ 'StartTime' ] )
        {
            $title += " from  $(Get-Date -Date $filterHashtable[ 'StartTime' ] -Format G)"
        }
        if( $filterHashtable[ 'EndTime' ] )
        {
            $title += " to  $(Get-Date -Date $filterHashtable[ 'EndTime' ] -Format G)"
        }
        if( $PSBoundParameters[ 'user' ] )
        {
            $title += " for user $user"
        }
        [array]$selected = @( $results | Out-GridView -Title $title -PassThru )
        if( $selected -and $selected.Count )
        {
            $selected | Set-Clipboard
        }
    }
}
else
{
    Write-Warning "No relevant events found"
}
