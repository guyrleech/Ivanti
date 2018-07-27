#requires -version 3.0
<#
    Grab AppSense/Ivanti AMC configuration details via web services API and export to csv or xml file

    @guyrleech (c) 2018

    Modification History:

#>

<#
.SYNOPSIS

Retrieve configuration for AppSense/Ivanti Management Centre and export to CSV or XML file(s)

.PARAMETER outputFolder

Folder where the output files will be created which must exist before the script is run unless the -force option is specified which will create the folder if it does not exist

.PARAMETER servers

A comma separated list of AMC servers to query. There is little benefit in specifying more than one server if they are configured to use the same SQL database unless using -wmi
An optional :<port> can be appended to a server name which will override the -port parameter

.PARAMETER format

Whether to produce a single XML file or multiple CSV ones

.PARAMETER port

The IIS port to connect to

.PARAMETER force

Will overwrite output files if they exist already otherwise the exports will fail

.PARAMETER https

Connect to the AMC using https

.PARAMETER wmi

Gather information about machine and resources via WMI/CIM

.PARAMETER machines

Include information about machines within AMC

.PARAMETER alerts

Include alerts. If -daysBack not specified then will include all alerts

.PARAMETER events

Include events. If -daysBack not specified then will include all events

.PARAMETER daysBack

The number of days back to include events and alerts for. Will include all if not specified which can be slow

.PARAMETER cpuSamples

How many seconds to sample CPU consumption over. Zero means no CPU sampling occurs

.PARAMETER webServicesDll

The AMC web services dll to use

.PARAMETER installDir

THe AMC console installation folder which contains the AMC web services dll

.EXAMPLE

& '.\AMC config.ps1' -outputFolder c:\temp\AMC -format CSV

Will collect information for the AMC server the script is running on and write multiple CSV files containing the configuration to the c:\temp\AMC folder

.EXAMPLE

& '.\AMC config.ps1' -outputFolder c:\temp\AMC -format XML -servers amcprod01,amctest01 -machines -events -alerts -daysBack 60 -wmi -cpuSamples 15

Will collect information for the AMC servers amcprod01 and amctest01 and write a single XML file to the c:\temp\AMC folder which will include system and resource info via WMI/CIM, 
average CPU consumption over 15 seconds, all machines known to the AMCs and all events and alerts created in the last 60 days.

.NOTES

The script must run where the AMC console is installed to that it has access to the web services API dll.
The script must be run as a user who has sufficient access to the AMC to query the items requested.

#>

[CmdletBinding()]

Param
(
    [string]$outputFolder = '.' ,
    [string[]]$servers= @( 'localhost' ) ,
    [ValidateSet('XML','CSV')]
    [string]$format = 'XML' ,
    [switch]$force ,
    [switch]$wmi ,
    [switch]$alerts ,
    [switch]$events ,
    [switch]$machines ,
    [ValidateScript( { $_ -ge 0 })]
    [int]$daysBack = 0 ,
    [ValidateScript( { $_ -gt 0 })]
    [int]$port = 7751 ,
    [ValidateScript( { $_ -ge 0 })]
    [int]$cpuSamples = 0 ,
    [switch]$https ,
    [string]$installDir = "$env:ProgramFiles\AppSense\Management Center\Console",
    [string]$webServicesDll = 'ManagementConsole.WebServices.dll'
)

[string[]]$conditionTypes = @(
    'NetBIOS' ,
    'Container' , ## also used for AD computer where filter will be computer name rather than *
    'Computer Group' , ## documentation is wrong
    'Domain' ,  ## not used AFAIK
    'All' )

Add-Type -Path ( Join-Path $installDir $webServicesDll ) -ErrorAction Stop

[string]$server = $null
[string[]]$excludedFields = @( '*key','*guid','RowError','RowState','Table','ItemArray' )
[hashtable]$exportParams = @{}
[datetime]$dateFrom = if( $daysBack ) { (Get-Date).AddDays( -$daysBack ) } else { (Get-Date).AddYears( -20 ) }

if( ! $force )
{
    $exportParams.Add( 'NoClobber' , $true )
}

if( ! ( Test-Path -Path $outputFolder -PathType Container ) )
{
    if( $force )
    {
        $newFolder = New-Item -Path $outputFolder -ItemType Directory -Force
        if( ! $newFolder )
        {
            Exit 1
        }
    }
    else
    {
        Write-Error "Output folder `"$outputFolder`" does nto exist. Use -force to create"
        Exit 2
    }
}

$results = @( ForEach( $server in $servers )
{
    [string]$thisServer,[int]$thisPort = if( $server.IndexOf( ':' ) -ge 0 ) { ($server -split ':') } else { $server , $port  } 
    
    Write-Verbose ( "{0}:{1}" -f $thisServer , $thisPort )

    [bool]$carryOn= $true

    $url = 'http{2}://{0}:{1}/ManagementServer' -f $thisServer, $thisPort , $(if( $https ) { 's' } )

    $credential = [System.Net.CredentialCache]::DefaultCredentials.GetCredential( $url, 'Basic' )
    
    try
    {
        [ManagementConsole.WebServices]::Connect( $url, $credential )
    }
    catch
    {
        Write-Warning "Failed to connect to AMC on $url"
        $carryOn = $false
    }

    if( $carryOn )
    {
        $assignedPackages = New-Object System.Collections.ArrayList
        $auditing = New-Object System.Collections.ArrayList
        $installationSchedules = New-Object System.Collections.ArrayList
        $membershipRules = New-Object System.Collections.ArrayList
        $allEvents = New-Object System.Collections.ArrayList

        $eventDefinitions =[ManagementConsole.WebServices]::Events.GetEventDefinitions()
        [hashtable]$eventDefinitionsLookup = @{}
        $eventDefinitions.EventDefinition | ForEach-Object `
        {
            $eventDefinitionsLookup.Add( $_.EventDefinitionKey , $_ )
        }

        ## Get global events
        $allEvents = @( if( $events )
        {
            $theseEvents = [ManagementConsole.WebServices]::Events.GetEventsFromGroupKey( $null , $true )
            Write-Verbose "Got $($theseEvents.Event.Count) global events"
            $theseEvents.Event | Where Time -ge $dateFrom | ForEach-Object `
            {
                $event = $_
                $eventDefinition = $eventDefinitionsLookup[ $event.EventDefinitionKey ]
                [string]$eventText = $eventDefinition.EventDescription
                $theseEvents.Param | Where EventKey -eq $event.EventKey | ForEach-Object `
                {
                    $eventText = $eventText -replace "{$($_.Name)}" , $_.Value
                }
                $event | Select GroupName,@{n='Event Id';e={$_.EventDefinitionKey}},@{n='Name';e={$eventDefinition.Name}},@{n='Product';e={$eventDefinition.ProductName}},@{n='Event';e={$eventText}},UserName,MachineName,Time
            }
        } )

        $groups = [ManagementConsole.WebServices]::Groups.GetGroups($true).Groups
        [hashtable]$groupNames = @{}
        ForEach( $group in $groups )
        {
            $groupNames.Add( $group.GroupKey , $group.Name )
        }
        $serverDetails = [ManagementConsole.WebServices]::Database.GetInfo().NamedValues | select -ExcludeProperty $excludedFields -Property *
        $failoverServers = [ManagementConsole.WebServices]::Servers.GetServers($true).Servers | select -ExcludeProperty $excludedFields -Property *,@{n='Group';e={$groupNames[ $_.GroupKey ]}}
        if( $machines )
        {
            $allMachines = [ManagementConsole.WebServices]::Machines.GetMachines($true).Machines | select -ExcludeProperty $excludedFields -Property *
            $discoveredMachines = [ManagementConsole.WebServices]::DiscoveredMachines.GetMachines().DiscoveredMachines | select -ExcludeProperty $excludedFields -Property *
        }
        $credentials = [ManagementConsole.WebServices]::Deployment.GetDeploymentCredentials().Credentials| select -ExcludeProperty $excludedFields -Property *
        $securityRoles = [ManagementConsole.WebServices]::Security.GetSecurityRoles($true).SecurityRoles| select -ExcludeProperty $excludedFields -Property *

        [hashtable]$roleMasks = @{}
        ForEach( $role in $securityRoles )
        {
            try
            {
                $roleMasks.Add( $role.PermissionsMask -as [long] , $role.Name )
            }
            catch {}
        }

        $users = [ManagementConsole.WebServices]::Security.GetUsers().Users | Select Name,Sid,IsGroup,IsMember,CreationTime,ModifiedTime,@{n='Role';e={ if( $_.SecurityDescriptor -match ( ';S:\(A:(\d+):{0};\)' -f $_.sid ) ) { $roleMasks[ ( $matches[1] -as [long] ) ] }}},SecurityDescriptor,PolicyKey
        $licences = [ManagementConsole.WebServices]::Licenses.GetV2Licenses().licensingv2 | Select DisplayName,IssueDate,ExpiryDate,CustomerName,CreationTime,ModifiedTime
        $products = [ManagementConsole.WebServices]::Products.GetProducts().products | select -ExcludeProperty ( $excludedFields + 'Icon' ) -Property *
        $reports = [ManagementConsole.WebServices]::Reports.GetReportDefinitions().ReportDefinitions | select -ExcludeProperty $excludedFields -Property *

        [int]$counter = 1

        ForEach( $group in $groups )
        {
            Write-Verbose "Processing group $counter / $($groups.Count) `"$($group.Name)`""

            $assignedPackages += [ManagementConsole.WebServices]::Groups.GetGroupPackages( $group.GroupKey ).GroupPackages | 
                Select @{n='Group';e={$group.Name}},Name,Type,Company,Platform,ProductName,Major,Minor,Build,Revision,Exists,CreationTime,ModifiedTime,PatchCode,PatchMajor,PathcMinor,PatchBuild,PatchRevision
            $auditing += [ManagementConsole.WebServices]::Groups.GetEventFilter($group.GroupKey).EventFilter | Where-Object { $_.Enabled } | 
                Select @{n='Group';e={$group.Name}},EventDefinitionKey,Name,Description,ProductName,Enabled,HighVolume,DefaultEnabledState
            $installationSchedules += [ManagementConsole.WebServices]::Groups.GetInstallationSchedule($group.GroupKey).Schedule | 
                Select @{n='Group';e={$group.Name}},* -ExcludeProperty $excludedFields
            $membershipRules += [ManagementConsole.WebServices]::Conditions.GetConditions($group.GroupKey).Conditions  | 
                Select @{n='Group';e={$group.Name}},@{n='Priority';e={$group.Priority}},ConditionPK,ConditionType,@{n='Condition Type';e={$conditionTypes[ $_.ConditionType ]}},IsInclude,IncludeChildren,ADObjectDistinguishedName,ModifiedTime,Filter,Domain
            $allEvents += @( if( $events )
            {
                $theseEvents = [ManagementConsole.WebServices]::Events.GetEventsFromGroupKey($group.GroupKey,$true)
                Write-Verbose "`tGot $($theseEvents.Event.Count) group events"
                $theseEvents.Event | Where Time -ge $dateFrom  | ForEach-Object `
                {
                    $event = $_
                    $eventDefinition = $eventDefinitionsLookup[ $event.EventDefinitionKey ]
                    [string]$eventText = $eventDefinition.EventDescription
                    $theseEvents.Param | Where EventKey -eq $event.EventKey | ForEach-Object `
                    {
                        $eventText = $eventText -replace "{$($_.Name)}" , $_.Value
                    }
                    $event | Select GroupName,@{n='Event Id';e={$_.EventDefinitionKey}},@{n='Name';e={$eventDefinition.Name}},@{n='Product';e={$eventDefinition.ProductName}},@{n='Event';e={$eventText}},UserName,MachineName,Time
                }
            } )
            $counter++
        }

        [hashtable]$packages = @{}
        [ManagementConsole.WebServices]::Packages.GetPackages().Packages | ForEach-Object `
        {
            $packages.Add( $_.PackageKey , $_ )
        }

        $machinePackages = @( [ManagementConsole.WebServices]::Packages.GetPackages().PackageVersions | ForEach-Object `
        {
            $package = $packages[ $_.PackageKey ]
            if( ! $package )
            {
                Write-Warning "Failed to get package for version $_"
            }
            else
            {
                Add-Member -InputObject $_ -NotePropertyMembers `
                @{
                    'Product Name' = $package.ProductName
                    'Type' = $package.Type
                }
            }
            $_
        }  | select -ExcludeProperty ( $excludedFields + 'PackagesRow' ) -Property * )
        
        $groups = $groups | Select -ExcludeProperty $excludedFields -Property *

        $wmiInfo = $null

        if( $wmi )
        {
            $osinfo,$logicalDisks,$computerInfo,$hotfixCount,$latestHotfix,$nics = Invoke-Command -ComputerName $thisServer -ScriptBlock `
            {
                Get-WmiObject -Class Win32_OperatingSystem
                Get-WmiObject -Class Win32_logicaldisk -Filter 'DriveType = 3'
                Get-WmiObject -Class Win32_ComputerSystem
                $hf = @( Get-HotFix )
                $hf.Count
                $hf | Where InstalledOn | sort InstalledOn -Descending | Select -First 1 -ExpandProperty InstalledOn
                @( Get-NetAdapter )
            }
            $wmiInfo = [pscustomobject]@{
                'Operating System' = $osinfo.Caption
                'Total Visible Memory (MB)' = [math]::Round( $osinfo.TotalVisibleMemorySize / 1KB )
                'Free Memory (MB)' = [math]::Round( $osinfo.FreePhysicalMemory / 1KB ) ## already in KB 
                'Free Pagefile Space (MB)' = [math]::Round( $osinfo.FreeSpaceInPagingFiles / 1KB )
                'Committed Memory' = ( '{0:N1}%' -f ( 100 - [Math]::Round( ( $osinfo.FreeVirtualMemory / $osinfo.TotalVirtualMemorySize ) * 100 , 1 ) ) )
                'Logical Processors' = $computerInfo.NumberOfLogicalProcessors
                'Processors' = $computerInfo.NumberOfProcessors
                'Last Booted' = [Management.ManagementDateTimeConverter]::ToDateTime(  $osinfo.LastBootUpTime )
                'Install Date' = [Management.ManagementDateTimeConverter]::ToDateTime( $osinfo.InstallDate )
                'Country Code' = $osinfo.CountryCode
                'Build Number' = $osinfo.BuildNumber
                'Hotfix Last Installed' = Get-Date -Date $latestHotfix -Format d
                'Hotfixes Installed' = [int]$hotfixCount
            }
            
            if( $cpuSamples -gt 0 )
            {
                Write-Verbose "Sampling CPU for $cpuSamples seconds ..."
                Add-Member -InputObject $wmiInfo -MemberType NoteProperty -Name "CPU usage over $cpuSamples seconds" -Value `
                   ( '{0:N1}%' -f ( Get-Counter -ComputerName $thisServer -Counter '\Processor(*)\% Processor Time' -SampleInterval 1 -MaxSamples $cpuSamples |select -ExpandProperty CounterSamples| Where-Object { $_.InstanceName -eq '_total' } | select -ExpandProperty CookedValue  | Measure-Object -Average ).Average )
            }

            $logicalDisks | ForEach-Object `
            {
                Add-Member -InputObject $wmiInfo -NotePropertyMembers @{
                    "Disk $($_.DeviceId) size (GB)" = "$([math]::Round( $_.Size / 1GB, 1))"
                    "Disk $($_.DeviceId) free space (GB)" = "$([math]::Round( $_.FreeSpace / 1GB, 1))"
                }
            }

            $nics | ForEach-Object `
            {
                Add-Member -InputObject $wmiInfo -NotePropertyMembers @{
                    ( '"{0}" description' -f $_.Name ) = $_.InterfaceDescription
                    ( '"{0}" status' -f $_.Name ) = $_.Status
                    ( '"{0}" speed' -f $_.Name ) = $_.LinkSpeed
                    ( '"{0}" MTU size' -f $_.Name ) = $_.MTUsize
                    ( '"{0}" media connection state' -f $_.Name ) = $_.MediaConnectionState
                }
            }
        }
        
        $allAlerts = $null
        if( $alerts )
        {
            $allAlerts = @( [ManagementConsole.WebServices]::Alerts.GetAlerts().Alerts | Where Time -ge $dateFrom  | Select -Property * -ExcludeProperty $excludedFields )
        }

        if( $format -eq 'CSV' )
        {
            $failoverServers | Export-Csv -Path ( Join-Path $outputFolder "$($server).failoverservers.csv" ) -NoTypeInformation @exportParams
            $credentials | Export-Csv -Path ( Join-Path $outputFolder "$($server).credentials.csv" ) -NoTypeInformation @exportParams
            $users | Export-Csv -Path ( Join-Path $outputFolder "$($server).users.csv" ) -NoTypeInformation @exportParams
            $groups | Export-Csv -Path ( Join-Path $outputFolder "$($server).groups.csv" ) -NoTypeInformation @exportParams
            $serverDetails | Export-Csv -Path ( Join-Path $outputFolder "$($server).serverdetails.csv" ) -NoTypeInformation @exportParams
            $machinePackages | Export-Csv -Path ( Join-Path $outputFolder "$($server).packages.csv" ) -NoTypeInformation @exportParams
            $securityRoles | Export-Csv -Path ( Join-Path $outputFolder "$($server).securityroles.csv" ) -NoTypeInformation @exportParams
            $membershipRules | Export-Csv -Path ( Join-Path $outputFolder "$($server).membershiprules.csv" ) -NoTypeInformation @exportParams
            $assignedPackages | Export-Csv -Path ( Join-Path $outputFolder "$($server).assignedpackages.csv" ) -NoTypeInformation @exportParams
            $auditing | Export-Csv -Path ( Join-Path $outputFolder "$($server).auditing.csv" ) -NoTypeInformation @exportParams
            $licences | Export-Csv -Path ( Join-Path $outputFolder "$($server).licences.csv" ) -NoTypeInformation @exportParams
            $products | Export-Csv -Path ( Join-Path $outputFolder "$($server).products.csv" ) -NoTypeInformation @exportParams
            $reports | Export-Csv -Path ( Join-Path $outputFolder "$($server).reports.csv" ) -NoTypeInformation @exportParams
            $installationSchedules | Export-Csv -Path ( Join-Path $outputFolder "$($server).installationschedules.csv" ) -NoTypeInformation @exportParams

            if( $allAlerts -and $allAlerts.Count )
            {
                $allAlerts | Export-Csv -Path ( Join-Path $outputFolder "$($server).alerts.csv" ) -NoTypeInformation @exportParams
            }
            if( $allEvents -and $allEvents.Count )
            {
                $allEvents | Export-Csv -Path ( Join-Path $outputFolder "$($server).events.csv" ) -NoTypeInformation @exportParams
            }
            if( $wmiInfo )
            {
                $wmiInfo | Export-Csv -Path ( Join-Path $outputFolder "$($server).wmiinfo.csv" ) -NoTypeInformation @exportParams
            }
            if( $machines )
            {
                $discoveredMachines | Export-Csv -Path ( Join-Path $outputFolder "$($server).discoveredmachines.csv" ) -NoTypeInformation @exportParams
                $allMachines | Export-Csv -Path ( Join-Path $outputFolder "$($server).machines.csv" ) -NoTypeInformation @exportParams
            }
        }
        else
        {
            $object = [pscustomobject]@{ 
                    'Server' = '{0}:{1}' -f $server,$port
                    'Failover Servers' = $failoverServers
                    'Security Roles' = $securityRoles
                    'Membership Rules' = $membershipRules
                    'Assigned Packages' = $assignedPackages
                    'Auditing' = $auditing
                    'Installation Schedules' = $installationSchedules
                    'Packages' = $machinePackages
                    'Client Access Credentials' = $credentials 
                    'Users' = $users
                    'Deployment Groups' = $groups
                    'Server Details' = $serverDetails
                    'Licences' = $licences
                    'Products' = $products
                    'Reports' = $reports
                }
            if( $machines )
            {
                Add-Member -InputObject $object -NotePropertyMembers `
                @{
                    'Machines' = $allMachines
                    'Discovered Machines' = $discoveredMachines
                 }
            }
            if( $allAlerts -and $allAlerts.Count )
            {
                Add-Member -InputObject $object -MemberType NoteProperty -Name 'Alerts' -Value $allAlerts
            }
            if( $allEvents -and $allEvents.Count )
            {
                Add-Member -InputObject $object -MemberType NoteProperty -Name 'Events' -Value $allEvents
            }
            if( $wmiInfo )
            {
                Add-Member -InputObject $object -MemberType NoteProperty -Name 'WMI Info' -Value $wmiInfo
            }
            ## change object type name so it looks "nice" in XML output
            $object.pstypenames.Clear()
            $object.pstypenames.Add('Ivanti.AMC.Configuration')
            $object
        }

        [ManagementConsole.WebServices]::Disconnect()
    }
} )

if( $results -and $results.Count -and $format -eq 'XML' )
{ 
    $results | Export-Clixml -Path ( Join-Path $outputFolder 'AMC-config.xml' ) @exportParams 
}