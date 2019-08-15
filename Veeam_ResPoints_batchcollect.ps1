<# © 2007-2019 - LogicMonitor, Inc.  All rights reserved. #>

$hostname               = '##system.hostname##'

# If the hostname is an IP address query DNS for the FQDN
if($hostname -match "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"){
    $hostname = [System.Net.Dns]::GetHostbyAddress($hostname).HostName
}

if ([string]::IsNullOrEmpty('##veeam.user##')) { $veeam_user = '##wmi.user##' } else { $veeam_user = '##veeam.user##' }
if ([string]::IsNullOrEmpty('##veeam.pass##')) { $veeam_pass = '##wmi.pass##' } else { $veeam_pass = '##veeam.pass##' }

# Store a date stamp for calculating the age of the restore points
[datetime]$Now = Get-Date
$Now = $Now.ToUniversalTime()


## ******** Beginning of LM Helper Methods *****************************************************************************************

function Make-NotNaN {
    param( $Metric )

    if ( [string]::IsNullOrEmpty($Metric) -or [string]::IsNullOrWhiteSpace($Metric) ) {
        return "0" 
    } else {
        return $Metric 
    }
}

function Get-LMActiveDiscoveryOutput {
    Param (
        # Custom Hashtable of Objects representing the Veeam Jobs.
        [Parameter(Mandatory = $true)]
        $VeeamObjects
    )

    $lm_output = ""

    # Now Print out the AD-Formatted output
    ForEach ($VeeamObject in $VeeamObjects) {
           $tmp_VmID = $VeeamObject.ObjectID
           $tmp_VmName = $VeeamObject.VmName
           $tmp_Location = $VeeamObject.Location
           $tmp_propprefix = "auto.veeam.backupandreplication"
        
        $lm_output += "$($tmp_VmID)##$($tmp_VmName)##$($tmp_Location)####$($tmp_propprefix).vmobjectid=$($tmp_VmID)&$($tmp_propprefix).virtualmachinename=$($tmp_VmName)&$($tmp_propprefix).vmlocation=$($tmp_Location)`n"

    }

return $lm_output
}

$Lookup = @{}
$Lookup.Add('Full',0)
$Lookup.Add('Increment',1)

## ******** Beginning of LM Helper Methods *********************************************************************************************

function Get-VeeamConnection {
    Param (
        # Hostname of the Veeam Server we are connecting to.
        [Parameter(Mandatory = $true)]
        [string]
        $VeeamHostname,

        # Veeam Username
        [Parameter(Mandatory = $true)]
        [string]
        $VeeamUsername,

        # Veeam Password
        [Parameter(Mandatory = $true)]
        [String]
        $VeeamPassword
    )

    $max_attempts = 2
    $attempt_sleep = 2
    $current_attempt_count = 0

    ## Build credential object
    If (($VeeamUsername -like "*veeam.user*") -or ($VeeamUsername -like "*wmi.user*")) {
        # The user has not provided any creds. Let's try with whatever user this thing has.
        while (-Not$veeam_session -and ($current_attempt_count -le $max_attempts)) {
            $current_attempt_count++
            $veeam_session = New-PSSession -ComputerName $VeeamHostname
            Start-Sleep -Seconds $attempt_sleep
        }
    }

    else {
        $secure_pass = ConvertTo-SecureString -String $VeeamPassword -AsPlainText -Force
        $creds = New-Object -typename System.Management.Automation.PSCredential($VeeamUsername, $secure_pass)

        ## Attempt to acquire a persistent session object.  Keep trying until we hit the $max_attempts value.
        while (-Not$veeam_session -and ($current_attempt_count -le $max_attempts)) {
            $current_attempt_count++
            $veeam_session = New-PSSession -ComputerName $VeeamHostname -Credential $creds
            Start-Sleep -Seconds $attempt_sleep
        }
    }

    ## Ensure that the session was successfully created, otherwise exit.
    if ( -Not $veeam_session ) {
        Write-Host "Error connecting session.  Terminating."
        Exit
    }

    return $veeam_session
}

function Get-VeeamVirtualMachines {
    
    Param (
        <# Veeam Session Object
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]
        $VeeamSession#>
        [Parameter(Mandatory= $true)]
        [string]$JobType
        
    )

    $tmp_veeam_objects = @()
    <#
    ## Make the call to the Veeam PS cmdlet to retrieve the backup jobs
    $vjs = Invoke-Command -Session $VeeamSession -ScriptBlock {
        Add-PSSnapin -Name VeeamPSSnapIn -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        
   
        $RemoteJobs = Get-VBRJob -WarningAction SilentlyContinue | Where-Object { $_.JobType -eq "Backup" } | Select-Object -Property *
        ForEach ($Job in $RemoteJobs) {Get-VBRJobObject -Job $Job.Name | ? {$_.Type -eq "Include"}}
    
    }#> #Replace this section with a PS Session.  Working on code below.

    $RemoteJobs = Get-VBRJob -WarningAction SilentlyContinue | Where-Object { $_.JobType -eq $JobType } | Select-Object -Property *
    ForEach ($Job in $RemoteJobs) {
        $JobName = $Job.Name
        #Collect the Job Objects and build a table of virtual machines
        $JobObjects = Get-VBRJobObject -Job $JobName | ? {$_.Type -eq "Include"}
        ForEach ($vm in $JobObjects) {
            $new_veeam_vm = New-Object -TypeName psobject
            $new_veeam_vm | Add-Member NoteProperty -Name ObjectID -Value $vm.ObjectId
            $new_veeam_vm | Add-Member NoteProperty -Name VmName -Value $vm.Name
            $new_veeam_vm | Add-Member NoteProperty -Name Location -Value $vm.Location
            $new_veeam_vm | Add-Member NoteProperty -Name BackupJobId -Value $vm.JobID
            $new_veeam_vm | Add-Member NoteProperty -Name BackupJobName -Value $JobName
            $new_veeam_vm | Add-Member NoteProperty -Name BackupJobType -Value $JobType
            $tmp_veeam_objects += $new_veeam_vm
        }
    
    }
    return $tmp_veeam_objects
}

Function Get-VeeamRestorePoints {
    Param (
        # GUID of the Veeam Virtual Machine.
        [Parameter(Mandatory = $true)]
        [string]$VmId,

        [Parameter(Mandatory = $true)]
        [string]$JobName

    )
    # Retrieve the restore points by VMiD and JobName
    $RestorePoints = Get-VBRRestorePoint -ObjectId $VmId -Backup $JobName | Select-Object *

    # Get a count of restore points. 
    [int]$RestorePointCount = $RestorePoints.count
    # If there is more than 1 RP, find the latest restore point, the fulls, and the increments
    if ($RestorePointCount -gt 1) {

        # Find the latest consistent Full or Simple restore point and report its size in bytes, type 1=Full 2=Increment 3=Debug, and age in seconds
        $LatestRp = $RestorePoints | ? {$_.IsConsistent -eq "True"} | Sort-Object CreationTimeUtc | Select-Object -Last 1
        [datetime]$LatestCreationTimeUtc = $LatestRp.CreationTimeUtc
        [int64]$LatestAgeSec = (New-Timespan -Start $LatestCreationTimeUtc -End $Now).TotalSeconds
        [string]$LatestType = $LatestRp.Type
        [string]$TypeReturn = $Lookup.$($LatestType)
        [string]$LatestSize = $LatestRp.ApproxSize
    
        # Find the Full restore points and count them.  Excluded "inconsistent/incomplete" fulls
        $Fulls = $RestorePoints | ? {$_.Type -eq "Full"} | ? {$_.IsConsistent -eq "True"}
        $FullCount = $Fulls.Count

        # Find the backup increments and cound them. Exclude "inconsistent/incomplete" increments
        $Increments = $RestorePoints | ? {$_.Type -eq "Increment"} | ? {$_.IsConsistent -eq "True"}
        $IncrementCount = $Increments.Count

        # Sort the fulls so we can pull the newest and oldest
       $Fulls = $Fulls | Sort-Object CreationTimeUtc
       $OldestFull = $Fulls | Select-Object -First 1
       $NewestFull = $Fulls | Select-Object -Last 1
   
       # Find the creationdata of the oldest full and return in in epoch time
       [datetime]$OldFullCreationUtc = $OldestFull.CreationTimeUtc
       #[int64]$OldFullEpochTime = (New-Timespan -Start $EpochStart -End $OldFullCreationUtc).TotalSeconds
       [int64]$OldFullAgeSec = (New-Timespan -Start $OldFullCreationUtc -End $Now).TotalSeconds

       # Find the creationdate of the newest full and return it in Unix Epoch time
       [datetime]$NewFullCreationUtc = $NewestFull.CreationTimeUtc
       # [int64]$NewFullEpochTime = (New-TimeSpan -Start $EpochStart -End $NewFullCreationUtc).TotalSeconds
       [int64]$NewFullAgeSec = (New-Timespan -Start $NewFullCreationUtc -End $Now).TotalSeconds
   

       # Sort the incremenets so we can pull the newest and oldest
       $Increments = $Increments | Sort-Object CreationTimeUtc
       $OldestIncrement = $Increments | Select-Object -First 1
       $NewestIncrement = $Increments | Select-Object -Last 1

       #Find the creationdate of the oldest increment and return in epoch time
       [datetime]$OldIncrementCreationUtc = $OldestIncrement.CreationTimeUtc
       # [int64]$OldIncEpochTime = (New-Timespan -Start $EpochStart -End $OldIncrementCreationUtc).TotalSeconds
       [int64]$OldIncAgeSec = (New-Timespan -Start $OldIncrementCreationUtc -End $Now).TotalSeconds


       # Find the creationdate of the newest increment and return in epoch time
       [datetime]$NewIncrementCreationUtc = $NewestIncrement.CreationTimeUtc
       # [int64]$NewIncEpochTime = (New-TimeSpan -Start $EpochStart -End $NewIncrementCreationUtc).TotalSeconds
       [int64]$NewIncAgeSec = (New-Timespan -Start $NewIncrementCreationUtc -End $Now).TotalSeconds

       # Write out the data to return to Logicmonitor
       # Write-Host "$( $wildvalue ).Status=$( Sanitize-Output $task.Status )"
      
       Write-Host "$( $VmId ).LatestType=$( Sanitize-Output $TypeReturn )"
       Write-Host "$( $VmId ).LatestSize=$( Sanitize-Output $LatestSize )"
       Write-Host "$( $VmId ).FullCount=$( Sanitize-Output $FullCount )"
       Write-Host "$( $VmId ).IncCount=$( Sanitize-Output $IncrementCount )"
       Write-Host "$( $VmId ).OldestFull=$( Sanitize-Output $OldFullAgeSec )"
       Write-Host "$( $VmId ).NewestFull=$( Sanitize-Output $NewFullAgeSec )"
       Write-Host "$( $VmId ).OldestIncrement=$( Sanitize-Output $OldIncAgeSec )"
       Write-Host "$( $VmId ).NewestIncrement=$( Sanitize-Output $NewIncAgeSec )"

       }
       # Else, pull stats for the single restore point
       else {
       $LatestRp = $RestorePoints

        [datetime]$LatestCreationTimeUtc = $LatestRp.CreationTimeUtc
        [int64]$LatestAgeSec = (New-Timespan -Start $LatestCreationTimeUtc -End $Now).TotalSeconds
        [string]$LatestType = $LatestRp.Type
        [string]$TypeReturn = $Lookup.$($LatestType)
        [string]$LatestSize = $LatestRp.ApproxSize
        
        Write-Host "$( $VmId ).LatestType=$( Sanitize-Output $TypeReturn )"
        Write-Host "$( $VmId ).LatestSize=$( Sanitize-Output $LatestSize )"
        Write-Host "$( $VmId ).FullCount=$( Sanitize-Output "1" )"
        Write-Host "$( $VmId ).IncCount=$( Sanitize-Output "0" )"
        Write-Host "$( $VmId ).OldestFull=$( Sanitize-Output $LatestAgeSec )"
        Write-Host "$( $VmId ).NewestFull=$( Sanitize-Output $LatestAgeSec )"
        Write-Host "$( $VmId ).OldestIncrement=$( Sanitize-Output "0" )"
        Write-Host "$( $VmId ).NewestIncrement=$( Sanitize-Output "0" )"

       }
}








## ******** Beginning of the main routine *********************************************************************************************
# Add-PSSnapin -Name VeeamPSSnapIn -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
# $veeam_session = Get-VeeamConnection -VeeamHostname $hostname -VeeamUsername $veeam_user -VeeamPassword $veeam_pass

# Get the Veeam Virtual Machines included in Backup Jobs
$veeam_objects = Get-VeeamVirtualMachines -VeeamSession $veeam_session -JobType "Backup"

Foreach ($vm in $veeam_objects) {
    Write-Warning "Starting VM $($vm.VmName)"
    Get-VeeamRestorePoints -VmId $vm.ObjectID -JobName $vm.BackupJobName


}

Exit
