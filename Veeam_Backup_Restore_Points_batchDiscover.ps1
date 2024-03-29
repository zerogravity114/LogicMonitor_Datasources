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
    Invoke-Command -Session $veeam_session -ScriptBlock {Add-PSSnapin -Name VeeamPSSnapIn -WarningAction SilentlyContinue -ErrorAction SilentlyContinue}
    return $veeam_session
}

function Get-VeeamVirtualMachines {
    
    Param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]
        $VeeamSession,

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

    # $RemoteJobs = Get-VBRJob -WarningAction SilentlyContinue | Where-Object { $_.JobType -eq $JobType } | Select-Object -Property *
    $RemoteJobs = Invoke-Command -Session $VeeamSession -ScriptBlock {Get-VBRJob -WarningAction SilentlyContinue | Where-Object { $_.JobType -eq $Using:JobType } | Select-Object -Property *}
    
    ForEach ($Job in $RemoteJobs) {
        $JobName = $Job.Name
        #Collect the Job Objects and build a table of virtual machines
        $JobObjects = Invoke-Command -Session $VeeamSession -ScriptBlock {Get-VBRJobObject -Job $Using:JobName | ? {$_.Type -eq "Include"}}
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



## ******** Beginning of the main routine *********************************************************************************************
# Add-PSSnapin -Name VeeamPSSnapIn -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
# $veeam_session = Get-VeeamConnection -VeeamHostname $hostname -VeeamUsername $veeam_user -VeeamPassword $veeam_pass
$veeam_session = Get-VeeamConnection -VeeamHostname "localhost" -VeeamUsername "adminpatrick" -VeeamPassword "bTjZ+v6hyshL+j"

# Get the Veeam Virtual Machines included in Backup Jobs
$veeam_objects = Get-VeeamVirtualMachines -VeeamSession $veeam_session -JobType "Backup"

Get-LMActiveDiscoveryOutput -VeeamObjects $veeam_objects

Exit
