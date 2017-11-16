
<#
.SYNOPSIS
	Deploy a new AD forest on a Windows server

.DESCRIPTION
	Extensive description of the script

.Parameter ipaddress
    Specify

.Example
	deploy1stDCtest.ps1 -Azuredeployment $False

This example deploy AD DS in a non Azure environment and requires IP configuration. The script calls the SetStaticIP and requires additional parameters

########################################################################################### 
Starting Script deploy1stDCtest.ps1
########################################################################################### 
Setting static IP Address and DNS
IP Address of Server: 192.168.10.52
Subnet Prefix: 24
Default GW: 192.168.10.2
DNS IP Address: 192.168.10.51
Write to log input parameters
IP Address of Server:  192.168.10.52
Subnet Prefix: 24
Default GW: 192.168.10.2
DNS IP Address: 192.168.10.51
.Example
	deploy1stDCtest.ps1 -DomainName <Domain_FQDN> -NetbiosName <Domain_NetBios_Name>

This example deploy AD DS in Azure environment. No IP config is done in the OS since it is configured on Azure side

.NOTES
    Author:  david
	Version: 0.1
    Date:    20171106
	Usage:   
#>



######################################################################################################
#                                         	PARAMETERS
######################################################################################################

Param (
    [Parameter(Mandatory=$false)]
	[STRING] $Azuredeployment=$true,
    [Parameter(Mandatory=$false)]
	[STRING] $DomainName="RDSLab.io",
    [Parameter(Mandatory=$false)]
	[STRING] $NetbiosName="RDSLAB",  
    [Parameter(Mandatory=$false)]
	[STRING] $DomainLevel="Win2012",
    [Parameter(Mandatory=$false)]
	[STRING] $ForestLevel="Win2012",
    [Parameter(Mandatory=$false)]
	[STRING] $ADDBPath="C:\Windows\NTDS",
    [Parameter(Mandatory=$false)]
	[STRING] $ADLogPath="C:\Windows\NTDS",
    [Parameter(Mandatory=$false)]
	[STRING] $SysvolPath="C:\Windows\SYSVOL",
	[Parameter(Mandatory=$false)]
	[STRING] $IPAddress="192.168.10.11",
	[Parameter(Mandatory=$false)]
	[STRING] $IPPrefix="24",
    [Parameter(Mandatory=$false)]
	[STRING] $IPGW="192.168.10.2",
    [Parameter(Mandatory=$false)]
	[STRING] $IPDNS="192.168.10.11",
    [Parameter(Mandatory=$true)]
	[SECURESTRING] $SafeADMPWD   
    )
    


######################################################################################################
#                                         	Function log
######################################################################################################
function log
{

Param (
	[Parameter(Mandatory=$true,Position=1)]
	[STRING] $string,
	[Parameter(Mandatory=$false,Position=2)]
	[STRING] $color,
    [Parameter(Mandatory=$false,Position=3)]
	[STRING] $datelog
  
    )

    #$date = (get-date).tostring('yyyyMMdd')
    #$hour = (get-date).tostring('HHmmss')
    [string]$logfilename = $datelog + "_deployADtest.log"

    #Testing log Path

    if(!(Test-Path "C:\Scriptlog"))
        {
            New-Item -Name "ScriptLog" -Path c:\ -ItemType Directory
            
            }
    [string]$path = "c:\Scriptlog\"
    $pathlog = $path + $logfilename
   
    if (!$Color) 
        {
            [string]$color = "white"
        }
    #write-host $string -foregroundcolor $color
    (get-date -format yyyyMMdd_HHmmsstt).tostring()+":"+$string | out-file -Filepath $pathlog -Append    
   
}



######################################################################################################
#                                         	Function SetStaticIP
######################################################################################################

function SetStaticIP
{

Param (

	[Parameter(Mandatory=$True)]
	[STRING] $IPAddress,
	[Parameter(Mandatory=$True)]
	[STRING] $IPPrefix,
    [Parameter(Mandatory=$True)]
	[STRING] $IPGW,
    [Parameter(Mandatory=$True)]
	[STRING] $IPDNS    
    )

            log "Getting Interface index" green $dateexecution
            $IPIf = (Get-NetAdapter).ifIndex
            $logging.IPIf = "Interface Index: "+$IPIf
            log $logging.IPIf cyan $dateexecution

            log "Setting IP Address" green $dateexecution
            New-NetIPAddress -IPAddress $IPAddress -PrefixLength $IPPrefix `
            -InterfaceIndex $IPIf -DefaultGateway $IPGW -ea stop | Out-Null
            log "Setting DNS Server" green $dateexecution
            Set-DnsClientServerAddress -InterfaceIndex $IPIf -ServerAddresses ($IPDNS) -ea stop | Out-Null

}

######################################################################################################
#                                         	Function FormatDatadisk
######################################################################################################

function FormatDatadisk
{



            log "Getting offline disk" green $dateexecution
            $OfflineDisks = (Get-Disk | ? {$_.OperationalStatus -eq "Offline"})
            $logging.Offlinedisks = "Offline disks list: "+$OfflineDisks
            log $logging.Offlinedisks cyan $dateexecution

                    #log "Getting the first available drive letter to export for path value in AD installation" green $dateexecution
                    #$availablediskletters = (ls function:[d-z]: -n|?{!(test-path $_)})
                    #$exportavailableletter = $availablediskletters[0].ToString()


            log "Initializing and formating offline disks" green $dateexecution
            $counter = 0

            foreach($disk in $OfflineDisks)
                {
                    $counter = $counter+1

                    log "Getting the first available drive letter for path value in AD installation" green $dateexecution
                    $availablediskletters = (ls function:[d-z]: -n|?{!(test-path $_)})
                    $firstavailableletter = $availablediskletters[0].ToString()
                    $firstavailableletter = $firstavailableletter.ToCharArray()
                    
                    Initialize-Disk -Number $disk.Number -ea stop | Out-Null
                    log "Creating partition for disk " magenta $dateexecution
                    New-Partition -DiskNumber $disk.Number -AssignDriveLetter -UseMaximumSize -ea stop | Out-Null
                    log "Formating volume"
                    [string]$volumelabel = "Data"+$counter
                    Format-Volume -DriveLetter $firstavailableletter[0] -FileSystem NTFS -NewFileSystemLabel $volumelabel -ea stop | Out-Null
                    
                }

            #return ($exportavailableletter)
}

######################################################################################################
#                                         	Main
######################################################################################################

    #Get Date
    $dateexecution = (Get-Date -format yyyyMMdd_HHmmsstt).tostring()
    #Hash table for logging
    [hashtable]$logging = @{}
    #Output hashtable
    [hashtable]$output = @{}

    log "########################################################################################### " green $dateexecution
    log "Starting Script deploy1stDCtest.ps1" green $dateexecution
    log "########################################################################################### " green $dateexecution
    #error variable cleaning
    $Error.clear()




    try 
    {

    #set static IP address only if $Azuredeployment is false

    if($Azuredeployment -eq $false) 
        {
            log "Setting static IP Address and DNS" green $dateexecution
            #$ipaddress = Read-Host "IP Address of Server"
            #$ipprefix = Read-Host "Subnet Prefix"
            #$ipgw = Read-Host "Default GW"
            #$ipdns = Read-Host "DNS IP Address"

            log "Write to log input parameters" green $dateexecution
            $logging.IpAddress = "IP Address of Server:  "+ $IpAddress
            $logging.ipprefix = "Subnet Prefix: "+ $ipprefix
            $logging.ipgw = "Default GW: "+ $ipgw
            $logging.ipdns = "DNS IP Address: "+ $ipdns

            log $logging.IpAddress cyan $dateexecution
            log $logging.ipprefix cyan $dateexecution
            log $logging.ipgw cyan $dateexecution
            log $logging.ipdns cyan $dateexecution



            SetStaticIP -ipaddress $ipaddress -ipprefix $ipprefix -ipgw $ipgw -ipdns $ipdns


            
            }

     log "########################################################################################### " green $dateexecution
     log "Formating Data disks" green $dateexecution
     log "########################################################################################### " green $dateexecution

            FormatDatadisk
            $letterpath = (Get-Volume | ? {$_.FileSystemLabel -eq "Data1"}).DriveLetter
            $logging.ADDiskletter = "AD config files are on "+$letterpath
            log $logging.ADDiskletter cyan $dateexecution
            $ADDBPath = $letterpath+":\NTDS"
            $logging.ADDBPath = "AD Database path is "+$ADDBPath
            log $logging.ADDBPath cyan $dateexecution
            $ADLogPath = $letterpath+":\NTDS"
            $logging.ADLogPath = "AD Log path path is "+$ADLogPath
            log $logging.ADLogPath cyan $dateexecution
            $SysvolPath = $letterpath+":\Sysvol"
            $logging.Sysvol = "AD sysvol path is "+$SysvolPath
            log $logging.Sysvol cyan $dateexecution
    
     log "########################################################################################### " green $dateexecution
     log "Importing Module Servermanager" green $dateexecution
     log "########################################################################################### " green $dateexecution
    
     Import-Module ServerManager -ea stop | Out-Null

     log "Testing AD-Domain-Service presence" green $dateexecution
        if((Get-WindowsFeature -Name "AD-Domain-Services").installstate -eq "installed")
                {
                    log "AD-Domain-Services is installed" green $dateexecution
            
                }
                else
                {
                    log "AD-Domain-Services is not installed" magenta $dateexecution
                    log "Installing AD-Domain-Services" green $dateexecution
                    Install-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -ea stop | Out-Null

                }


        log "Create New Forest, add Domain Controller" green $dateexecution
        log "Importing PS Module ADDSDeployment" green $dateexecution

        Import-Module ADDSDeployment -ea stop | Out-Null
        log "Installing AD Forest and 1st DC" green $dateexecution
        #$ADPassword = ConvertTo-SecureString -String $SafeADMPWD
        Install-ADDSForest -CreateDnsDelegation:$False `
        -DatabasePath $ADDBPath `
        -DomainMode $DomainLevel `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -ForestMode $ForestLevel `
        -InstallDns:$True `
        -LogPath $ADLogPath `
        -NoRebootOnCompletion:$False `
        -SysvolPath $SysvolPath `
        -SafeModeAdministratorPassword $SafeADMPWD `
        -Force:$True -whatif -ea stop | Out-Null 

}


    catch
    {
    log "Erreur détectée" magenta $dateexecution
    
    [string]$result = '$false'
    $logging.error = "An error occured. " +$error[0]
    $logging.result = $result
    $output.error = $logging.error
    $output.result = $logging.result
    $logresult = "Résultat du script :"+ $logging.result
    log $logresult magenta $dateexecution
    log $logging.error magenta $dateexecution
    }
    
    return $output | fl

