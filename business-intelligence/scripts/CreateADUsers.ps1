param (
    [Parameter(Mandatory=$true)]
    [string]$pdNumber,
    [Parameter(Mandatory=$true)]
    [string]$EnvironmentType,
    [Parameter(Mandatory=$true)]
    [string]$DefaultSecretName
    # [Parameter(Mandatory=$true)]
    # [string]$SecretArn
)

# Import ActiveDirectory module
try {
    Import-Module -Name ActiveDirectory -ErrorAction Stop
} catch {
    if ((Get-WindowsFeature RSAT-DNS-Server).InstallState -ne "True") {
        try {
            Install-WindowsFeature -Name GPMc,RSAT-AD-PowerShell,RSAT-AD-AdminCenter,RSAT-ADDS-Tools,RSAT-DNS-Server -ErrorAction Stop
            Import-Module -Name ActiveDirectory -ErrorAction Stop
        } catch {
            Write-Error "Failed to install ActiveDirectory module: $_"
            exit
        }
    } else {
        Write-Error "Failed to import ActiveDirectory module: $_"
        exit
    }
}

# Retrieve domain admin password from Secret Manager
#$fetchedSecret = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $SecretArn).SecretString
# $fetchedSecret = ConvertFrom-Json -InputObject (aws secretsmanager get-secret-value --secret-id $SecretArn | ConvertFrom-Json).SecretString
# $username = $fetchedSecret.shortname+"\"+$fetchedSecret.username
# $credentials = (New-Object PSCredential($username,(ConvertTo-SecureString $fetchedSecret.password -AsPlainText -Force)))

# Retrieve default secret from Secret Manager
#$fetchedDefault = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $DefaultSecretName).SecretString
$fetchedDefault = ConvertFrom-Json -InputObject (aws secretsmanager get-secret-value --secret-id $DefaultSecretName | ConvertFrom-Json).SecretString
$password = (ConvertTo-SecureString $fetchedDefault.password -AsPlainText -Force)

# Retrieve domain details
$DomainName = (Get-ADDomain -Identity $fetchedDefault.domain).DistinguishedName
$DomainNetBIOS = (Get-ADDomain -Identity $fetchedDefault.domain).NetBIOSName
$DomainDnsRoot = (Get-ADDomain -Identity $fetchedDefault.domain).DNSRoot
$Domain = "OU="+$DomainNetBIOS+","+$DomainName

# Join Domain
if ((Get-WMIObject Win32_ComputerSystem).partofdomain -eq $false) {
    # Add-Computer -DomainName $fetchedSecret.domain -Credential $Credentials -force -Options JoinWithNewName,AccountCreate -restart
    Write-Output "Not part of a domain. Exiting script."
    exit
}
else {
    $DomainOutput = (Get-WMIObject Win32_ComputerSystem).Domain
    Write-Output "Part of domain $DomainOutput."
}
if ([string]::IsNullOrEmpty($DomainNetBIOS)) {
    Write-Error "Failed to retrieve domain details. Script cannot proceed."
    exit
}

# Construct account OU
$pdNumberLower = $pdNumber.ToLower()
$ServiceAccountOU = "OU=Service_Accounts,OU="+$pdNumber
$saPath = $ServiceAccountOU+","+$Domain

$ServiceAccount = $pdNumber.ToUpper()

# Create GMSA users
$gmsaNameArray = "SQL$ServiceAccount","SQLAgent-$($ServiceAccount)","SQLBrowser-$($ServiceAccount)","SQLSIS-$($ServiceAccount)","SQLSAS-$($ServiceAccount)"
$allowedPrincipals = $pdNumberLower+"-db-computers"

foreach ($gmsaName in $gmsaNameArray) {
    # Check if the GMSA already exists in Active Directory
    if (Get-ADServiceAccount -Server $DomainDnsRoot -Filter "Name -eq '$($gmsaName)'") {
        # If the GMSA already exists, update its properties
        Write-Output "$($gmsaName) already exists."
        Get-ADServiceAccount -Server $DomainDnsRoot -Identity $gmsaName
    }
    else {
        Write-Host "Creating user $($gmsaName)"
        # If the GMSA does not exist, create it
        New-ADServiceAccount -Name $($gmsaName) `
        -DNSHostName "$($gmsaName).$($DomainDnsRoot)" `
        -Description "Used for SQL services." `
        -ManagedPasswordIntervalInDays "42" `
        -PrincipalsAllowedToRetrieveManagedPassword $allowedPrincipals `
        -Path $saPath `
        -Enabled $true `
        -SamAccountName $($gmsaName) `
        -Server $DomainDnsRoot
        Write-Output "$($gmsaName) created."
        Get-ADServiceAccount -Server $DomainDnsRoot -Identity $gmsaName
    }
}