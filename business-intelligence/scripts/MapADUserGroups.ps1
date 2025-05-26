param (
    [Parameter(Mandatory=$true)]
    [string]$pdNumber,
    [Parameter(Mandatory=$true)]
    [string]$EnvironmentType,
    [Parameter(Mandatory=$true)]
    [string]$DefaultSecretName,
    [Parameter(Mandatory=$true)]
    [string]$authaccessgroup
)

# Import ActiveDirectory module
try {
    Import-Module -Name ActiveDirectory -ErrorAction Stop
} catch {
    if ((Get-WindowsFeature RSAT-DNS-Server).InstallState -ne 'True') {
        try {
            Install-WindowsFeature -Name GPMC,RSAT-AD-PowerShell,RSAT-AD-AdminCenter,RSAT-ADDS-Tools,RSAT-DNS-Server -ErrorAction Stop
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

$fetchedDefault = ConvertFrom-Json -InputObject (aws secretsmanager get-secret-value --secret-id $DefaultSecretName | ConvertFrom-Json).SecretString
$password = (ConvertTo-SecureString $fetchedDefault.password -AsPlainText -Force)

# Retrieve domain details
$DomainName = (Get-ADDomain -Identity $fetchedDefault.domain).DistinguishedName
$DomainNetBIOS = (Get-ADDomain -Identity $fetchedDefault.domain).NetBIOSName
$DomainDnsRoot = (Get-ADDomain -Identity $fetchedDefault.domain).DNSRoot
$Domain = "OU="+$DomainNetBIOS+","+$DomainName

if ([string]::IsNullOrEmpty($DomainNetBIOS)) {
    Write-Error "Failed to retrieve domain details. Script cannot proceed."
    exit
}

$ServiceAccount = $pdNumber.ToUpper()

## Add the SQL GMSA to pd-auth-db group
$gmsaNameArray = "SQLService-$($ServiceAccount)","SQLAgent-$($ServiceAccount)","SQLBrowser-$($ServiceAccount)","SQLSIS-$($ServiceAccount)","SQLSAS-$($ServiceAccount)","SQLSRS-$($ServiceAccount)"
$groupsqlNameArray = $authaccessgroup

foreach ($userSql in $gmsaNameArray) {
    foreach ($groupsqlName in $groupsqlNameArray) {
        $sqlAccountUn = (Get-ADServiceAccount -Server $DomainDnsRoot -Identity $userSql -Properties PrincipalsAllowedToRetrieveManagedPassword).DistinguishedName
        Add-ADGroupMember -Server $DomainDnsRoot -Identity $groupsqlName -Members $sqlAccountUn
        Write-Output "$userSql added to $groupsqlName."
    }
}