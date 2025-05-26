param (
    [Parameter(Mandatory=$true)]
    [string]$pdNumber,
    [Parameter(Mandatory=$true)]
    [string]$EnvironmentType,
    [Parameter(Mandatory=$true)]
    [string]$DefaultSecretName
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

# App OU GP links
$appGpoArray = "$EnvironmentType-db-settings","db-firewall-policy"

$appOU = "OU=SQL_Servers,OU="+$pdNumber+","+$Domain

$appLinks = (Get-ADOrganizationalUnit -Server $DomainDnsRoot -Filter "distinguishedName -eq '$appOU'" | Get-GPInheritance -Domain $DomainDnsRoot).GpoLinks.DisplayName

foreach ($appGpo in $appGpoArray) {
    if ($appLinks -contains $appGpo) {
        Write-Host "$($appGpo) is already linked to the app servers OU."
    } else {
        Write-Host "$($appGpo) is not linked to the app servers OU. `n"
        New-GPLink -Server $DomainDnsRoot -Name $appGpo -Target $appOU
        Write-Output "GP-Link created. GPO = $($appGpo); Path = $appOU `n"
    }
}