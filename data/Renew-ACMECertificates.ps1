<#
.SYNOPSIS
    Script to renew a create or renew a list of certificates from Let's Encrypt using the Posh-ACME module
.PARAMETER key_vault_name
    Name of the KeyVault were the certificates are stored
.PARAMETER subscription_id
    ID of the subscription were the KeyVault and the DNS-Zones are located.
.PARAMETER renewal_deadline_days
    Number of days before the certificate expires, when the renewal should be triggered
.PARAMETER AmountOfRetries
    Amount of retries if the commit fails
.PARAMETER certificate_configs
    A list of objects representing the domains for which certificates should be requested or renewed. The object contains the following properties:
    - ID: (required) The unique ID of the Certificate. This ID is used as the name of the certificate in the KeyVault.
    - Email: (required) The email address that will be used for the certificate request.
    - Domains: (required) List of Domains for the certificate.
    - LEServerName: (required) The name of the Let's Encrypt server that should be used for the certificate request. Possible values are: "LEStage" or "LEProduction"
    - CertKey: (required) The key length and algorithm that should be used for the certificate request. Possible values are: "2048" (RSA), "4096 (RSA)", "ec-256" and "ec-384"
#>
#Requires -Modules @{ ModuleName="Posh-ACME"; ModuleVersion="4.18.0" }
#Requires -Modules @{ ModuleName="Az"; ModuleVersion="8.0.0" }
#Requires -Modules @{ ModuleName="Az.KeyVault"; ModuleVersion="4.5.0" }

param
(
    [Parameter (Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String] $key_vault_name,
    [Parameter (Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String] $subscription_id,
    [Parameter (Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Int] $renewal_deadline_days,
    [Parameter (Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [object]$certificate_configs,
    [Parameter (Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String] $account_email
)

Write-Verbose "Got the following certificate_configs input: $($certificate_configs | Out-String)"

foreach ($CertificateConfig in $certificate_configs) {
    if ($null -eq $CertificateConfig.ID) {
        Throw [System.ArgumentNullException]::new("ID is missing for one of the certificate_configs")
    }
    if ($CertificateConfig.ID -Notmatch '[0-9a-zA-Z-]') {
        Throw [System.ArgumentException]::new("ID contains invalid characters, only a-z, A-Z, 0-9 and - are allowed")
    }
    if ($null -eq $CertificateConfig.Email) {
        Throw [System.ArgumentNullException]::new("Email is missing for one of the certificate_configs")
    }
    if ($null -eq $CertificateConfig.Domains) {
        Throw [System.ArgumentNullException]::new("Domains is missing for one of the certificate_configs")
    }
    if ($null -eq $CertificateConfig.LEServerName) {
        Throw [System.ArgumentNullException]::new("LEServerName is missing for one of the certificate_configs")
    }
    if ($null -eq $CertificateConfig.CertKey) {
        Throw [System.ArgumentNullException]::new("CertKey is missing for one of the certificate_configs")
    }
}

$Account = Connect-AzAccount -Identity -ErrorAction Stop

$SuccessfullyRenewedCertificates = New-Object System.Collections.Generic.List[System.Object]
$FailedToRenewCertificates = New-Object System.Collections.Generic.List[System.Object]

# Get public IP of the Automation Runner and add it to the KeyVault allowed IPs
$PublicIP = (Invoke-WebRequest ifconfig.me/ip -UseBasicParsing).Content
Write-Verbose "Automation Account is using the following public IP: $PublicIP"
Add-AzKeyVaultNetworkRule -VaultName $key_vault_name -IpAddressRange "$PublicIP/32" -ErrorAction Stop

$DNSProviderAuthArgs = @{
    AZSubscriptionId = $subscription_id
    AZUseIMDS        = $true
}

function Get-HashFromObject($Object) {
    $ObjectString = $Object | Out-String
    $enc = [system.Text.Encoding]::UTF8
    $data = $enc.GetBytes($ObjectString)
    $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $ResultHash = $sha1.ComputeHash($data)
    $str_out = [Convert]::ToBase64String($ResultHash)
    return $str_out
}
function Get-Certificate($CertificateConfig, $CertificateConfigHash, $KeyVaultName) {
    $RandomSecureString = [System.Guid]::NewGuid().ToString() | ConvertTo-SecureString -AsPlainText -Force
    try {
        Write-Verbose "Requesting Certificate with the following configuration: $($CertificateConfig | Out-String)"
        Set-PAServer $CertificateConfig.LEServerName
        $Certificate = New-PACertificate -Domain $CertificateConfig.Domains -Plugin Azure -PluginArgs $DNSProviderAuthArgs -AcceptTOS -Contact $CertificateConfig.Email -Name $CertificateConfig.ID -CertKeyLength $CertificateConfig.CertKey -PfxPassSecure $RandomSecureString -Force
        Write-Verbose "Certificate $($CertificateConfig.ID) successfully requested from Let's Encrypt: $($Certificate | Out-String)"
    }
    catch {
        Write-Error "Error requesting certificate $($CertificateConfig.ID) from Let's Encrypt: $($_.Exception.Message)" -ErrorAction Continue
        $FailedToRenewCertificates.Add($CertificateConfig)
        return
    }
    try {
        $KeyVaultImportResult = Import-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateConfig.ID -FilePath $Certificate.PfxFullChain -Password $RandomSecureString -Tag @{CertificateConfigHash = $CertificateConfigHash }
        Write-Verbose "Certificate $($CertificateConfig.ID) successfully imported into KeyVault $($KeyVaultName): $($KeyVaultImportResult | Out-String)"
    }
    catch {
        Write-Error "Error importing certificate $($CertificateConfig.ID) into KeyVault $($KeyVaultName): $($_.Exception.Message)" -ErrorAction Continue
        $FailedToRenewCertificates.Add($CertificateConfig)
        return
    }
    $SuccessfullyRenewedCertificates.Add($CertificateConfig)
    return
}

try {
    foreach ($CertificateConfig in $certificate_configs) {
        $CertificateConfigHash = Get-HashFromObject $CertificateConfig
        Write-Verbose "Configuration hash for certificate config $($CertificateConfig.ID) is $CertificateConfigHash"
        $Certificate = Get-AzKeyVaultCertificate -VaultName $key_vault_name -Name $CertificateConfig.ID -ErrorAction SilentlyContinue
        if ($null -eq $Certificate) {
            Write-Output "No Certificate $($CertificateConfig.ID) found in KeyVault $key_vault_name, requesting it now from Let's Encrypt"
            Get-Certificate $CertificateConfig $CertificateConfigHash $key_vault_name
            continue
        }
        $ExpireInDays = ($Certificate.Expires - (Get-Date)).Days
        if ($ExpireInDays -lt $renewal_deadline_days) {
            Write-Output "Certificate $($CertificateConfig.ID) found in keyvault, but expires in $ExpireInDays days, renewing certificate from Let's Encrypt"
            Get-Certificate $CertificateConfig $CertificateConfigHash $key_vault_name
            continue
        }
        if (($null -eq $Certificate.Tags) -or (-not ($Certificate.Tags.ContainsKey("CertificateConfigHash")))) {
            Write-Warning "Certificate $($CertificateConfig.ID) found in keyvault, but no CertificateConfigHash tag found, therefore recreating certificate from Let's Encrypt"
            Get-Certificate $CertificateConfig $CertificateConfigHash $key_vault_name
            continue
        }
        Write-Verbose "Certificate in KeyVault has the following Configuration Hash: $($Certificate.Tags["CertificateConfigHash"])"
        if ($Certificate.Tags["CertificateConfigHash"] -ne $CertificateConfigHash) {
            Write-Output "Certificate $($CertificateConfig.ID) found in keyvault but the configuration has changed, renewing certificate from Let's Encrypt with the new configuration"
            Get-Certificate $CertificateConfig $CertificateConfigHash $key_vault_name
            continue
        }
        Write-Output "Certificate $($CertificateConfig.ID) found in keyvault and is still valid with no configuration changes"
    }

    if ($SuccessfullyRenewedCertificates.Count -gt 0) {
        Write-Output "Successfully renewed the following certificates: $(($SuccessfullyRenewedCertificates | Select-Object -ExpandProperty ID) -join ", ")"
    }
    if ($FailedToRenewCertificates.Count -gt 0) {
        Write-Error "Failed to renew the following certificates: $(($FailedToRenewCertificates | Select-Object -ExpandProperty ID) -join ", ")" -ErrorAction "Stop"
    }
}
catch {
    Write-Error "Unexpected error occured: $($_.Exception.Message)" -ErrorAction "Stop" 
}
finally {
    Remove-AzKeyVaultNetworkRule -VaultName $key_vault_name -IpAddressRange "$PublicIP/32"
}