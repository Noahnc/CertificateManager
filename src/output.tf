output "automation_account_id" {
  description = "The ID of the Automation Account."
  value       = azurerm_automation_account.main.id
}

output "automation_runnbook_id" {
  description = "The ID of the Automation Runbook."
  value       = azurerm_automation_runbook.main.id
}

output "key_vault_certificates" {
  description = <<EOF
    Map of all the certificates created in the KeyVault.
    The Key is the Key of the certificate input Map.
    The value is an object with the following attributes:
    - id: The ID of the certificate in the KeyVault.
    - secret_id: The ID of the associated secret in the KeyVault.
    - versionless_id: The ID of the certificate in the KeyVault without the version.
    - versionless_secret_id: The ID of the associated secret in the KeyVault without the version (needed for Application Gateway).
    EOF
  value = {
    for index, cert in var.certificates : index => {
      id                    = azurerm_key_vault_certificate.main[index].id
      secret_id             = azurerm_key_vault_certificate.main[index].secret_id
      versionless_id        = azurerm_key_vault_certificate.main[index].versionless_id
      versionless_secret_id = azurerm_key_vault_certificate.main[index].versionless_secret_id
    }
  }
}

