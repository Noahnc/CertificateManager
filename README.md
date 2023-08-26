# Azure Certificate Manager

The following terraform module deploys a Certificate Manger on Azure. The Certificate Manager is an Azure Automation Service that automatically requests certificates from Let's Encrypt for specified domains and stores them in Azure Key Vault. The certificates are then checked regularly and renewed if necessary.

## Requirements

In order to be able to use this module, the following prerequisites must be met:

- The specified KeyVault must use Azure role-based access control (rbac) as authorization model. Vault access policies cannot be used.
- The module can only create and manage certificates for domains hosted as zones in Azure DNS.
- In order for the module to be able to execute the Azure Automation Job directly after changes to the module inputs have been made, this module calls the shell of the host OS and sends a post request to the Azure Automation Webhook with Curl. Therefore, curl must be installed on the host.
- If you want to use the Input `certificates.authorized_role_assigners`, you have to create the following custom role:

```bash
resource "azurerm_role_definition" "custom_role_assigner" {
  name        = "Custom-Role-Assignment-Contributor"
  scope       = <subscription-id>
  description = "Custom Role allowing to assign roles on azure resources"
  permissions {
    actions = [
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleAssignments/delete",
      ]
  }
}
```

## Important notes

- When adding a new certificate to the `certificates` input map, Terraform will first create a self-signed dummy certificate in the KeyVault. This is necessary so that Terraform knows the ID of the certificate for the output map. After Terraform has created all resources, the runbook job is executed, which requests the certificate from Let's Encrypt and replaces the dummy certificate. However, this process can take a few minutes.

## Example

```bash
module "main_certificate_manager" {
  source                 = <module-source>
  name                   = <name>
  location               = <location>
  resource_group_name    = <resource-group-name>
  key_vault              = {
    name                = <key-vault-name>
    id = <key_vault_id>
  }
  enable_verbose_logging = false
  default_contact_email  = <mail>
  run_schedule = {
    start_time = "22:00"
  }
  certificates = {
    "example-wildcard" = {
      main_domain         = "*.example.com"
      alternative_domains = ["*.prod.example.com", "*.stage.example.com"]
    }
}
```
