locals {
  module_tags = {
    Environment = "${terraform.workspace}"
    Resource    = "AzureAutomation"
  }

  runbook_parameters = merge({ renewal_deadline_days = var.certificate_renewal_deadline_days }, { account_email = var.default_contact_email }, { key_vault_name = var.key_vault.name }, { subscription_id = data.azurerm_client_config.current.subscription_id }, { certificate_configs = jsonencode([for k, v in var.certificates : {
    ID           = "sslcert-${k}"
    Domains      = concat([v.main_domain], v.alternative_domains)
    Email        = v.email == null ? var.default_contact_email : v.email
    LEServerName = v.enable_staging_mode == true ? "LE_STAGE" : "LE_PROD"
    CertKey      = v.cert_key
    }])
  })


  # Hash of the some certificate config attributes to trigger the recreation of the runnbook triggers when the certificate config changes
  certificate_config_hash = sha256(jsonencode({ for k, v in var.certificates : k => {
    email               = v.email
    main_domain         = v.main_domain
    alternative_domains = v.alternative_domains
    enable_staging_mode = v.enable_staging_mode
    cert_key            = v.cert_key
  } }))
}


resource "azurerm_automation_account" "main" {
  name                = "aaa-CertMan-${var.name}-${var.location}-${terraform.workspace}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "Basic"
  identity {
    type = "SystemAssigned"
  }
  tags = merge(local.module_tags, var.tags)
}

data "local_file" "main" {
  filename = "${path.module}/data/Renew-ACMECertificates.ps1"
}

resource "azurerm_automation_runbook" "main" {
  name                    = "aar-CertMan-${var.name}-${var.location}-${terraform.workspace}"
  location                = var.location
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.main.name
  log_verbose             = var.enable_verbose_logging
  log_progress            = var.enable_verbose_logging
  description             = "This Runbook will check all certificates in the given Key Vault and renew them if they are about to expire using ACME-Let's Encrypt."
  runbook_type            = "PowerShell"
  content                 = data.local_file.main.content
  tags                    = merge(local.module_tags, var.tags)
}

resource "azurerm_automation_module" "posh-acme" {
  name                    = "posh-acme"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.main.name

  module_link {
    uri = "https://psg-prod-eastus.azureedge.net/packages/posh-acme.4.18.0.nupkg"
  }
}

resource "time_offset" "scheduled_run_start_time" {
  offset_days = 1
  triggers = {
    run_schedule_config_hash = sha256(jsonencode(var.run_schedule))
    certificates_config_hash = local.certificate_config_hash
    name                     = var.name
    resource_group_name      = var.resource_group_name
    location                 = var.location
  }

}

# Creates a timestamp that is 3 days in the future. This is used as the expiry time for the Azure Automation Webhook.
# The Webhook is only needed to trigger the Runbook once after a new Domain is added or the configuration has changed.
resource "time_offset" "azure_automation_webhook_lifetime" {
  offset_days = 3
  triggers = {
    config_hash = local.certificate_config_hash
    script      = data.local_file.main.content_sha256
  }
}

resource "azurerm_automation_schedule" "main" {
  name                    = "aas-CertMan-${var.name}-${var.location}-${terraform.workspace}"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.main.name
  frequency               = "Hour"
  interval                = var.run_schedule.runs_every_other_hour
  timezone                = var.run_schedule.timezone
  # Initial start has to be at least 5min in the future. Because of this, every time the azurerm_automation_schedule.main has to be replaced, a new start_time will be calculated that is the current time + one day.
  # The time of that timestamp is than replaced by the scheduled_run_start_time varibale.
  start_time = "${substr(time_offset.scheduled_run_start_time.rfc3339, 0, 10)}T${var.run_schedule.start_time}:00Z"
  lifecycle {
    replace_triggered_by = [
      time_offset.scheduled_run_start_time
    ]
  }
}

resource "azurerm_automation_job_schedule" "main" {
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.main.name
  schedule_name           = azurerm_automation_schedule.main.name
  runbook_name            = azurerm_automation_runbook.main.name
  parameters              = local.runbook_parameters
  lifecycle {
    replace_triggered_by = [
      azurerm_automation_schedule.main,
      azurerm_automation_runbook.main
    ]
  }
}

# The webhook is used to trigger the Job onece after a new Domain has been added or the configuration-hash has changed.
resource "azurerm_automation_webhook" "main" {
  name                    = "aaw-CertMan-${var.name}-${var.location}-${terraform.workspace}"
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.main.name
  expiry_time             = time_offset.azure_automation_webhook_lifetime.rfc3339
  enabled                 = true
  runbook_name            = azurerm_automation_runbook.main.name
  parameters              = local.runbook_parameters
}

# If any of the depends_on resources has changed, this null_resource will be recreated and therefore the webhook triggered, that runs the job.
# The webhook is triggerd using Post Request send by curl.
resource "terraform_data" "webhook_post_request" {

  provisioner "local-exec" {
    command = "curl -d -X POST ${azurerm_automation_webhook.main.uri}"
  }

  depends_on = [
    azurerm_automation_module.posh-acme,
    azurerm_automation_webhook.main,
    azurerm_automation_runbook.main,
    azurerm_role_assignment.dns_contributor,
    module.automation_account_keyvault_permissions,
    azurerm_key_vault_certificate.main
  ]

  lifecycle {
    replace_triggered_by = [
      azurerm_automation_webhook.main
    ]
  }
}

# This resource is used to create each certificate initialy as Self-Signed Certificate in the KeyVault, so that Terraform knows the ID of the certificate.
# After the Runbook job has been triggered, it will find this certificate and replace it with a Let's Encrypt certificate.
# Based on the lifecycle block, this resource will ignore any changes on the actual certificate and will only initialy create it and remove it when the certificate is no longer in the var.certificates map.
resource "azurerm_key_vault_certificate" "main" {
  for_each     = var.certificates
  name         = "sslcert-${each.key}"
  key_vault_id = var.key_vault.id
  tags         = { CertificateConfigHash = "replace_on_next_run" }
  certificate_policy {
    issuer_parameters {
      name = "Self"
    }
    key_properties {
      exportable = true
      key_size   = 4096
      key_type   = "RSA"
      reuse_key  = false
    }
    secret_properties {
      content_type = "application/x-pkcs12"
    }
    x509_certificate_properties {
      key_usage = [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyAgreement",
        "keyCertSign",
        "keyEncipherment",
      ]

      subject_alternative_names {
        dns_names = ["initial-cert.com"]
        emails    = each.value.email != null ? [each.value.email] : [var.default_contact_email]
      }
      subject            = "CN=initial-cert"
      validity_in_months = 1
    }
    lifetime_action {
      action {
        action_type = "EmailContacts"
      }
      trigger {
        days_before_expiry = (var.certificate_renewal_deadline_days - 3)
      }
    }
  }
  lifecycle {
    ignore_changes = all
  }
}

# Assigns dns-contributor permissions to the Automation Account managed identity. Is needed, so that the Runbook can read and create DNS records for the ACME challenge.
resource "azurerm_role_assignment" "dns_contributor" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "DNS Zone Contributor"
  principal_id         = azurerm_automation_account.main.identity.0.principal_id
}

# Assigns the Automation Account managed identity the Key Vault Contributor and Key Vault Administrator role on the Key Vault. This is needed, so that the Runbook can read and write the certificates and modify allowed ips.
module "automation_account_keyvault_permissions" {
  for_each = { for key, value in var.certificates : key => value if value.authorized_role_assigners != null }
  source   = "Noahnc/rbac/azurerm"
  version  = "1.0.1"
  principal_ids = {
    automation_account = azurerm_automation_account.main.identity.0.principal_id
  }
  scopes = {
    keyvault = var.key_vault.id
  }
  role_definitions = ["Key Vault Administrator", "Contributor"]
}

module "certificate_role_assignment_permissions" {
  for_each      = { for key, value in var.certificates : key => value if value.authorized_role_assigners != null }
  source        = "Noahnc/rbac/azurerm"
  version       = "1.0.1"
  principal_ids = each.value.authorized_role_assigners
  scopes = {
    certificate = azurerm_key_vault_certificate.main[each.key].resource_manager_versionless_id
  }
  role_definitions = ["Custom-Role-Assignment-Contributor"]
}
