variable "name" {
  description = "The name of the CertificateManager"
  type        = string
}

variable "location" {
  description = "The location/region where the Azure Automation Account running the CertificateManager will be deployed."
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group in which the Azure Automation Account running the CertificateManager will be deployed."
  type        = string
}

variable "default_contact_email" {
  description = "Email address used for the Certificate. This will only be used if no email is set in the certificate object."
  type        = string
}

variable "certificates" {
  description = <<EOF
  A Map of objects containing containing configuration about the certificates to create and manage.
  The Key of the Map is an unique identifier for the certificate that will be used as name for the key_vault element. Allowed characters are: a-z, A-Z, 0-9, and -.
  The Value of the Map is an object with the following attributes:
  - email: (optional) Email address used for the Certificate. If not set, the default_contact_email will be used.
  - main_domain: (required) The main domain of the certificate. Example: "*.example.com" for a wildcard certificate.
  - alternative_domains: (optional) A list of alternative names for the certificate.
  - enable_staging_mode: (optional) If set to true, the staging mode of Let's Encrypt will be used. This is useful for testing purposes, since the production env. has api rate limits. Default: false
  - cert_key: (optional) The certificate key length and its algorithm. Default: 4096 (RSA). Possible values are "2048" (RSA), "4096" (RSA), "'ec-256" and "ec-384".
  - authorized_role_assigners: (optional) A map of object-ids of a Users, Groups or SPs, that get Role-Assignment-Permission on the certificate. The Key is an unique identifier, the value the id.
  EOF
  type = map(object({
    email                     = optional(string)
    main_domain               = string
    alternative_domains       = optional(list(string), [])
    enable_staging_mode       = optional(bool, false)
    cert_key                  = optional(string, "4096")
    authorized_role_assigners = optional(map(string))
  }))

  validation {
    # Check that each key of the map only uses the following characters: a-z, A-Z, 0-9, and -
    condition     = alltrue([for k, v in var.certificates : can(regex("^[a-zA-Z0-9-]+$", k))])
    error_message = "The key of the certificates map must only contain the following characters: a-z, A-Z, 0-9, and -"
  }
  validation {
    # Check that the main_domain of each map element is a valid domain name
    condition     = alltrue([for k, v in var.certificates : can(regex("^[a-z0-9-.*]+$", v.main_domain))])
    error_message = "main_domain must be a valid domain name (e.g. example.com)"
  }

  validation {
    # Check that the alternative_domains of each map element are valid domain names
    condition     = alltrue([for k, v in var.certificates : length(v.alternative_domains) == 0 || alltrue([for domain in v.alternative_domains : can(regex("^[a-z0-9-.*]+$", domain))])])
    error_message = "alternative_domains must be a list of valid domain names (e.g. example.com)"
  }
  validation {
    # Check that the cert_key of each map element is one of the following values: 2048, 4096, ec-256, ec-384
    condition     = alltrue([for k, v in var.certificates : can(regex("^(2048|4096|ec-256|ec-384)$", v.cert_key))])
    error_message = "cert_key must be one of the following values: 2048, 4096, ec-256, ec-384"
  }
}

variable "key_vault" {
  description = "Name and the id of the KeyVault in which the certificates will be created."
  type = object({
    name = string
    id   = string
  })
}

variable "certificate_renewal_deadline_days" {
  description = "The number of days before the certificate expiration date to renew the certificate. Possible values are between 5 and 40. Default is 30 days."
  type        = number
  default     = 30

  validation {
    # Check that the number is between 5 and 40
    condition     = var.certificate_renewal_deadline_days >= 5 && var.certificate_renewal_deadline_days <= 40
    error_message = "The certificate_renewal_deadline_days must be between 5 and 40."
  }
}

variable "run_schedule" {
  description = <<EOF
  An object containing settings about the schedule of the CertificateManager. The following attributes are supported:
  - runs_every_other_hour: (optional) Number of hours between each run of the CertificateManager. Possible values are 6, 12 and 24. Default is 24 hours.
  - timezone: (optional) The timezone in which the CertificateManager will run. Default is "W. Europe Standard Time". More information about the supported timezones can be found here: https://docs.microsoft.com/en-us/rest/api/maps/timezone/gettimezoneenumwindows
  - start_time: (optional) The time at which the CertificateManager will start running in utc. Default is 23:00. The time must be in the format "HH:MM"
  EOF
  type = object({
    runs_every_other_hour = optional(number, 24)
    timezone              = optional(string, "Europe/Zurich")
    start_time            = optional(string, "23:00")
  })
  default = {}

  validation {
    # Check that the time is in format "HH:MM"
    condition     = can(regex("^([0-1][0-9]|2[0-3]):[0-5][0-9]$", var.run_schedule.start_time))
    error_message = "The start_time must be in the format HH:MM"
  }
  validation {
    # Check that the runs_every_other_hour is 6, 12 or 24
    condition     = can(regex("^(6|12|24)$", var.run_schedule.runs_every_other_hour))
    error_message = "The runs_every_other_hour must be 6, 12 or 24"
  }
}

variable "enable_verbose_logging" {
  description = "Enable verbose logging for the CertificateManager."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Map of additional tags."
  type        = map(string)
  default     = {}
}
