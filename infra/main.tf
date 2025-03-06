terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Generate a random string to use as default salt if none is provided
resource "random_string" "salt" {
  length  = 32
  special = true
  upper   = true
  lower   = true
  numeric = true  # Updated from 'number' to 'numeric' as per recommendation
}

# Generate a random string for JWT key IDs
resource "random_string" "signing_key_id" {
  length  = 16
  special = false
  upper   = true
  lower   = true
  numeric = true
}

resource "random_string" "encryption_key_id" {
  length  = 16
  special = false
  upper   = true
  lower   = true
  numeric = true
}

# Generate RSA key pair for JWT signing
resource "tls_private_key" "jwt_signing_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Generate RSA key pair for JWT encryption 
resource "tls_private_key" "jwt_encryption_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

variable "salt" {
  description = "Salt value for various operations"
  type        = string
  sensitive   = true
  default     = ""  # Empty default to allow conditional use of random string
}

variable "location" {
  description = "Azure region where resources will be deployed"
  type        = string
  default     = "swedencentral"
}

variable "resource_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "apim-jwt"
}

# Use provided salt or random salt
locals {
  salt_value = var.salt != "" ? var.salt : random_string.salt.result
}

# Create a resource group
resource "azurerm_resource_group" "rg" {
  name     = "${var.resource_prefix}-rg"
  location = var.location
  
  tags = {
    Environment = "Dev"
    Project     = "APIM JWT Validation"
  }
}

# Create API Management
resource "azurerm_api_management" "apim" {
  name                = "${var.resource_prefix}-apim"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  publisher_name      = "Example Organization"
  publisher_email     = "admin@example.org"
  
  sku_name = "Developer_1"  # Less expensive tier for development

  identity {
    type = "SystemAssigned"
  }
}

# Create Key Vault
resource "azurerm_key_vault" "kv" {
  name                        = "${var.resource_prefix}-kv"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  
  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id
    
    key_permissions = [
      "Get", "List", "Create", "Delete", "Update",
    ]
    
    secret_permissions = [
      "Get", "List", "Set", "Delete",
    ]
  }

  # Give API Management access to Key Vault
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = azurerm_api_management.apim.identity[0].principal_id
    
    secret_permissions = [
      "Get", "List",
    ]
  }
}

# Store salt in Key Vault
resource "azurerm_key_vault_secret" "salt" {
  name         = "jwt-salt"
  value        = local.salt_value
  key_vault_id = azurerm_key_vault.kv.id
}

# Store keys in Key Vault
resource "azurerm_key_vault_secret" "jwt_signing_private_key" {
  name         = "jwt-signing-private-key"
  value        = tls_private_key.jwt_signing_key.private_key_pem
  key_vault_id = azurerm_key_vault.kv.id
}

resource "azurerm_key_vault_secret" "jwt_signing_public_key" {
  name         = "jwt-signing-public-key"
  value        = tls_private_key.jwt_signing_key.public_key_pem
  key_vault_id = azurerm_key_vault.kv.id
}

resource "azurerm_key_vault_secret" "jwt_encryption_private_key" {
  name         = "jwt-encryption-private-key"
  value        = tls_private_key.jwt_encryption_key.private_key_pem
  key_vault_id = azurerm_key_vault.kv.id
}

resource "azurerm_key_vault_secret" "jwt_encryption_public_key" {
  name         = "jwt-encryption-public-key"
  value        = tls_private_key.jwt_encryption_key.public_key_pem
  key_vault_id = azurerm_key_vault.kv.id
}

# Fetch current Azure client config
data "azurerm_client_config" "current" {}

# Create a sample API product
resource "azurerm_api_management_product" "hello_product" {
  product_id            = "hello-world-product"
  api_management_name   = azurerm_api_management.apim.name
  resource_group_name   = azurerm_resource_group.rg.name
  display_name          = "Hello World API Product"
  description           = "A product containing a simple Hello World API"
  subscription_required = true
  published             = true
}

# Create a sample API
resource "azurerm_api_management_api" "hello_api" {
  name                = "hello-world-api"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  revision            = "1"
  display_name        = "Hello World API"
  path                = "hello"
  protocols           = ["https"]
  service_url         = ""  # No backend service needed since we're using a mock response
}

# Associate the API with the product
resource "azurerm_api_management_product_api" "hello_product_api" {
  product_id          = azurerm_api_management_product.hello_product.product_id
  api_name            = azurerm_api_management_api.hello_api.name
  api_management_name = azurerm_api_management.apim.name
  resource_group_name = azurerm_resource_group.rg.name
}

# Create an operation in the API
resource "azurerm_api_management_api_operation" "hello_operation" {
  operation_id        = "get-hello-world"
  api_name            = azurerm_api_management_api.hello_api.name
  api_management_name = azurerm_api_management.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  display_name        = "Get Hello World"
  method              = "GET"
  url_template        = "/"
  description         = "Returns a Hello World JSON message"
}

# Apply the Hello World policy to the API operation
resource "azurerm_api_management_api_operation_policy" "hello_policy" {
  api_name            = azurerm_api_management_api.hello_api.name
  api_management_name = azurerm_api_management.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  operation_id        = azurerm_api_management_api_operation.hello_operation.operation_id
  
  xml_content = file("${path.module}/hello-world-policy.xml")
}

# Create named values in API Management for JWT validation
resource "azurerm_api_management_named_value" "jwt_openid_config_url" {
  name                = "validate-jwt-openid-config-url"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-openid-config-url"
  value               = "https://example.org/.well-known/openid-configuration"
  count               = 0
}

resource "azurerm_api_management_named_value" "jwt_audience" {
  name                = "validate-jwt-audience"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-audience"
  value               = "api://secure-api"
}

resource "azurerm_api_management_named_value" "jwt_issuer" {
  name                = "validate-jwt-issuer"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-issuer"
  value               = "https://example.org/issuer"
}

resource "azurerm_api_management_named_value" "jwt_required_scope" {
  name                = "validate-jwt-required-scope"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-required-scope"
  value               = "api.access"
}

resource "azurerm_api_management_named_value" "jwt_enc_key_id" {
  name                = "validate-jwt-enc-key-id"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-enc-key-id"
  value               = random_string.encryption_key_id.result
}

resource "azurerm_api_management_named_value" "jwt_signing_key_id" {
  name                = "validate-jwt-signing-key-id"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-signing-key-id"
  value               = random_string.signing_key_id.result
}

resource "azurerm_api_management_named_value" "jwt_encryption_key" {
  name                = "validate-jwt-encryption-key"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-encryption-key"
  secret              = true
  value_from_key_vault {
    secret_id = azurerm_key_vault_secret.jwt_encryption_private_key.id
  }
}

resource "azurerm_api_management_named_value" "jwt_signing_key" {
  name                = "validate-jwt-signing-key"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-signing-key"
  secret              = true
  value_from_key_vault {
    secret_id = azurerm_key_vault_secret.jwt_signing_public_key.id
  }
}

# Create named values with base64-encoded keys for JWT validation
resource "azurerm_api_management_named_value" "jwt_signing_key_base64" {
  name                = "validate-jwt-signing-key-base64"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-signing-key-base64"
  secret              = true
  value               = base64encode(
                          replace(
                            replace(
                              tls_private_key.jwt_signing_key.public_key_pem,
                              "-----BEGIN PUBLIC KEY-----\n", ""
                            ),
                            "\n-----END PUBLIC KEY-----\n", ""
                          )
                        )
}

resource "azurerm_api_management_named_value" "jwt_encryption_key_base64" {
  name                = "validate-jwt-encryption-key-base64"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  display_name        = "validate-jwt-encryption-key-base64"
  secret              = true
  value               = base64encode(
                          replace(
                            replace(
                              tls_private_key.jwt_encryption_key.private_key_pem,
                              "-----BEGIN RSA PRIVATE KEY-----\n", ""
                            ),
                            "\n-----END RSA PRIVATE KEY-----\n", ""
                          )
                        )
}

# Create a secure API with JWT validation
resource "azurerm_api_management_api" "secure_api" {
  name                = "secure-api"
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  revision            = "1"
  display_name        = "Secure API with JWT Validation"
  path                = "secure"
  protocols           = ["https"]
  subscription_required = true
}

# Create a GET operation in the secure API
resource "azurerm_api_management_api_operation" "secure_get_operation" {
  operation_id        = "secure-get"
  api_name            = azurerm_api_management_api.secure_api.name
  api_management_name = azurerm_api_management.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  display_name        = "Secure Get Operation"
  method              = "GET"
  url_template        = "/data"
  description         = "A secure endpoint that requires JWT validation"
}

# Apply the JWT validation policy to the API
resource "azurerm_api_management_api_policy" "secure_api_policy" {
  api_name            = azurerm_api_management_api.secure_api.name
  api_management_name = azurerm_api_management.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  
  xml_content = file("${path.module}/validate-jwt-policy.xml")
}

# Apply specific policy to the secure data operation
resource "azurerm_api_management_api_operation_policy" "secure_data_policy" {
  api_name            = azurerm_api_management_api.secure_api.name
  api_management_name = azurerm_api_management.apim.name
  resource_group_name = azurerm_resource_group.rg.name
  operation_id        = azurerm_api_management_api_operation.secure_get_operation.operation_id
  
  xml_content = file("${path.module}/secure-data-policy.xml")
}

# Associate the secure API with the product
resource "azurerm_api_management_product_api" "secure_product_api" {
  product_id          = azurerm_api_management_product.hello_product.product_id
  api_name            = azurerm_api_management_api.secure_api.name
  api_management_name = azurerm_api_management.apim.name
  resource_group_name = azurerm_resource_group.rg.name
}

# Create a test subscription for the product
resource "azurerm_api_management_subscription" "test_subscription" {
  resource_group_name = azurerm_resource_group.rg.name
  api_management_name = azurerm_api_management.apim.name
  product_id          = azurerm_api_management_product.hello_product.id
  display_name        = "Test Subscription"
  state               = "active"
}

# Outputs for testing
output "hello_world_curl_command" {
  description = "Curl command to test the Hello World API endpoint"
  value       = "curl -X GET \"https://${azurerm_api_management.apim.gateway_url}/hello\" -H \"Ocp-Apim-Subscription-Key: $(terraform output -raw subscription_key)\""
}

output "secure_api_curl_command" {
  description = "Curl command to test the Secure API endpoint (requires valid JWT token)"
  value       = "curl -X GET \"https://${azurerm_api_management.apim.gateway_url}/secure/data\" -H \"Authorization: Bearer YOUR_JWT_TOKEN\" -H \"Ocp-Apim-Subscription-Key: $(terraform output -raw subscription_key)\""
}

output "subscription_key" {
  description = "Subscription key for the API product"
  sensitive   = true
  value       = azurerm_api_management_subscription.test_subscription.primary_key
}

output "public_signing_key" {
  description = "Public signing key for JWT token validation (for reference)"
  value       = tls_private_key.jwt_signing_key.public_key_pem
  sensitive   = true
}

output "public_encryption_key" {
  description = "Public encryption key for JWT token encryption (for reference)"
  value       = tls_private_key.jwt_encryption_key.public_key_pem
  sensitive   = true
}

output "jwt_requirements" {
  sensitive = true
  description = "JWT token requirements for the secure API"
  value = {
    issuer     = azurerm_api_management_named_value.jwt_issuer.value
    audience   = azurerm_api_management_named_value.jwt_audience.value
    scope      = azurerm_api_management_named_value.jwt_required_scope.value
    signing_kid = random_string.signing_key_id.result
    enc_kid     = random_string.encryption_key_id.result
  }
}