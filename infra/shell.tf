# This file configures the execution of the API testing script

# Create a resource to run the test script after deployment
resource "null_resource" "run_test_script" {
  depends_on = [
    azurerm_api_management_api_operation_policy.hello_policy,
    azurerm_api_management_api_policy.secure_api_policy
  ]

  # Pass parameters to the external test script
  provisioner "local-exec" {
    command = <<-EOT
      ${path.module}/test_api.sh \
        --gateway-url=${azurerm_api_management.apim.gateway_url} \
        --issuer=${azurerm_api_management_named_value.jwt_issuer.value} \
        --audience=${azurerm_api_management_named_value.jwt_audience.value} \
        --scope=${azurerm_api_management_named_value.jwt_required_scope.value} \
        --signing-key-id=${local.jwt_signing_key_id} \
        --encryption-key-id=${local.jwt_encryption_key_id} \
        --keys-dir=${local.keys_directory}
    EOT
  }
}

# Output information about the test script
output "test_script_path" {
  description = "Path to the API testing script"
  value       = "${path.module}/test_api.sh"
}

output "test_script_command" {
  description = "Command to manually run the API testing script"
  value       = "${path.module}/test_api.sh --gateway-url=${azurerm_api_management.apim.gateway_url} --issuer=${azurerm_api_management_named_value.jwt_issuer.value} --audience=${azurerm_api_management_named_value.jwt_audience.value} --scope=${azurerm_api_management_named_value.jwt_required_scope.value} --signing-key-id=${local.jwt_signing_key_id} --encryption-key-id=${local.jwt_encryption_key_id} --keys-dir=${local.keys_directory}"
  sensitive = true
}