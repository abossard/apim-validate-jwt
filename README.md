# Azure API Management JWT Validation Demo 🔐

## Overview 📚

This repository demonstrates how to implement secure JWT (JSON Web Token) validation in Azure API Management. It provides a complete infrastructure as code setup using Terraform to create and configure an Azure API Management instance with policies for JWT validation, including both signing verification and encryption handling.

## 🌟 Features

- ✅ Complete Terraform infrastructure setup
- 🔑 RSA key generation for JWT signing and encryption
- 🔒 Azure Key Vault integration for secure key storage
- 🛡️ JWT validation policy implementation with specific elements:
  - `issuer-signing-keys` - For validating the token signature
  - `audiences` - For validating the intended token recipient
  - `issuers` - For validating the token issuer
  - `required-claims` - For ensuring specific claims are present
  - `decryption-keys` - For handling encrypted JWE tokens

## 📋 Repository Structure

```
├── README.md                   # This documentation file
└── infra/                      # Infrastructure code directory
    ├── hello-world-policy.xml  # Simple policy for basic API operations
    ├── main.tf                 # Terraform configuration file
    ├── secure-data-policy.xml  # JWT validation policy for secure API operations
    └── validate-jwt-policy.xml # Base JWT validation policy
```

## 🔧 Implementation Details

### JWT Validation Components

The implementation focuses on configuring the `validate-jwt` policy in API Management with the following elements:

1. **`issuer-signing-keys`** - Public keys used to verify the signature of incoming JWTs
2. **`audiences`** - Valid audience values that the JWT must contain
3. **`issuers`** - Valid issuer values that the JWT must contain
4. **`required-claims`** - Claims that must be present in the JWT, such as scopes
5. **`decryption-keys`** - Private keys for decrypting JWE (encrypted JWT) tokens

### API Structure

The demo provides two APIs:

1. **Hello World API** 👋 - A simple API that returns a greeting message without JWT validation
2. **Secure API** 🔐 - An API protected with JWT validation

## 🚀 Getting Started

### Prerequisites

- Azure subscription
- Terraform installed
- Azure CLI installed and authenticated

### Deployment Steps

1. Clone this repository
2. Navigate to the `infra` directory
3. Initialize Terraform:
   ```
   terraform init
   ```
4. Deploy the infrastructure:
   ```
   terraform apply
   ```
5. After deployment, Terraform will output:
   - A curl command for testing the Hello API
   - A curl command for testing the Secure API (requires a valid JWT)
   - The subscription key for API access
   - JWT requirements for token generation

## 🧪 Testing

To test the secure API, you'll need to:

1. Generate a valid JWT token with the required claims
2. Use the provided curl command, replacing `YOUR_JWT_TOKEN` with your actual token
3. Include the subscription key in the request

## 📝 Policy Details

The JWT validation policies enforce security through:

- Validating the token signature using RSA public keys
- Checking that the audience claim matches the API's identifier
- Verifying the token issuer is trusted
- Ensuring required scopes are present in the token
- Supporting decryption of encrypted tokens (JWE)

## ⚙️ Configuration

The main configuration parameters can be adjusted in the `main.tf` file:

- `resource_prefix` - The prefix for all Azure resources
- `location` - The Azure region where resources are deployed
- JWT validation parameters (issuer, audience, scope, etc.)

## 🔍 Security Considerations

- All sensitive keys are stored in Azure Key Vault
- API Management accesses keys securely through Key Vault references
- Public/private key pairs are generated with RSA 2048-bit encryption
- JWT validation fails closed (denies access on any validation failure)

## 📦 Extensions

This implementation can be extended by:

- Adding Azure Active Directory B2C integration
- Implementing custom claims validation
- Adding rate limiting and other API protection measures
- Implementing token caching for performance optimization

## 📖 Additional Resources

- [Azure API Management Documentation](https://docs.microsoft.com/en-us/azure/api-management/)
- [JWT.io - JWT Debugger and Library](https://jwt.io/)
- [Terraform Azure Provider Documentation](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)