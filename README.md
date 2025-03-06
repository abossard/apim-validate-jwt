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
- 🧪 Automated testing script for validating API endpoints and JWT token handling

## 📋 Repository Structure

```
├── README.md                   # This documentation file
└── infra/                      # Infrastructure code directory
    ├── hello-world-policy.xml  # Simple policy for basic API operations
    ├── main.tf                 # Terraform configuration file
    ├── shell.tf                # Test script generation for API endpoints
    ├── test_api.sh             # Generated test script (after terraform apply)
    ├── secure-data-policy.xml  # JWT validation policy for secure API operations
    ├── validate-jwt-policy.xml # Base JWT validation policy
    └── keys/                   # Directory where generated keys are stored locally
        ├── jwt_signing_private.pem        # Private key for JWT signing
        ├── jwt_signing_public.pem         # Public key for JWT signature validation
        ├── jwt_signing_public_base64.txt  # Base64 encoded public signing key
        ├── jwt_encryption_private.pem     # Private key for JWT decryption
        ├── jwt_encryption_public.pem      # Public key for JWT encryption
        └── jwt_encryption_private_base64.txt # Base64 encoded private encryption key
```

## 🔑 Key Generation and Storage

### Generated Keys

This solution generates two RSA key pairs (2048-bit) during deployment:

1. **JWT Signing Key Pair**:
   - **Private Key**: Used by token issuers to sign JWTs
   - **Public Key**: Used by API Management to verify JWT signatures
   - **Key ID**: Configured as `jwt-signing-key-1`

2. **JWT Encryption Key Pair**:
   - **Public Key**: Used by token issuers to encrypt JWTs (creating JWE tokens)
   - **Private Key**: Used by API Management to decrypt incoming JWE tokens
   - **Key ID**: Configured as `jwt-encryption-key-1`

### Key Storage Locations

Keys are stored in multiple locations for different purposes:

1. **Local Storage**: 
   - All keys are generated and stored in the `infra/keys/` directory
   - These local keys can be used by developers to generate valid test tokens
   - Base64-encoded versions (without headers/footers) are also created for easy use in APIM policies

2. **Azure Key Vault**:
   - All keys are securely stored in Azure Key Vault
   - Key Vault name format: `{resource_prefix}-kv`
   - Secret names:
     - `jwt-signing-private-key`
     - `jwt-signing-public-key`
     - `jwt-encryption-private-key`
     - `jwt-encryption-public-key`

3. **API Management Named Values**:
   - Keys are referenced in API Management as named values
   - These named values are used in the JWT validation policies
   - Named value names:
     - `validate-jwt-signing-key`
     - `validate-jwt-signing-key-base64`
     - `validate-jwt-encryption-key`
     - `validate-jwt-encryption-key-base64`

### Key Usage in API Management

- The public signing key is used in the `<issuer-signing-keys>` section of the validate-jwt policy
- The private encryption key is used in the `<decryption-keys>` section of the validate-jwt policy
- Keys are referenced using their Key IDs, which match the values stored in named values

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
- For testing: jq and openssl (used by the generated test script)

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
5. After deployment, Terraform will:
   - Output commands for testing the APIs
   - Generate and run a test script that automatically tests both APIs
   - Create the required keys in the `keys` directory

## 🧪 Testing

### Automated Testing

The deployment automatically generates and runs a test script (`test_api.sh`) that:

1. Tests the Hello World API endpoint
2. Generates a valid JWT token using the locally stored signing key
3. Tests the Secure API with the generated token
4. Tests the Secure API with a tampered token to verify validation works

You can run this script again at any time:

```bash
./infra/test_api.sh
```

### Manual Testing

To test the secure API manually, you'll need to:

1. Generate a valid JWT token with the required claims
2. Use the provided curl command from the Terraform outputs
3. Include the subscription key in the request

### Creating Test Tokens

You can use the locally generated keys in the `infra/keys/` directory to create test tokens:
- Use `jwt_signing_private.pem` to sign your tokens
- Use `jwt_encryption_public.pem` to encrypt your tokens (if testing JWE)
- Ensure your tokens include the required claims:
  - issuer: Value from `validate-jwt-issuer` named value
  - audience: Value from `validate-jwt-audience` named value
  - scope: Value from `validate-jwt-required-scope` named value

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