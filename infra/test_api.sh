#!/bin/bash
set -e

# Color codes for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Default values
GATEWAY_URL=""
JWT_ISSUER=""
JWT_AUDIENCE=""
JWT_REQUIRED_SCOPE=""
JWT_SIGNING_KEY_ID=""
JWT_ENCRYPTION_KEY_ID=""
KEYS_DIR="./keys"

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --gateway-url=*) GATEWAY_URL="${1#*=}" ;;
        --issuer=*) JWT_ISSUER="${1#*=}" ;;
        --audience=*) JWT_AUDIENCE="${1#*=}" ;;
        --scope=*) JWT_REQUIRED_SCOPE="${1#*=}" ;;
        --signing-key-id=*) JWT_SIGNING_KEY_ID="${1#*=}" ;;
        --encryption-key-id=*) JWT_ENCRYPTION_KEY_ID="${1#*=}" ;;
        --keys-dir=*) KEYS_DIR="${1#*=}" ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

echo -e "${BLUE}=== API Management JWT Validation Testing Script ===${NC}\n"

# Validate required parameters
if [ -z "$GATEWAY_URL" ]; then
    echo -e "${YELLOW}Gateway URL not provided, attempting to fetch from Terraform output...${NC}"
    GATEWAY_URL=$(terraform output -raw gateway_url 2>/dev/null || echo "")
    
    if [ -z "$GATEWAY_URL" ]; then
        echo -e "${RED}Error: Could not determine API Management Gateway URL${NC}"
        echo "Please provide it using --gateway-url parameter"
        exit 1
    fi
fi

# Show configuration
echo -e "${GREEN}Configuration:${NC}"
echo "Gateway URL: $GATEWAY_URL"
echo "JWT Issuer: $JWT_ISSUER"
echo "JWT Audience: $JWT_AUDIENCE"
echo "JWT Required Scope: $JWT_REQUIRED_SCOPE"
echo "JWT Signing Key ID: $JWT_SIGNING_KEY_ID"
echo "Keys Directory: $KEYS_DIR"
echo -e "\n"

# ===== STEP 1: Test the Hello World API =====
echo -e "${YELLOW}Testing Hello World API...${NC}"
echo -e "GET $GATEWAY_URL/hello\n"

HELLO_RESPONSE=$(curl -s -X GET "$GATEWAY_URL/hello")

echo -e "${GREEN}Response:${NC}"
echo "$HELLO_RESPONSE" | jq . || echo "$HELLO_RESPONSE"
echo -e "\n"

# ===== STEP 2: Generate a JWT Token =====
echo -e "${YELLOW}Generating JWT Token...${NC}"

# Check if we have the required tools
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required but not installed. Please install jq to continue.${NC}"
    exit 1
fi

if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl is required but not installed.${NC}"
    exit 1
fi

# Create header and payload files
JWT_HEADER=$(cat <<EOF
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "$JWT_SIGNING_KEY_ID"
}
EOF
)

# Current time and expiration (1 hour from now)
CURRENT_TIME=$(date +%s)
EXPIRATION_TIME=$((CURRENT_TIME + 3600))

JWT_PAYLOAD=$(cat <<EOF
{
  "iss": "$JWT_ISSUER",
  "sub": "test-user",
  "aud": "$JWT_AUDIENCE",
  "scope": "$JWT_REQUIRED_SCOPE",
  "name": "Test User",
  "roles": ["api-user"],
  "iat": $CURRENT_TIME,
  "exp": $EXPIRATION_TIME
}
EOF
)

echo -e "${BLUE}JWT Header:${NC}"
echo "$JWT_HEADER" | jq .
echo -e "\n${BLUE}JWT Payload:${NC}"
echo "$JWT_PAYLOAD" | jq .

# Base64 encode the header and payload
HEADER_BASE64=$(echo -n "$JWT_HEADER" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')
PAYLOAD_BASE64=$(echo -n "$JWT_PAYLOAD" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')

# Combine header and payload to form the data to sign
UNSIGNED_TOKEN="$HEADER_BASE64.$PAYLOAD_BASE64"

# Sign the token
PRIVATE_KEY_PATH="$KEYS_DIR/jwt_signing_private.pem"

if [ ! -f "$PRIVATE_KEY_PATH" ]; then
    echo -e "${RED}Error: Private signing key not found at $PRIVATE_KEY_PATH${NC}"
    echo -e "${YELLOW}Checking for keys in current directory...${NC}"
    PRIVATE_KEY_PATH="./jwt_signing_private.pem"
    if [ ! -f "$PRIVATE_KEY_PATH" ]; then
        echo -e "${RED}Error: Private signing key not found in current directory either.${NC}"
        echo -e "${YELLOW}Please specify the correct path to the jwt_signing_private.pem file.${NC}"
        exit 1
    fi
fi

echo "Using signing key: $PRIVATE_KEY_PATH"
SIGNATURE=$(echo -n "$UNSIGNED_TOKEN" | openssl dgst -sha256 -sign "$PRIVATE_KEY_PATH" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')

# Create the complete JWT token
JWT_TOKEN="$UNSIGNED_TOKEN.$SIGNATURE"

echo -e "${GREEN}Generated JWT Token:${NC}"
echo "$JWT_TOKEN"
echo -e "\n"

# Save token to a temp file for easy reuse
echo "$JWT_TOKEN" > /tmp/jwt_token.txt
echo -e "Token saved to /tmp/jwt_token.txt for reference\n"

# ===== STEP 3: Test the Secure API with JWT Token =====
echo -e "${YELLOW}Testing Secure API with JWT Token...${NC}"
echo -e "GET $GATEWAY_URL/secure/data\n"

SECURE_RESPONSE=$(curl -s -X GET "$GATEWAY_URL/secure/data" \
  -H "Authorization: Bearer $JWT_TOKEN")

echo -e "${GREEN}Response:${NC}"
echo "$SECURE_RESPONSE" | jq . || echo "$SECURE_RESPONSE"
echo -e "\n"

# ===== STEP 4: Test with invalid token (wrong scope) =====
echo -e "${YELLOW}Testing with invalid JWT Token (tampered payload)...${NC}"

# Create a tampered payload (changing the scope)
TAMPERED_PAYLOAD=$(echo "$JWT_PAYLOAD" | jq '.scope = "wrong-scope"')
TAMPERED_PAYLOAD_BASE64=$(echo -n "$TAMPERED_PAYLOAD" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')

# Combine with original header
TAMPERED_UNSIGNED_TOKEN="$HEADER_BASE64.$TAMPERED_PAYLOAD_BASE64"

# Sign with the same key (simulating a properly signed but tampered token)
TAMPERED_SIGNATURE=$(echo -n "$TAMPERED_UNSIGNED_TOKEN" | openssl dgst -sha256 -sign "$PRIVATE_KEY_PATH" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')

# Create the tampered JWT token
TAMPERED_JWT_TOKEN="$TAMPERED_UNSIGNED_TOKEN.$TAMPERED_SIGNATURE"

echo -e "GET $GATEWAY_URL/secure/data with tampered token\n"

INVALID_RESPONSE=$(curl -s -X GET "$GATEWAY_URL/secure/data" \
  -H "Authorization: Bearer $TAMPERED_JWT_TOKEN")

echo -e "${RED}Expected Error Response:${NC}"
echo "$INVALID_RESPONSE" | jq . || echo "$INVALID_RESPONSE"

echo -e "\n${BLUE}=== Testing Complete ===${NC}"
