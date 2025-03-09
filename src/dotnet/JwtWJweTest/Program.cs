using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;


static string Base64UrlEncode(byte[] input)
{
    string base64 = Convert.ToBase64String(input);
    return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

// Overload for string input - renamed to avoid duplicate function definition
static string Base64UrlEncodeStr(string input) => Base64UrlEncode(Encoding.UTF8.GetBytes(input));

// Helper method for Base64Url encoding


// Simple argument parser to handle --key=value arguments
static Dictionary<string, string> ParseArgs(string[] args)
{
    var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (var arg in args)
    {
        if (arg.StartsWith("--"))
        {
            var parts = arg.Split('=', 2);
            if (parts.Length == 2)
            {
                parameters[parts[0].TrimStart('-').ToLower()] = parts[1];
            }
        }
    }
    return parameters;
}

// Main async method
async Task MainAsync(string[] args)
{
    // Parse command-line arguments
    var parameters = ParseArgs(args);
    
    if (!parameters.ContainsKey("gateway-url") || string.IsNullOrWhiteSpace(parameters["gateway-url"]))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Error: Gateway URL must be provided using --gateway-url parameter");
        Console.ResetColor();
        return;
    }
    
    // Retrieve parameters
    string gatewayUrl = parameters["gateway-url"].TrimEnd('/');
    string issuer = parameters.ContainsKey("issuer") ? parameters["issuer"] : "";
    string audience = parameters.ContainsKey("audience") ? parameters["audience"] : "";
    string scope = parameters.ContainsKey("scope") ? parameters["scope"] : "";
    string signingKeyId = parameters.ContainsKey("signing-key-id") ? parameters["signing-key-id"] : "";
    string encryptionKeyId = parameters.ContainsKey("encryption-key-id") ? parameters["encryption-key-id"] : "";
    string keysDir = parameters.ContainsKey("keys-dir") ? parameters["keys-dir"] : "./keys";
    
    // Display configuration
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("Configuration:");
    Console.WriteLine($"Gateway URL: {gatewayUrl}");
    Console.WriteLine($"JWT Issuer: {issuer}");
    Console.WriteLine($"JWT Audience: {audience}");
    Console.WriteLine($"JWT Required Scope: {scope}");
    Console.WriteLine($"JWT Signing Key ID: {signingKeyId}");
    Console.WriteLine($"JWT Encryption Key ID: {encryptionKeyId}");
    Console.WriteLine($"Keys Directory: {keysDir}");
    Console.ResetColor();
    Console.WriteLine();
    
    using var httpClient = new HttpClient();
    
    // ===== STEP 1: Test the Hello World API =====
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("Testing Hello World API...");
    Console.ResetColor();
    string helloUrl = $"{gatewayUrl}/hello";
    Console.WriteLine($"GET {helloUrl}\n");
    try
    {
        string helloResponse = await httpClient.GetStringAsync(helloUrl);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("Response:");
        Console.ResetColor();
        Console.WriteLine(helloResponse);
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error calling Hello API: {ex.Message}");
        Console.ResetColor();
    }
    Console.WriteLine();
    
    // ===== STEP 2: Generate a JWT Token =====
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("Generating JWT Token...");
    Console.ResetColor();
    
    var header = new JwtHeader
    {
        alg = "HS256",
        typ = "JWT",
        kid = signingKeyId
    };
    string headerJson = JsonSerializer.Serialize(header, MyJsonContext.Default.JwtHeader);
    
    long currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    long expirationTime = currentTime + 3600;
    
    var payload = new JwtPayload
    {
        iss = issuer,
        sub = "test-user",
        aud = audience,
        scope = scope,
        name = "Test User",
        roles = new string[] { "api-user" },
        iat = currentTime,
        exp = expirationTime
    };
    string payloadJson = JsonSerializer.Serialize(payload, MyJsonContext.Default.JwtPayload);
    
    var indentedOptions = new JsonSerializerOptions { WriteIndented = true };
    Console.ForegroundColor = ConsoleColor.Blue;
    Console.WriteLine("JWT Header:");
    Console.ResetColor();
    Console.WriteLine(JsonSerializer.Serialize(header, MyJsonContext.Default.JwtHeader));
    Console.WriteLine();
    
    Console.ForegroundColor = ConsoleColor.Blue;
    Console.WriteLine("JWT Payload:");
    Console.ResetColor();
    Console.WriteLine(JsonSerializer.Serialize(payload, MyJsonContext.Default.JwtPayload));
    Console.WriteLine();
    
    string headerEncoded = Base64UrlEncodeStr(headerJson);
    string payloadEncoded = Base64UrlEncodeStr(payloadJson);
    string unsignedToken = $"{headerEncoded}.{payloadEncoded}";
    
    // Load symmetric signing key
    string keyPath = Path.Combine(keysDir, "jwt_signing_key.txt");
    if (!File.Exists(keyPath))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error: Symmetric signing key not found at {keyPath}");
        Console.ResetColor();
        return;
    }
    string symmetricKey = File.ReadAllText(keyPath).Trim();
    Console.WriteLine($"Using symmetric signing key from: {keyPath}");
    
    string signatureEncoded;
    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(symmetricKey)))
    {
        byte[] signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(unsignedToken));
        signatureEncoded = Base64UrlEncode(signatureBytes);
    }
    
    string jwtToken = $"{unsignedToken}.{signatureEncoded}";
    
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("\nGenerated JWT Token:");
    Console.ResetColor();
    Console.WriteLine(jwtToken);
    Console.WriteLine();
    
    // Save token to a temp file for easy reuse
    string tempTokenPath = Path.Combine(Path.GetTempPath(), "jwt_token.txt");
    File.WriteAllText(tempTokenPath, jwtToken);
    Console.WriteLine($"Token saved to {tempTokenPath} for reference\n");
    
    // ===== STEP 3: Test the Secure API with JWT Token =====
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("Testing Secure API with JWT Token...");
    Console.ResetColor();
    string secureUrl = $"{gatewayUrl}/secure/data";
    Console.WriteLine($"GET {secureUrl}\n");
    try
    {
        using var requestMessage = new HttpRequestMessage(HttpMethod.Get, secureUrl);
        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwtToken);
        var secureResponse = await httpClient.SendAsync(requestMessage);
        string secureResponseContent = await secureResponse.Content.ReadAsStringAsync();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("Response:");
        Console.ResetColor();
        Console.WriteLine(secureResponseContent);
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error calling Secure API: {ex.Message}");
        Console.ResetColor();
    }
    Console.WriteLine();
    
    // ===== STEP 4: Test with invalid token (tampered payload) =====
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("Testing with invalid JWT Token (tampered payload)...");
    Console.ResetColor();
    
    // Create tampered payload with wrong scope
    var tamperedPayload = new JwtPayload
    {
        iss = issuer,
        sub = "test-user",
        aud = audience,
        scope = "wrong-scope",
        name = "Test User",
        roles = new string[] { "api-user" },
        iat = currentTime,
        exp = expirationTime
    };
    string tamperedPayloadJson = JsonSerializer.Serialize(tamperedPayload, MyJsonContext.Default.JwtPayload);
    string tamperedPayloadEncoded = Base64UrlEncodeStr(tamperedPayloadJson);
    string tamperedUnsignedToken = $"{headerEncoded}.{tamperedPayloadEncoded}";
    
    string tamperedSignatureEncoded;
    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(symmetricKey)))
    {
        byte[] tamperedSignatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(tamperedUnsignedToken));
        tamperedSignatureEncoded = Base64UrlEncode(tamperedSignatureBytes);
    }
    
    string tamperedJwtToken = $"{tamperedUnsignedToken}.{tamperedSignatureEncoded}";
    
    Console.WriteLine($"GET {secureUrl} with tampered token\n");
    try
    {
        using var tamperedRequest = new HttpRequestMessage(HttpMethod.Get, secureUrl);
        tamperedRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tamperedJwtToken);
        var invalidResponse = await httpClient.SendAsync(tamperedRequest);
        string invalidResponseContent = await invalidResponse.Content.ReadAsStringAsync();
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Expected Error Response:");
        Console.ResetColor();
        Console.WriteLine(invalidResponseContent);
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error calling Secure API with tampered token: {ex.Message}");
        Console.ResetColor();
    }
    Console.WriteLine();
    
    Console.ForegroundColor = ConsoleColor.Blue;
    Console.WriteLine("=== Testing Complete ===");
    Console.ResetColor();
}

await MainAsync(args);



public class JwtHeader
{
    public required string alg { get; set; }
    public required string typ { get; set; }
    public required string kid { get; set; }
}

public class JwtPayload
{
    public required string iss { get; set; }
    public required string sub { get; set; }
    public required string aud { get; set; }
    public required string scope { get; set; }
    public required string name { get; set; }
    public required string[] roles { get; set; }
    public long iat { get; set; }
    public long exp { get; set; }
}

[JsonSerializable(typeof(JwtHeader))]
[JsonSerializable(typeof(JwtPayload))]
internal partial class MyJsonContext : JsonSerializerContext { }
