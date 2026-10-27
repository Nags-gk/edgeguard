using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace EdgeGuard.Authz.Identity;

/// <summary>
/// Issues signed tokens for the public demo personas, so visitors without an account in the
/// Microsoft Entra tenant can still exercise every policy path. Demo tokens use their own
/// issuer and audience and only reach the bundled demo applications.
/// </summary>
public sealed class DemoIssuer
{
    public const string Issuer = "https://edgeguard.demo/issuer";
    public const string UserAudience = "api://edgeguard";
    public const string DeviceAudience = "edgeguard-device";

    private readonly RsaSecurityKey _key;
    private readonly SigningCredentials _creds;
    private readonly JsonWebTokenHandler _handler = new() { SetDefaultTimesOnTokenCreation = false };

    public DemoIssuer(string? pem)
    {
        var rsa = RSA.Create(2048);
        if (!string.IsNullOrWhiteSpace(pem)) rsa.ImportFromPem(pem);
        _key = new RsaSecurityKey(rsa) { KeyId = Base64UrlEncoder.Encode(SHA256.HashData(rsa.ExportRSAPublicKey()))[..16] };
        _creds = new SigningCredentials(_key, SecurityAlgorithms.RsaSha256);
    }

    public SecurityKey ValidationKey => _key;

    public string IssueUserToken(DemoPersona p, TimeSpan lifetime, DateTimeOffset? now = null, string? audience = null)
    {
        var t = now ?? DateTimeOffset.UtcNow;
        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = audience ?? UserAudience,
            IssuedAt = t.UtcDateTime,
            NotBefore = t.UtcDateTime,
            Expires = t.Add(lifetime).UtcDateTime,
            SigningCredentials = _creds,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = p.Subject,
                ["oid"] = p.Subject,
                ["name"] = p.Name,
                ["preferred_username"] = p.Username,
                ["roles"] = p.Groups.ToArray(),
                ["amr"] = p.Mfa ? new[] { "pwd", "mfa" } : new[] { "pwd" },
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
        });
    }

    public string IssueDeviceToken(string deviceId, bool compliant, string os, TimeSpan lifetime)
    {
        var t = DateTimeOffset.UtcNow;
        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = DeviceAudience,
            IssuedAt = t.UtcDateTime,
            NotBefore = t.UtcDateTime,
            Expires = t.Add(lifetime).UtcDateTime,
            SigningCredentials = _creds,
            Claims = new Dictionary<string, object>
            {
                ["device_id"] = deviceId,
                ["compliant"] = compliant,
                ["os"] = os,
            },
        });
    }
}

public sealed record DemoPersona(
    string Key, string Subject, string Name, string Username, string[] Groups, bool Mfa,
    string? DeviceId, bool DeviceCompliant, string DeviceOs, string Story);

public static class DemoPersonas
{
    public static readonly DemoPersona[] All =
    {
        new("alice", "demo-alice", "Alice (HR)", "alice@contoso.demo", new[] { "HR", "Employees" }, true,
            "dev-alice-laptop", true, "Windows 11", "HR staff, MFA, Intune-compliant laptop"),
        new("bob", "demo-bob", "Bob (Engineering)", "bob@contoso.demo", new[] { "Engineering", "Employees" }, false,
            "dev-bob-mac", true, "macOS 15", "Engineer who signed in without MFA"),
        new("carol", "demo-carol", "Carol (Finance)", "carol@contoso.demo", new[] { "Finance", "Employees" }, true,
            "dev-carol-personal", false, "Android 15", "Finance analyst on an unmanaged personal phone"),
        new("dave", "demo-dave", "Dave (Security)", "dave@contoso.demo", new[] { "Security", "Employees" }, true,
            "dev-dave-soc", true, "Windows 11", "SOC analyst with a research exception for malware sites"),
        new("eve", "demo-eve", "Eve (Contractor)", "eve@contoso.demo", new[] { "Contractors" }, true,
            null, false, "unknown", "Contractor with no registered device"),
    };

    public static DemoPersona? Find(string key) =>
        All.FirstOrDefault(p => p.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
}
