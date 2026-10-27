using System.Security.Cryptography;
using EdgeGuard.Authz.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace EdgeGuard.Authz.Tests;

/// <summary>Entra-shaped tokens validated against an injected OIDC configuration (no network).</summary>
public class EntraTokenTests
{
    private const string Tenant = "11111111-2222-3333-4444-555555555555";
    private const string ClientId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private static readonly RsaSecurityKey TenantKey = new(RSA.Create(2048)) { KeyId = "entra-key-1" };

    private sealed class StaticConfig : IConfigurationManager<OpenIdConnectConfiguration>
    {
        private readonly OpenIdConnectConfiguration _c = new();
        public StaticConfig(SecurityKey key) => _c.SigningKeys.Add(key);
        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel) => Task.FromResult(_c);
        public void RequestRefresh() { }
    }

    private static TokenValidator Validator() => new(
        new EntraOptions { TenantId = Tenant, Audiences = new[] { $"api://{ClientId}", ClientId } },
        new DemoIssuer(null), demoEnabled: true, entraConfig: new StaticConfig(TenantKey));

    private static string EntraToken(string issuer, string audience, SecurityKey key, string[]? roles = null, string[]? amr = null, string? acrs = null) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object?>
            {
                ["oid"] = "00000000-0000-0000-0000-00000000beef",
                ["tid"] = Tenant,
                ["name"] = "Nagaraj",
                ["roles"] = roles ?? new[] { "Employees" },
                ["amr"] = amr,
                ["acrs"] = acrs,
            }.Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value!),
        });

    [Fact]
    public async Task V2_access_token_from_the_tenant_is_accepted_with_app_roles()
    {
        var r = await Validator().ValidateUserAsync(EntraToken($"https://login.microsoftonline.com/{Tenant}/v2.0", ClientId, TenantKey, new[] { "HR", "Employees" }));
        Assert.Null(r.Error);
        Assert.Equal("entra", r.User!.Issuer);
        Assert.Equal("00000000-0000-0000-0000-00000000beef", r.User.Subject);
        Assert.Equal(new[] { "HR", "Employees" }, r.User.Groups);
    }

    [Fact]
    public async Task V1_issuer_and_app_id_uri_audience_are_accepted() =>
        Assert.Null((await Validator().ValidateUserAsync(EntraToken($"https://sts.windows.net/{Tenant}/", $"api://{ClientId}", TenantKey))).Error);

    [Fact]
    public async Task Token_from_another_tenant_is_rejected() =>
        Assert.Equal("untrusted_issuer", (await Validator().ValidateUserAsync(
            EntraToken("https://login.microsoftonline.com/99999999-0000-0000-0000-000000000000/v2.0", ClientId, TenantKey))).Error);

    [Fact]
    public async Task Token_for_another_api_is_rejected() =>
        Assert.Equal("wrong_audience", (await Validator().ValidateUserAsync(
            EntraToken($"https://login.microsoftonline.com/{Tenant}/v2.0", "https://graph.microsoft.com", TenantKey))).Error);

    [Fact]
    public async Task Token_signed_with_a_key_outside_the_tenant_jwks_is_rejected() =>
        Assert.Equal("bad_signature", (await Validator().ValidateUserAsync(
            EntraToken($"https://login.microsoftonline.com/{Tenant}/v2.0", ClientId, new RsaSecurityKey(RSA.Create(2048)) { KeyId = "attacker" }))).Error);

    [Theory]
    [InlineData(new[] { "pwd", "mfa" }, null, true)]
    [InlineData(null, "c1", true)]          // Conditional Access authentication context
    [InlineData(new[] { "pwd" }, null, false)]
    public async Task Mfa_is_read_from_amr_or_authentication_context(string[]? amr, string? acrs, bool mfa) =>
        Assert.Equal(mfa, (await Validator().ValidateUserAsync(
            EntraToken($"https://login.microsoftonline.com/{Tenant}/v2.0", ClientId, TenantKey, amr: amr, acrs: acrs))).User!.Mfa);
}
