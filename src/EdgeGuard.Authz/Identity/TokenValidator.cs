using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using EdgeGuard.Authz.Policy;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace EdgeGuard.Authz.Identity;

public sealed class EntraOptions
{
    /// <summary>Directory (tenant) ID of the Microsoft Entra tenant. Empty disables Entra validation.</summary>
    public string TenantId { get; set; } = "";
    /// <summary>Accepted audiences: the API's Application ID URI and/or client ID.</summary>
    public string[] Audiences { get; set; } = Array.Empty<string>();
    public string Authority => $"https://login.microsoftonline.com/{TenantId}/v2.0";
    public bool Enabled => !string.IsNullOrWhiteSpace(TenantId) && Audiences.Length > 0;
}

public sealed record TokenResult(UserIdentity? User, string? Error, bool CacheHit);

/// <summary>
/// Validates bearer tokens from Microsoft Entra ID (v1 and v2 access tokens, signing keys
/// from OIDC discovery with automatic rotation) or from the demo issuer. Successful results
/// are cached by token hash until min(token expiry, CacheTtl) so the hot path skips RSA work.
/// </summary>
public sealed class TokenValidator
{
    private readonly EntraOptions _entra;
    private readonly DemoIssuer _demo;
    private readonly bool _demoEnabled;
    private readonly JsonWebTokenHandler _handler = new();
    private readonly IConfigurationManager<OpenIdConnectConfiguration>? _entraConfig;
    private readonly ConcurrentDictionary<string, (UserIdentity User, DateTimeOffset Until)> _cache = new();
    private readonly TimeProvider _time;

    public TimeSpan CacheTtl { get; init; } = TimeSpan.FromSeconds(60);
    public bool CacheEnabled { get; set; } = true;
    public int MaxCacheEntries { get; init; } = 50_000;

    public TokenValidator(EntraOptions entra, DemoIssuer demo, bool demoEnabled, TimeProvider? time = null,
        IConfigurationManager<OpenIdConnectConfiguration>? entraConfig = null)
    {
        _entra = entra;
        _demo = demo;
        _demoEnabled = demoEnabled;
        _time = time ?? TimeProvider.System;
        if (entraConfig is not null)
            _entraConfig = entraConfig;
        else if (entra.Enabled)
            _entraConfig = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{entra.Authority}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever { RequireHttps = true });
    }

    public bool EntraEnabled => _entra.Enabled;
    public string EntraTenant => _entra.TenantId;

    public async Task<TokenResult> ValidateUserAsync(string? token, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token)) return new(null, "missing_token", false);
        var now = _time.GetUtcNow();
        var key = Hash(token);

        if (CacheEnabled && _cache.TryGetValue(key, out var hit))
        {
            if (hit.Until > now) return new(hit.User, null, true);
            _cache.TryRemove(key, out _);
        }

        JsonWebToken jwt;
        try { jwt = _handler.ReadJsonWebToken(token); }
        catch (Exception) { return new(null, "malformed_token", false); }

        TokenValidationResult result;
        string issuerKind;
        if (_demoEnabled && jwt.Issuer == DemoIssuer.Issuer)
        {
            issuerKind = "demo";
            result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidIssuer = DemoIssuer.Issuer,
                ValidAudience = DemoIssuer.UserAudience,
                IssuerSigningKey = _demo.ValidationKey,
                ClockSkew = TimeSpan.FromSeconds(30),
                LifetimeValidator = (nbf, exp, _, p) => LifetimeOk(nbf, exp, p.ClockSkew),
            });
        }
        else if (_entraConfig is not null)
        {
            issuerKind = "entra";
            var cfg = await _entraConfig.GetConfigurationAsync(ct);
            result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                // v2.0 tokens use login.microsoftonline.com/{tid}/v2.0; v1.0 tokens use sts.windows.net/{tid}/
                ValidIssuers = new[] { _entra.Authority, $"https://sts.windows.net/{_entra.TenantId}/" },
                ValidAudiences = _entra.Audiences,
                IssuerSigningKeys = cfg.SigningKeys,
                ClockSkew = TimeSpan.FromMinutes(2),
                LifetimeValidator = (nbf, exp, _, p) => LifetimeOk(nbf, exp, p.ClockSkew),
            });
            if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
                _entraConfig.RequestRefresh(); // signing key rolled over: refetch JWKS next time
        }
        else
        {
            return new(null, "untrusted_issuer", false);
        }

        if (!result.IsValid)
            return new(null, Classify(result.Exception), false);

        var user = ToIdentity((JsonWebToken)result.SecurityToken, issuerKind);
        if (CacheEnabled)
        {
            if (_cache.Count >= MaxCacheEntries) _cache.Clear(); // bounded memory; rare full reset
            var until = user.ExpiresAt < now + CacheTtl ? user.ExpiresAt : now + CacheTtl;
            _cache[key] = (user, until);
        }
        return new(user, null, false);
    }

    public async Task<DeviceState?> ValidateDeviceAsync(string? token)
    {
        if (string.IsNullOrEmpty(token) || !_demoEnabled) return null;
        var r = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = DemoIssuer.Issuer,
            ValidAudience = DemoIssuer.DeviceAudience,
            IssuerSigningKey = _demo.ValidationKey,
            ClockSkew = TimeSpan.FromSeconds(30),
            LifetimeValidator = (nbf, exp, _, p) => LifetimeOk(nbf, exp, p.ClockSkew),
        });
        if (!r.IsValid) return null;
        var c = r.Claims;
        return new DeviceState(
            c.TryGetValue("device_id", out var id) ? id?.ToString() ?? "" : "",
            c.TryGetValue("compliant", out var comp) && comp is bool b && b,
            c.TryGetValue("os", out var os) ? os?.ToString() ?? "" : "");
    }

    private bool LifetimeOk(DateTime? nbf, DateTime? exp, TimeSpan skew)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        if (exp is null || now > exp.Value + skew) return false;
        if (nbf is not null && now + skew < nbf.Value) return false;
        return true;
    }

    private static UserIdentity ToIdentity(JsonWebToken t, string issuerKind)
    {
        string Claim(string type) => t.TryGetPayloadValue<string>(type, out var v) ? v : "";
        var subject = Claim("oid") is { Length: > 0 } oid ? oid : t.Subject;
        var name = Claim("name") is { Length: > 0 } n ? n : Claim("preferred_username");
        var groups = new List<string>();
        foreach (var type in new[] { "roles", "groups" })
            if (t.TryGetPayloadValue<string[]>(type, out var arr)) groups.AddRange(arr);
            else if (t.TryGetPayloadValue<string>(type, out var one)) groups.Add(one);
        var mfa = t.TryGetPayloadValue<string[]>("amr", out var amr) && amr.Contains("mfa")
                  || Claim("acrs").Contains("c1"); // Entra authentication-context claim
        return new UserIdentity(subject, name, issuerKind, groups, mfa, new DateTimeOffset(t.ValidTo, TimeSpan.Zero));
    }

    private static string Classify(Exception? e) => e switch
    {
        SecurityTokenExpiredException => "token_expired",
        SecurityTokenInvalidLifetimeException => "token_expired",
        SecurityTokenInvalidAudienceException => "wrong_audience",
        SecurityTokenInvalidIssuerException => "untrusted_issuer",
        SecurityTokenSignatureKeyNotFoundException => "bad_signature",
        SecurityTokenInvalidSignatureException => "bad_signature",
        _ => "invalid_token",
    };

    private static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
