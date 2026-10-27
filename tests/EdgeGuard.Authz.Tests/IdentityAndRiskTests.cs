using EdgeGuard.Authz.Identity;
using EdgeGuard.Authz.Policy;
using EdgeGuard.Authz.Risk;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace EdgeGuard.Authz.Tests;

public class TokenValidatorTests
{
    private static readonly DemoIssuer Issuer = new(null);
    private static readonly DemoPersona Alice = DemoPersonas.Find("alice")!;
    private static readonly DemoPersona Bob = DemoPersonas.Find("bob")!;

    private static TokenValidator Validator(TimeProvider? t = null) => new(new EntraOptions(), Issuer, demoEnabled: true, t);

    [Fact]
    public async Task Valid_demo_token_yields_identity_groups_and_mfa()
    {
        var r = await Validator().ValidateUserAsync(Issuer.IssueUserToken(Alice, TimeSpan.FromMinutes(5)));
        Assert.Null(r.Error);
        Assert.Equal("demo-alice", r.User!.Subject);
        Assert.Contains("HR", r.User.Groups);
        Assert.True(r.User.Mfa);
        Assert.False((await Validator().ValidateUserAsync(Issuer.IssueUserToken(Bob, TimeSpan.FromMinutes(5)))).User!.Mfa);
    }

    [Fact]
    public async Task Expired_token_is_rejected()
    {
        var token = Issuer.IssueUserToken(Alice, TimeSpan.FromMinutes(5), DateTimeOffset.UtcNow.AddHours(-1));
        Assert.Equal("token_expired", (await Validator().ValidateUserAsync(token)).Error);
    }

    [Fact]
    public async Task Wrong_audience_is_rejected() =>
        Assert.Equal("wrong_audience", (await Validator().ValidateUserAsync(
            Issuer.IssueUserToken(Alice, TimeSpan.FromMinutes(5), audience: "api://other"))).Error);

    [Fact]
    public async Task Token_signed_by_another_key_is_rejected()
    {
        var forged = new DemoIssuer(null).IssueUserToken(Alice, TimeSpan.FromMinutes(5));
        Assert.Equal("bad_signature", (await Validator().ValidateUserAsync(forged)).Error);
    }

    [Theory]
    [InlineData(null, "missing_token")]
    [InlineData("", "missing_token")]
    [InlineData("not-a-jwt", "malformed_token")]
    public async Task Missing_or_malformed_tokens(string? token, string error) =>
        Assert.Equal(error, (await Validator().ValidateUserAsync(token)).Error);

    [Fact]
    public async Task Foreign_issuer_is_untrusted_when_entra_is_not_configured()
    {
        var withoutDemo = new TokenValidator(new EntraOptions(), Issuer, demoEnabled: false);
        Assert.Equal("untrusted_issuer", (await withoutDemo.ValidateUserAsync(Issuer.IssueUserToken(Alice, TimeSpan.FromMinutes(5)))).Error);
    }

    [Fact]
    public async Task Validation_results_are_cached_until_ttl_then_revalidated()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var v = new TokenValidator(new EntraOptions(), Issuer, true, clock) { CacheTtl = TimeSpan.FromSeconds(60) };
        var token = Issuer.IssueUserToken(Alice, TimeSpan.FromMinutes(10), clock.GetUtcNow());
        Assert.False((await v.ValidateUserAsync(token)).CacheHit);
        Assert.True((await v.ValidateUserAsync(token)).CacheHit);
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.False((await v.ValidateUserAsync(token)).CacheHit);
    }

    [Fact]
    public async Task Cache_never_outlives_the_token()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var v = new TokenValidator(new EntraOptions(), Issuer, true, clock) { CacheTtl = TimeSpan.FromMinutes(30) };
        var token = Issuer.IssueUserToken(Alice, TimeSpan.FromMinutes(2), clock.GetUtcNow());
        Assert.NotNull((await v.ValidateUserAsync(token)).User);
        clock.Advance(TimeSpan.FromMinutes(3));
        var r = await v.ValidateUserAsync(token);
        Assert.Null(r.User);
        Assert.Equal("token_expired", r.Error);
    }

    [Fact]
    public async Task Device_token_is_parsed_and_a_user_token_cannot_pose_as_a_device()
    {
        var v = Validator();
        var device = await v.ValidateDeviceAsync(Issuer.IssueDeviceToken("dev-1", true, "Windows 11", TimeSpan.FromMinutes(5)));
        Assert.Equal(new DeviceState("dev-1", true, "Windows 11"), device);
        Assert.Null(await v.ValidateDeviceAsync(Issuer.IssueUserToken(Alice, TimeSpan.FromMinutes(5))));
    }
}

public class RiskEngineTests
{
    [Fact]
    public void Normal_session_with_device_has_no_risk() =>
        Assert.Equal(RiskLevel.None, new RiskEngine(new RiskOptions()).Assess("u", hasDevice: true).Level);

    [Fact]
    public void Missing_device_is_low_risk() =>
        Assert.Equal(RiskLevel.Low, new RiskEngine(new RiskOptions()).Assess("u", hasDevice: false).Level);

    [Fact]
    public void Request_velocity_raises_risk_and_decays_after_the_window()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var r = new RiskEngine(new RiskOptions { MediumRequestsPer10s = 5, HighRequestsPer10s = 10 }, clock);
        RiskLevel last = RiskLevel.None;
        for (var i = 0; i < 6; i++) last = r.Assess("u", true).Level;
        Assert.Equal(RiskLevel.Medium, last);
        for (var i = 0; i < 5; i++) last = r.Assess("u", true).Level;
        Assert.Equal(RiskLevel.High, last);
        clock.Advance(TimeSpan.FromSeconds(11));
        Assert.Equal(RiskLevel.None, r.Assess("u", true).Level);
    }

    [Fact]
    public void Repeated_denials_escalate_risk()
    {
        var r = new RiskEngine(new RiskOptions { MediumDenialsPer60s = 2, HighDenialsPer60s = 4 });
        r.RecordDenial("u"); r.RecordDenial("u");
        Assert.Equal(RiskLevel.Medium, r.Assess("u", true).Level);
        r.RecordDenial("u"); r.RecordDenial("u");
        Assert.Equal(RiskLevel.High, r.Assess("u", true).Level);
        Assert.Equal(RiskLevel.None, r.Assess("someone-else", true).Level);
    }

    [Fact]
    public void External_signal_contains_an_identity_until_it_expires()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var r = new RiskEngine(new RiskOptions(), clock);
        r.SetExternalRisk("u", RiskLevel.High, "anomaly detector: impossible travel", TimeSpan.FromMinutes(5));
        var s = r.Assess("u", true);
        Assert.Equal(RiskLevel.High, s.Level);
        Assert.Contains("anomaly", s.Why);
        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(RiskLevel.None, r.Assess("u", true).Level);
    }
}

public class RiskReleaseTests
{
    [Fact]
    public void Releasing_an_identity_clears_signals_and_behavioral_history()
    {
        var r = new RiskEngine(new RiskOptions { MediumDenialsPer60s = 1, HighDenialsPer60s = 2 });
        r.RecordDenial("u"); r.RecordDenial("u");
        r.SetExternalRisk("u", RiskLevel.High, "x", TimeSpan.FromMinutes(5));
        Assert.Equal(RiskLevel.High, r.Assess("u", true).Level);
        r.ClearExternalRisk("u");
        Assert.Equal(RiskLevel.None, r.Assess("u", true).Level);
    }
}
