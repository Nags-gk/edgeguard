using EdgeGuard.Authz.Policy;
using Xunit;

namespace EdgeGuard.Authz.Tests;

public class PolicyEngineTests
{
    private static readonly PolicyEngine Engine = new(PolicySet.Load("policy.json"));

    private static UserIdentity User(bool mfa = true, params string[] groups) =>
        new("u1", "User", "demo", groups, mfa, DateTimeOffset.UtcNow.AddMinutes(10));

    private static readonly DeviceState Compliant = new("d1", true, "Windows 11");
    private static readonly DeviceState Unmanaged = new("d2", false, "Android");

    private static Decision Eval(string path, UserIdentity? u, DeviceState? d = null, RiskLevel risk = RiskLevel.None) =>
        Engine.Evaluate(new AccessRequest("GET", path, u, d, risk));

    [Fact]
    public void Anonymous_app_is_reachable_without_identity() =>
        Assert.Equal(Verdict.Allow, Eval("/apps/status", null).Verdict);

    [Fact]
    public void Protected_app_without_identity_is_unauthenticated() =>
        Assert.Equal(Verdict.Unauthenticated, Eval("/apps/hr", null).Verdict);

    [Fact]
    public void Unpublished_path_is_denied() =>
        Assert.Equal("no_app", Eval("/apps/payroll", User(true, "HR")).ReasonCode);

    [Fact]
    public void Hr_portal_allows_hr_with_mfa_and_compliant_device()
    {
        var d = Eval("/apps/hr/reviews", User(true, "HR", "Employees"), Compliant);
        Assert.True(d.Allowed);
        Assert.Contains("HR Portal: HR group, MFA and compliant device", d.AppliedPolicies);
    }

    [Theory]
    [InlineData(true, "Engineering", true, "group_required")]
    [InlineData(false, "HR", true, "mfa_required")]
    [InlineData(true, "HR", false, "device_noncompliant")]
    public void Hr_portal_enforces_every_grant_control(bool mfa, string group, bool compliantDevice, string reason)
    {
        var d = Eval("/apps/hr", User(mfa, group, "Employees"), compliantDevice ? Compliant : Unmanaged);
        Assert.Equal(Verdict.Deny, d.Verdict);
        Assert.Equal(reason, d.ReasonCode);
    }

    [Fact]
    public void Missing_device_signal_fails_compliance() =>
        Assert.Equal("device_noncompliant", Eval("/apps/finance", User(true, "Finance"), null).ReasonCode);

    [Fact]
    public void High_risk_blocks_even_a_fully_compliant_session()
    {
        var d = Eval("/apps/hr", User(true, "HR", "Employees"), Compliant, RiskLevel.High);
        Assert.Equal("policy_block", d.ReasonCode);
        Assert.Contains("Block high-risk sessions", d.Reason);
    }

    [Fact]
    public void Medium_risk_steps_up_to_mfa()
    {
        Assert.Equal("mfa_required", Eval("/apps/wiki", User(false, "Employees"), Compliant, RiskLevel.Medium).ReasonCode);
        Assert.True(Eval("/apps/wiki", User(true, "Employees"), Compliant, RiskLevel.Medium).Allowed);
        Assert.True(Eval("/apps/wiki", User(false, "Employees"), Compliant, RiskLevel.Low).Allowed);
    }

    [Theory]
    [InlineData("/internet/casino.example/", "web_category_blocked")]
    [InlineData("/internet/www.casino.example/play", "web_category_blocked")]   // subdomain inherits category
    [InlineData("/internet/PHISH.test/login", "web_category_blocked")]         // case-insensitive
    [InlineData("/internet/notcasino.example/", "granted")]                    // suffix must align on a label
    [InlineData("/internet/news.example/", "granted")]
    [InlineData("/internet/uncategorized.org/", "granted")]
    public void Web_content_filtering_by_fqdn_category(string path, string reason) =>
        Assert.Equal(reason, Eval(path, User(false, "Employees")).ReasonCode);

    [Fact]
    public void Security_group_has_a_research_exception_for_malware_but_not_gambling()
    {
        Assert.True(Eval("/internet/malware.test/", User(true, "Security", "Employees")).Allowed);
        Assert.False(Eval("/internet/casino.example/", User(true, "Security", "Employees")).Allowed);
    }

    [Theory]
    [InlineData("/internet/10.0.0.1/")]
    [InlineData("/internet/localhost/")]
    [InlineData("/internet/bad_label.example/")]
    [InlineData("/internet/-lead.example/")]
    [InlineData("/internet//")]
    public void Invalid_destinations_are_rejected(string path) =>
        Assert.Equal("bad_destination", Eval(path, User(true, "Employees")).ReasonCode);

    [Fact]
    public void Internet_access_requires_a_known_population() =>
        Assert.Equal("group_required", Eval("/internet/news.example/", User(true, "Visitors")).ReasonCode);

    [Fact]
    public void Authenticated_traffic_no_policy_grants_is_denied_by_default()
    {
        var set = new PolicySet { Apps = { new AppDefinition { Id = "x", Name = "X", PathPrefix = "/apps/x" } } };
        Assert.Equal("no_policy", new PolicyEngine(set).Evaluate(new AccessRequest("GET", "/apps/x", User(true, "Any"), null, RiskLevel.None)).ReasonCode);
    }

    [Fact]
    public void Block_wins_regardless_of_policy_order()
    {
        var set = new PolicySet
        {
            Apps = { new AppDefinition { Id = "x", Name = "X", PathPrefix = "/apps/x" } },
            Policies =
            {
                new AccessPolicy { Name = "grant", Grant = new GrantControls() },
                new AccessPolicy { Name = "block contractors", Assignment = new PolicyAssignment { IncludeGroups = { "Contractors" } }, Grant = new GrantControls { Block = true } },
            },
        };
        var e = new PolicyEngine(set);
        Assert.Equal("policy_block", e.Evaluate(new AccessRequest("GET", "/apps/x", User(true, "Contractors"), null, RiskLevel.None)).ReasonCode);
        Assert.True(e.Evaluate(new AccessRequest("GET", "/apps/x", User(true, "Employees"), null, RiskLevel.None)).Allowed);
    }

    [Fact]
    public void Disabled_and_excluded_policies_do_not_apply()
    {
        var set = new PolicySet
        {
            Apps = { new AppDefinition { Id = "x", Name = "X", PathPrefix = "/apps/x" } },
            Policies =
            {
                new AccessPolicy { Name = "allow", Grant = new GrantControls() },
                new AccessPolicy { Name = "off", Enabled = false, Grant = new GrantControls { Block = true } },
                new AccessPolicy { Name = "block all but admins", Assignment = new PolicyAssignment { ExcludeGroups = { "Admins" } }, Grant = new GrantControls { Block = true } },
            },
        };
        var e = new PolicyEngine(set);
        Assert.True(e.Evaluate(new AccessRequest("GET", "/apps/x", User(true, "Admins"), null, RiskLevel.None)).Allowed);
        Assert.False(e.Evaluate(new AccessRequest("GET", "/apps/x", User(true, "Users"), null, RiskLevel.None)).Allowed);
    }

    [Fact]
    public void Longest_app_prefix_wins_and_query_string_is_ignored()
    {
        Assert.Equal("hr", Eval("/apps/hr?x=/apps/status", User(true, "HR"), Compliant).AppId);
        Assert.Equal("status", Eval("/apps/status?next=/apps/hr", null).AppId);
    }
}
