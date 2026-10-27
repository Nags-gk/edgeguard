namespace EdgeGuard.Authz.Policy;

public sealed record UserIdentity(
    string Subject,
    string Name,
    string Issuer,
    IReadOnlyList<string> Groups,
    bool Mfa,
    DateTimeOffset ExpiresAt);

public sealed record DeviceState(string DeviceId, bool Compliant, string Os);

public sealed record AccessRequest(
    string Method,
    string Path,
    UserIdentity? User,
    DeviceState? Device,
    RiskLevel Risk);

public enum Verdict { Allow, Unauthenticated, Deny }

public sealed record Decision(
    Verdict Verdict,
    string ReasonCode,
    string Reason,
    string? AppId,
    string? Destination,
    IReadOnlyList<string> AppliedPolicies)
{
    public bool Allowed => Verdict == Verdict.Allow;
}

/// <summary>
/// Pure, side-effect-free evaluator with Conditional Access semantics:
/// collect every policy whose assignment matches; any Block wins; otherwise every
/// applicable grant control must be satisfied. Unmatched traffic is denied by default.
/// </summary>
public sealed class PolicyEngine
{
    private readonly PolicySet _set;
    private readonly AppDefinition[] _appsByPrefix;
    private readonly KeyValuePair<string, string>[] _categoriesBySuffix;

    public PolicyEngine(PolicySet set)
    {
        _set = set;
        _appsByPrefix = set.Apps.OrderByDescending(a => a.PathPrefix.Length).ToArray();
        _categoriesBySuffix = set.WebFilter.Categories.OrderByDescending(kv => kv.Key.Length).ToArray();
    }

    public PolicySet Policy => _set;

    public Decision Evaluate(AccessRequest req)
    {
        var path = req.Path.Split('?', 2)[0];
        string? destination = null;
        AppDefinition? app = null;
        var internet = path.StartsWith(_set.WebFilter.InternetPathPrefix, StringComparison.Ordinal);

        if (internet)
        {
            destination = ParseDestination(path);
            if (destination is null)
                return new(Verdict.Deny, "bad_destination", "Missing or invalid destination FQDN", null, null, Array.Empty<string>());
        }
        else
        {
            app = _appsByPrefix.FirstOrDefault(a => path.StartsWith(a.PathPrefix, StringComparison.Ordinal));
            if (app is null)
                return new(Verdict.Deny, "no_app", $"No published application matches {path}", null, null, Array.Empty<string>());
            if (app.AllowAnonymous)
                return new(Verdict.Allow, "anonymous_app", $"{app.Name} allows anonymous access", app.Id, null, Array.Empty<string>());
        }

        var appId = app?.Id ?? "internet";

        if (req.User is null)
            return new(Verdict.Unauthenticated, "no_identity", "A valid access token is required", appId, destination, Array.Empty<string>());

        var groups = new HashSet<string>(req.User.Groups, StringComparer.OrdinalIgnoreCase);

        // Web content filtering runs before access policies, like a Secure Web Gateway.
        if (internet)
        {
            var category = Categorize(destination!);
            if (category is not null && _set.WebFilter.BlockedCategories.Contains(category, StringComparer.OrdinalIgnoreCase)
                && !HasCategoryException(groups, category))
                return new(Verdict.Deny, "web_category_blocked", $"Web content filtering blocks category '{category}' ({destination})", appId, destination, Array.Empty<string>());
        }

        var applicable = _set.Policies.Where(p => p.Enabled && Matches(p.Assignment, appId, internet, groups, req.Risk)).ToList();
        var names = applicable.Select(p => p.Name).ToArray();

        var block = applicable.FirstOrDefault(p => p.Grant.Block);
        if (block is not null)
            return new(Verdict.Deny, "policy_block", $"Blocked by policy '{block.Name}'", appId, destination, names);

        foreach (var p in applicable)
        {
            var g = p.Grant;
            if (g.RequireAnyGroup.Count > 0 && !g.RequireAnyGroup.Any(groups.Contains))
                return new(Verdict.Deny, "group_required", $"Policy '{p.Name}' requires membership in one of: {string.Join(", ", g.RequireAnyGroup)}", appId, destination, names);
            if (g.RequireMfa && !req.User.Mfa)
                return new(Verdict.Deny, "mfa_required", $"Policy '{p.Name}' requires multifactor authentication", appId, destination, names);
            if (g.RequireCompliantDevice && req.Device is not { Compliant: true })
                return new(Verdict.Deny, "device_noncompliant", $"Policy '{p.Name}' requires a compliant device", appId, destination, names);
        }

        if (applicable.Count == 0 && !_set.DefaultAllowAuthenticated)
            return new(Verdict.Deny, "no_policy", "No access policy grants this request (default deny)", appId, destination, names);

        return new(Verdict.Allow, "granted", applicable.Count == 0 ? "Allowed by default" : $"Granted by {applicable.Count} policy(ies)", appId, destination, names);
    }

    private static bool Matches(PolicyAssignment a, string appId, bool internet, HashSet<string> groups, RiskLevel risk)
    {
        if (a.InternetTraffic is { } wantInternet && wantInternet != internet) return false;
        if (a.IncludeApps.Count > 0 && !a.IncludeApps.Contains(appId, StringComparer.OrdinalIgnoreCase) && !a.IncludeApps.Contains("*")) return false;
        if (a.ExcludeApps.Contains(appId, StringComparer.OrdinalIgnoreCase)) return false;
        if (a.IncludeGroups.Count > 0 && !a.IncludeGroups.Any(groups.Contains)) return false;
        if (a.ExcludeGroups.Any(groups.Contains)) return false;
        if (a.MinRisk is { } min && risk < min) return false;
        return true;
    }

    private bool HasCategoryException(HashSet<string> groups, string category) =>
        _set.WebFilter.GroupExceptions.Any(kv => groups.Contains(kv.Key) && kv.Value.Contains(category, StringComparer.OrdinalIgnoreCase));

    public string? Categorize(string fqdn)
    {
        foreach (var (suffix, category) in _categoriesBySuffix)
            if (fqdn.Equals(suffix, StringComparison.OrdinalIgnoreCase) || fqdn.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                return category;
        return null;
    }

    /// <summary>/internet/{fqdn}/rest -> fqdn, validated as a DNS name (no ports, no IP literals, no traversal).</summary>
    private string? ParseDestination(string path)
    {
        var rest = path[_set.WebFilter.InternetPathPrefix.Length..];
        var fqdn = rest.Split('/', 2)[0].ToLowerInvariant();
        if (fqdn.Length is 0 or > 253 || !fqdn.Contains('.')) return null;
        foreach (var label in fqdn.Split('.'))
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-') return null;
            if (!label.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')) return null;
        }
        if (fqdn.Split('.').All(l => l.All(char.IsDigit))) return null; // IP literal
        return fqdn;
    }
}
