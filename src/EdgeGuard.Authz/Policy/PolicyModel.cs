using System.Text.Json;
using System.Text.Json.Serialization;

namespace EdgeGuard.Authz.Policy;

public enum RiskLevel { None = 0, Low = 1, Medium = 2, High = 3 }

/// <summary>A protected private application, matched by path prefix (Private Access style).</summary>
public sealed record AppDefinition
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string PathPrefix { get; init; }
    public string Sensitivity { get; init; } = "normal";
    public bool AllowAnonymous { get; init; }
}

/// <summary>Who and what a policy applies to. Empty lists mean "all".</summary>
public sealed record PolicyAssignment
{
    public List<string> IncludeApps { get; init; } = new();
    public List<string> ExcludeApps { get; init; } = new();
    public List<string> IncludeGroups { get; init; } = new();
    public List<string> ExcludeGroups { get; init; } = new();
    /// <summary>Applies only when the evaluated risk is at least this level.</summary>
    public RiskLevel? MinRisk { get; init; }
    /// <summary>Applies only to internet (Secure Web Gateway) traffic when true, only to private apps when false.</summary>
    public bool? InternetTraffic { get; init; }
}

/// <summary>Grant controls. Every applicable policy's grant must be satisfied.</summary>
public sealed record GrantControls
{
    public bool Block { get; init; }
    public bool RequireMfa { get; init; }
    public bool RequireCompliantDevice { get; init; }
    /// <summary>User must be in at least one of these groups.</summary>
    public List<string> RequireAnyGroup { get; init; } = new();
}

public sealed record AccessPolicy
{
    public required string Name { get; init; }
    public bool Enabled { get; init; } = true;
    public PolicyAssignment Assignment { get; init; } = new();
    public GrantControls Grant { get; init; } = new();
}

public sealed record WebFilter
{
    public string InternetPathPrefix { get; init; } = "/internet/";
    /// <summary>FQDN suffix -> category. Longest matching suffix wins.</summary>
    public Dictionary<string, string> Categories { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> BlockedCategories { get; init; } = new();
    /// <summary>Group -> categories that group may still reach (e.g. Security may reach "malware" for research).</summary>
    public Dictionary<string, List<string>> GroupExceptions { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed record PolicySet
{
    public List<AppDefinition> Apps { get; init; } = new();
    public List<AccessPolicy> Policies { get; init; } = new();
    public WebFilter WebFilter { get; init; } = new();
    /// <summary>Decision for an authenticated request no policy applies to. Zero Trust default: deny.</summary>
    public bool DefaultAllowAuthenticated { get; init; }

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = true,
    };

    public static PolicySet Load(string path) =>
        JsonSerializer.Deserialize<PolicySet>(File.ReadAllText(path), JsonOptions)
        ?? throw new InvalidOperationException($"Empty policy file {path}");
}
