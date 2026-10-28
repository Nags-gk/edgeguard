using System.Security.Cryptography;
using System.Text;
using EdgeGuard.Authz;
using EdgeGuard.Authz.Identity;
using EdgeGuard.Authz.Policy;
using EdgeGuard.Authz.Risk;
using EdgeGuard.Authz.Services;
using EdgeGuard.Authz.Telemetry;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Prometheus;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration.GetSection("EdgeGuard");
int grpcPort = cfg.GetValue("GrpcPort", 9001), httpPort = cfg.GetValue("HttpPort", 9002), appsPort = cfg.GetValue("AppsPort", 9003);

builder.WebHost.ConfigureKestrel(k =>
{
    k.ListenAnyIP(grpcPort, o => o.Protocols = HttpProtocols.Http2); // ext_authz over h2c
    k.ListenAnyIP(httpPort, o => o.Protocols = HttpProtocols.Http1);  // console, demo tokens, metrics
    k.ListenAnyIP(appsPort, o => o.Protocols = HttpProtocols.Http1);  // demo private apps (upstream)
});
builder.Logging.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = "HH:mm:ss "; });

var entra = new EntraOptions
{
    TenantId = cfg["Entra:TenantId"] ?? "",
    Audiences = (cfg["Entra:Audiences"] ?? "").Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
};
var demoEnabled = cfg.GetValue("Demo:Enabled", true);
var demo = new DemoIssuer(cfg["Demo:SigningKeyPem"]);
var adminKey = cfg["AdminKey"] ?? "";

builder.Services.AddSingleton(entra);
builder.Services.AddSingleton(demo);
builder.Services.AddSingleton(new TokenValidator(entra, demo, demoEnabled) { CacheEnabled = cfg.GetValue("TokenCache", true) });
builder.Services.AddSingleton(sp => new PolicyStore(cfg["PolicyPath"] ?? "config/policy.json", sp.GetRequiredService<ILogger<PolicyStore>>()));
builder.Services.AddSingleton(new RiskEngine(cfg.GetSection("Risk").Get<RiskOptions>() ?? new RiskOptions()));
builder.Services.AddSingleton(new DecisionTelemetry(logToStdout: cfg.GetValue("LogDecisions", true)));
builder.Services.AddGrpc();

if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT")))
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService("edgeguard-authz"))
        .WithTracing(t => t.AddSource(DecisionTelemetry.Source.Name).AddAspNetCoreInstrumentation().AddOtlpExporter());

var app = builder.Build();
app.Services.GetRequiredService<PolicyStore>(); // fail fast on a bad policy file

// Load Entra signing keys before Envoy starts sending traffic (the entrypoint waits for /healthz).
var validator = app.Services.GetRequiredService<TokenValidator>();
if (validator.EntraEnabled)
{
    for (var attempt = 1; ; attempt++)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var keys = await validator.WarmUpAsync(cts.Token);
            app.Logger.LogInformation("Microsoft Entra tenant {Tenant}: loaded {Keys} signing keys", validator.EntraTenant, keys);
            break;
        }
        catch (Exception e) when (attempt < 3)
        {
            app.Logger.LogWarning(e, "Entra metadata fetch failed (attempt {Attempt}); retrying", attempt);
            await Task.Delay(TimeSpan.FromSeconds(attempt));
        }
        catch (Exception e)
        {
            // Keep serving demo identities; Entra requests will retry discovery on demand.
            app.Logger.LogError(e, "Entra metadata unavailable at startup");
            break;
        }
    }
}

// Demo upstream applications live on their own port, behind Envoy.
app.MapWhen(ctx => ctx.Connection.LocalPort == appsPort, a => a.Run(DemoApps.Handle));

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseHttpMetrics();

app.MapGrpcService<AuthorizationService>();

var api = app.MapGroup(""); // the apps port is split off above; gRPC port is h2c-only
api.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));
api.MapMetrics("/metrics");

api.MapGet("/api/config", (TokenValidator v, PolicyStore p) => Results.Ok(new
{
    entraEnabled = v.EntraEnabled,
    tenantId = v.EntraTenant,
    clientId = cfg["Entra:SpaClientId"] ?? "",
    scope = cfg["Entra:Scope"] ?? "",
    demoEnabled,
    policyVersion = p.Version,
}));

api.MapGet("/api/personas", () => DemoPersonas.All.Select(p => new
{
    p.Key, p.Name, p.Groups, p.Mfa, device = p.DeviceId is null ? null : new { id = p.DeviceId, compliant = p.DeviceCompliant, os = p.DeviceOs }, p.Story,
}));

api.MapPost("/api/demo/token", (DemoTokenRequest r) =>
{
    if (!demoEnabled) return Results.NotFound();
    var p = DemoPersonas.Find(r.Persona ?? "");
    if (p is null) return Results.BadRequest(new { error = "unknown persona" });
    string access = r.Tamper switch
    {
        "expired" => demo.IssueUserToken(p, TimeSpan.FromMinutes(5), DateTimeOffset.UtcNow.AddHours(-1)),
        "wrong_audience" => demo.IssueUserToken(p, TimeSpan.FromMinutes(15), audience: "api://some-other-app"),
        _ => demo.IssueUserToken(p, TimeSpan.FromMinutes(15)),
    };
    var device = p.DeviceId is null ? null : demo.IssueDeviceToken(p.DeviceId, p.DeviceCompliant, p.DeviceOs, TimeSpan.FromMinutes(15));
    return Results.Ok(new { persona = p.Key, accessToken = access, deviceToken = device, expiresIn = 900 });
});

api.MapGet("/api/decisions", (DecisionTelemetry t, int? limit, string? subject) =>
    Results.Ok(t.Recent(Math.Clamp(limit ?? 100, 1, 2000), subject)));

api.MapGet("/api/stats", (DecisionTelemetry t) =>
{
    var recent = t.Recent(2000);
    var lat = recent.Select(e => e.LatencyMs).OrderBy(x => x).ToArray();
    double Pct(double q) => lat.Length == 0 ? 0 : lat[Math.Min(lat.Length - 1, (int)Math.Ceiling(q * lat.Length) - 1)];
    return Results.Ok(new
    {
        total = t.Total,
        window = recent.Count,
        byVerdict = recent.GroupBy(e => e.Verdict).ToDictionary(g => g.Key, g => g.Count()),
        byReason = recent.GroupBy(e => e.ReasonCode).ToDictionary(g => g.Key, g => g.Count()),
        checkLatencyMs = new { p50 = Pct(0.50), p95 = Pct(0.95), p99 = Pct(0.99) },
        tokenCacheHitRate = recent.Count == 0 ? 0 : recent.Count(e => e.TokenCacheHit) / (double)recent.Count,
    });
});

api.MapGet("/api/policy", (PolicyStore p) => Results.Text(
    System.Text.Json.JsonSerializer.Serialize(p.Engine.Policy, PolicySet.JsonOptions), "application/json"));

// Containment hook for automation (e.g. the anomaly detector): raise or clear an identity's risk.
bool IsAdmin(HttpRequest r) =>
    adminKey.Length > 0 && r.Headers.TryGetValue("x-admin-key", out var k) &&
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(k.ToString()), Encoding.UTF8.GetBytes(adminKey));

api.MapGet("/api/admin/risk", (RiskEngine risk) => Results.Ok(risk.ExternalRiskSnapshot()));
api.MapPost("/api/admin/risk", (HttpRequest req, RiskOverride o, RiskEngine risk) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    if (string.IsNullOrWhiteSpace(o.Subject) || !Enum.TryParse<RiskLevel>(o.Level, true, out var level)) return Results.BadRequest();
    risk.SetExternalRisk(o.Subject, level, o.Reason ?? "external signal", TimeSpan.FromSeconds(Math.Clamp(o.TtlSeconds ?? 900, 10, 86_400)));
    return Results.Ok(new { o.Subject, level = level.ToString() });
});
api.MapDelete("/api/admin/risk/{subject}", (HttpRequest req, string subject, RiskEngine risk) =>
{
    if (!IsAdmin(req)) return Results.Unauthorized();
    risk.ClearExternalRisk(subject);
    return Results.NoContent();
});

app.Run();

public sealed record DemoTokenRequest(string? Persona, string? Tamper);
public sealed record RiskOverride(string Subject, string Level, string? Reason, int? TtlSeconds);
public partial class Program;
