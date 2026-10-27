using System.Diagnostics;
using System.Text.Json;
using Prometheus;

namespace EdgeGuard.Authz.Telemetry;

public sealed record DecisionEvent(
    DateTimeOffset Ts,
    string DecisionId,
    string RequestId,
    string? TraceParent,
    string Subject,
    string Issuer,
    string Method,
    string Path,
    string? App,
    string? Destination,
    string Verdict,
    string ReasonCode,
    string Reason,
    string[] Policies,
    string Risk,
    string RiskWhy,
    string? Device,
    bool? DeviceCompliant,
    string SourceIp,
    double LatencyMs,
    bool TokenCacheHit);

/// <summary>
/// Every authorization decision becomes (1) Prometheus metrics, (2) a structured JSON log line
/// for the log pipeline, and (3) an entry in an in-memory ring buffer the console and the
/// anomaly detector read. One event shape feeds dashboards, alerts and AI triage.
/// </summary>
public sealed class DecisionTelemetry
{
    public static readonly ActivitySource Source = new("EdgeGuard.Authz");

    private static readonly Counter Decisions = Metrics.CreateCounter(
        "edgeguard_decisions_total", "Authorization decisions", new CounterConfiguration { LabelNames = new[] { "verdict", "reason", "app" } });
    private static readonly Histogram CheckLatency = Metrics.CreateHistogram(
        "edgeguard_check_duration_seconds", "ext_authz Check latency",
        new HistogramConfiguration { Buckets = Histogram.ExponentialBuckets(0.00005, 2, 16), LabelNames = new[] { "verdict" } });
    private static readonly Counter TokenCache = Metrics.CreateCounter(
        "edgeguard_token_cache_total", "Token validation cache lookups", new CounterConfiguration { LabelNames = new[] { "result" } });

    private readonly DecisionEvent[] _ring;
    private long _next;
    private readonly bool _logToStdout;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public DecisionTelemetry(int capacity = 2000, bool logToStdout = true)
    {
        _ring = new DecisionEvent[capacity];
        _logToStdout = logToStdout;
    }

    public void Record(DecisionEvent e)
    {
        Decisions.WithLabels(e.Verdict, e.ReasonCode, e.App ?? "none").Inc();
        CheckLatency.WithLabels(e.Verdict).Observe(e.LatencyMs / 1000.0);
        TokenCache.WithLabels(e.TokenCacheHit ? "hit" : "miss").Inc();
        var slot = Interlocked.Increment(ref _next) - 1;
        _ring[slot % _ring.Length] = e;
        if (_logToStdout)
            Console.Out.WriteLine(JsonSerializer.Serialize(new { type = "edgeguard.decision", decision = e }, Json));
    }

    /// <summary>Most recent first.</summary>
    public IReadOnlyList<DecisionEvent> Recent(int max = 200, string? subject = null)
    {
        var end = Interlocked.Read(ref _next);
        var list = new List<DecisionEvent>(Math.Min(max, _ring.Length));
        for (var i = end - 1; i >= 0 && i >= end - _ring.Length && list.Count < max; i--)
        {
            var e = _ring[i % _ring.Length];
            if (e is null) continue;
            if (subject is null || e.Subject == subject) list.Add(e);
        }
        return list;
    }

    public long Total => Interlocked.Read(ref _next);
}
