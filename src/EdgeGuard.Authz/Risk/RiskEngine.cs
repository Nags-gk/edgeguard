using System.Collections.Concurrent;
using EdgeGuard.Authz.Policy;

namespace EdgeGuard.Authz.Risk;

public sealed class RiskOptions
{
    public int MediumRequestsPer10s { get; set; } = 40;
    public int HighRequestsPer10s { get; set; } = 100;
    public int MediumDenialsPer60s { get; set; } = 5;
    public int HighDenialsPer60s { get; set; } = 15;
}

public sealed record RiskSignal(RiskLevel Level, string Why);

/// <summary>
/// Per-identity session risk from behavior: request velocity, recent denials, and missing
/// device signal. External signals (for example from an anomaly detector) can raise risk
/// for a subject until they expire, which lets automation contain a compromised identity.
/// </summary>
public sealed class RiskEngine
{
    private sealed class Window
    {
        public readonly Queue<long> Requests = new();
        public readonly Queue<long> Denials = new();
    }

    private readonly ConcurrentDictionary<string, Window> _windows = new();
    private readonly ConcurrentDictionary<string, (RiskLevel Level, string Why, DateTimeOffset Until)> _external = new();
    private readonly RiskOptions _o;
    private readonly TimeProvider _time;

    public RiskEngine(RiskOptions o, TimeProvider? time = null) { _o = o; _time = time ?? TimeProvider.System; }

    public RiskSignal Assess(string subject, bool hasDevice)
    {
        var now = _time.GetUtcNow().ToUnixTimeMilliseconds();
        var w = _windows.GetOrAdd(subject, _ => new Window());
        int requests, denials;
        lock (w)
        {
            w.Requests.Enqueue(now);
            Trim(w.Requests, now - 10_000);
            Trim(w.Denials, now - 60_000);
            requests = w.Requests.Count;
            denials = w.Denials.Count;
        }

        var level = RiskLevel.None;
        var why = "normal behavior";
        void Raise(RiskLevel l, string reason) { if (l > level) { level = l; why = reason; } }

        if (!hasDevice) Raise(RiskLevel.Low, "no device signal");
        if (requests > _o.HighRequestsPer10s) Raise(RiskLevel.High, $"{requests} requests in 10s");
        else if (requests > _o.MediumRequestsPer10s) Raise(RiskLevel.Medium, $"{requests} requests in 10s");
        if (denials >= _o.HighDenialsPer60s) Raise(RiskLevel.High, $"{denials} denials in 60s");
        else if (denials >= _o.MediumDenialsPer60s) Raise(RiskLevel.Medium, $"{denials} denials in 60s");

        if (_external.TryGetValue(subject, out var ext))
        {
            if (ext.Until > _time.GetUtcNow()) Raise(ext.Level, ext.Why);
            else _external.TryRemove(subject, out _);
        }
        return new RiskSignal(level, why);
    }

    public void RecordDenial(string subject)
    {
        var now = _time.GetUtcNow().ToUnixTimeMilliseconds();
        var w = _windows.GetOrAdd(subject, _ => new Window());
        lock (w) { w.Denials.Enqueue(now); Trim(w.Denials, now - 60_000); }
    }

    public void SetExternalRisk(string subject, RiskLevel level, string why, TimeSpan ttl) =>
        _external[subject] = (level, why, _time.GetUtcNow() + ttl);

    /// <summary>Release an identity: drop external signals and its behavioral history.</summary>
    public void ClearExternalRisk(string subject)
    {
        _external.TryRemove(subject, out _);
        _windows.TryRemove(subject, out _);
    }

    public IReadOnlyDictionary<string, object> ExternalRiskSnapshot() =>
        _external.Where(kv => kv.Value.Until > _time.GetUtcNow())
                 .ToDictionary(kv => kv.Key, kv => (object)new { level = kv.Value.Level.ToString(), why = kv.Value.Why, until = kv.Value.Until });

    private static void Trim(Queue<long> q, long cutoff) { while (q.Count > 0 && q.Peek() < cutoff) q.Dequeue(); }
}
