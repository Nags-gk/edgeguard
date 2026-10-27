using EdgeGuard.Authz.Policy;

namespace EdgeGuard.Authz.Services;

/// <summary>Holds the active policy engine and hot-reloads it when the policy file changes.
/// A bad file is rejected and the last good policy stays live.</summary>
public sealed class PolicyStore : IDisposable
{
    private readonly string _path;
    private readonly ILogger<PolicyStore> _log;
    private readonly FileSystemWatcher? _watcher;
    private volatile PolicyEngine _engine;

    public PolicyStore(string path, ILogger<PolicyStore> log)
    {
        _path = Path.GetFullPath(path);
        _log = log;
        _engine = new PolicyEngine(PolicySet.Load(_path));
        Version = 1;
        try
        {
            _watcher = new FileSystemWatcher(Path.GetDirectoryName(_path)!, Path.GetFileName(_path))
            { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size, EnableRaisingEvents = true };
            _watcher.Changed += (_, _) => Reload();
        }
        catch (Exception e) { _log.LogWarning(e, "Policy hot-reload disabled"); }
    }

    public PolicyEngine Engine => _engine;
    public int Version { get; private set; }

    public bool Reload()
    {
        try
        {
            Thread.Sleep(50); // let the writer finish
            var next = new PolicyEngine(PolicySet.Load(_path));
            _engine = next;
            Version++;
            _log.LogInformation("Policy reloaded (version {Version}, {Count} policies)", Version, next.Policy.Policies.Count);
            return true;
        }
        catch (Exception e)
        {
            _log.LogError(e, "Rejected invalid policy file; keeping version {Version}", Version);
            return false;
        }
    }

    public void Dispose() => _watcher?.Dispose();
}
