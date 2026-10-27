using System.Text.Json;

namespace EdgeGuard.Authz;

/// <summary>
/// Stand-in private applications and internet destinations behind the gateway. They trust
/// only the identity headers EdgeGuard injects and echo them, so the console can show exactly
/// what reached the upstream (and that the original tokens did not).
/// </summary>
public static class DemoApps
{
    private static long _flaky;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static async Task Handle(HttpContext ctx)
    {
        var path = ctx.Request.Path.Value ?? "/";
        string H(string k) => ctx.Request.Headers[k].ToString();

        // Every other call fails, to demonstrate Envoy retrying on another attempt.
        if (path.StartsWith("/apps/wiki/flaky") && Interlocked.Increment(ref _flaky) % 2 == 1)
        {
            ctx.Response.StatusCode = 503;
            await ctx.Response.WriteAsync("upstream temporarily unavailable");
            return;
        }

        object content = path switch
        {
            var p when p.StartsWith("/apps/hr") => new { app = "HR Portal", data = "Salary bands and performance reviews (synthetic)" },
            var p when p.StartsWith("/apps/finance") => new { app = "Finance Ledger", data = "Q3 close workbook (synthetic)" },
            var p when p.StartsWith("/apps/wiki") => new { app = "Engineering Wiki", data = "Runbooks and design docs (synthetic)" },
            var p when p.StartsWith("/apps/status") => new { app = "Status Page", data = "All systems operational" },
            var p when p.StartsWith("/internet/") => new { app = "Internet egress", data = $"Simulated fetch of {p.Split('/')[2]}" },
            _ => new { app = "unknown", data = "" },
        };

        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            content,
            path,
            seenByUpstream = new
            {
                user = H("x-eg-user"),
                name = H("x-eg-name"),
                groups = H("x-eg-groups"),
                mfa = H("x-eg-mfa"),
                deviceCompliant = H("x-eg-device-compliant"),
                risk = H("x-eg-risk"),
                decisionId = H("x-eg-decision-id"),
                authorizationHeaderPresent = ctx.Request.Headers.ContainsKey("authorization"),
                deviceTokenPresent = ctx.Request.Headers.ContainsKey("x-device-token"),
            },
        }, Json));
    }
}
