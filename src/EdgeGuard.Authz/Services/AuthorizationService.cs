using System.Diagnostics;
using System.Text.Json;
using EdgeGuard.Authz.Identity;
using EdgeGuard.Authz.Policy;
using EdgeGuard.Authz.Risk;
using EdgeGuard.Authz.Telemetry;
using Envoy.Config.Core.V3;
using Envoy.Service.Auth.V3;
using Envoy.Type.V3;
using Grpc.Core;
using Status = Google.Rpc.Status;
using StatusCode = Envoy.Type.V3.StatusCode;

namespace EdgeGuard.Authz.Services;

/// <summary>
/// Envoy external authorization (envoy.service.auth.v3.Authorization/Check). Runs once per
/// request on the data path: validate identity, read device posture, score session risk,
/// evaluate access policy, then tell Envoy to forward (with identity headers injected and
/// credentials stripped) or to reject with 401/403.
/// </summary>
public sealed class AuthorizationService : Authorization.AuthorizationBase
{
    private const int GrpcOk = 0, GrpcPermissionDenied = 7, GrpcUnauthenticated = 16;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly TokenValidator _tokens;
    private readonly PolicyStore _policy;
    private readonly RiskEngine _risk;
    private readonly DecisionTelemetry _telemetry;

    public AuthorizationService(TokenValidator tokens, PolicyStore policy, RiskEngine risk, DecisionTelemetry telemetry)
    {
        _tokens = tokens; _policy = policy; _risk = risk; _telemetry = telemetry;
    }

    public override async Task<CheckResponse> Check(CheckRequest request, ServerCallContext context)
    {
        var sw = Stopwatch.StartNew();
        var http = request.Attributes?.Request?.Http ?? new AttributeContext.Types.HttpRequest();
        var headers = http.Headers;
        headers.TryGetValue("traceparent", out var traceparent);
        ActivityContext.TryParse(traceparent, null, out var parent);
        using var activity = DecisionTelemetry.Source.StartActivity("edgeguard.check", ActivityKind.Server, parent);

        var bearer = headers.TryGetValue("authorization", out var auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? auth[7..].Trim() : null;
        headers.TryGetValue("x-device-token", out var deviceToken);

        var tokenResult = await _tokens.ValidateUserAsync(bearer, context.CancellationToken);
        var device = tokenResult.User is null ? null : await _tokens.ValidateDeviceAsync(deviceToken);
        var risk = tokenResult.User is null
            ? new RiskSignal(RiskLevel.None, "unauthenticated")
            : _risk.Assess(tokenResult.User.Subject, device is not null);

        var path = string.IsNullOrEmpty(http.Path) ? "/" : http.Path;
        var decision = _policy.Engine.Evaluate(new AccessRequest(http.Method, path, tokenResult.User, device, risk.Level));

        // A presented-but-invalid token is reported precisely (expired, wrong audience, ...).
        if (decision.Verdict == Verdict.Unauthenticated && tokenResult.Error is { } err && err != "missing_token")
            decision = decision with { ReasonCode = err, Reason = $"Access token rejected: {err.Replace('_', ' ')}" };

        if (decision.Verdict == Verdict.Deny && tokenResult.User is not null)
            _risk.RecordDenial(tokenResult.User.Subject);

        var decisionId = Guid.NewGuid().ToString("N")[..16];
        var response = decision.Verdict switch
        {
            Verdict.Allow => Allow(decision, tokenResult.User, device, risk, decisionId),
            Verdict.Unauthenticated => Deny(StatusCode.Unauthorized, GrpcUnauthenticated, decision, decisionId,
                new HeaderValue { Key = "www-authenticate", Value = $"Bearer realm=\"EdgeGuard\", error=\"invalid_token\", error_description=\"{decision.ReasonCode}\"" }),
            _ => Deny(StatusCode.Forbidden, GrpcPermissionDenied, decision, decisionId),
        };
        sw.Stop();

        activity?.SetTag("edgeguard.verdict", decision.Verdict.ToString());
        activity?.SetTag("edgeguard.reason", decision.ReasonCode);
        activity?.SetTag("edgeguard.app", decision.AppId);

        _telemetry.Record(new DecisionEvent(
            DateTimeOffset.UtcNow, decisionId,
            headers.TryGetValue("x-request-id", out var rid) ? rid : "",
            traceparent,
            tokenResult.User?.Subject ?? "anonymous",
            tokenResult.User?.Issuer ?? "none",
            http.Method, path, decision.AppId, decision.Destination,
            decision.Verdict.ToString().ToLowerInvariant(), decision.ReasonCode, decision.Reason,
            decision.AppliedPolicies.ToArray(),
            risk.Level.ToString().ToLowerInvariant(), risk.Why,
            device?.DeviceId, device?.Compliant,
            SourceIp(request, headers),
            sw.Elapsed.TotalMilliseconds,
            tokenResult.CacheHit));
        return response;
    }

    private static CheckResponse Allow(Decision d, UserIdentity? user, DeviceState? device, RiskSignal risk, string decisionId)
    {
        var ok = new OkHttpResponse();
        // Overwrite (never append) so a client cannot smuggle its own identity headers upstream.
        void Set(string k, string v) => ok.Headers.Add(new HeaderValueOption
        {
            Header = new HeaderValue { Key = k, Value = v },
            AppendAction = HeaderValueOption.Types.HeaderAppendAction.OverwriteIfExistsOrAdd,
        });
        Set("x-eg-user", user?.Subject ?? "anonymous");
        Set("x-eg-name", user?.Name ?? "");
        Set("x-eg-groups", user is null ? "" : string.Join(",", user.Groups));
        Set("x-eg-mfa", user?.Mfa == true ? "true" : "false");
        Set("x-eg-device-compliant", device?.Compliant == true ? "true" : "false");
        Set("x-eg-risk", risk.Level.ToString().ToLowerInvariant());
        Set("x-eg-decision-id", decisionId);
        Set("x-eg-app", d.AppId ?? "");
        // Credentials stop at the edge: upstream apps never see the user's or device's tokens.
        ok.HeadersToRemove.Add("authorization");
        ok.HeadersToRemove.Add("x-device-token");
        ok.ResponseHeadersToAdd.Add(new HeaderValueOption { Header = new HeaderValue { Key = "x-eg-decision-id", Value = decisionId } });
        return new CheckResponse { Status = new Status { Code = GrpcOk }, OkResponse = ok };
    }

    private static CheckResponse Deny(StatusCode http, int grpc, Decision d, string decisionId, params HeaderValue[] extra)
    {
        var denied = new DeniedHttpResponse
        {
            Status = new HttpStatus { Code = http },
            Body = JsonSerializer.Serialize(new
            {
                decision = d.Verdict == Verdict.Unauthenticated ? "unauthenticated" : "deny",
                reason = d.ReasonCode,
                message = d.Reason,
                app = d.AppId,
                policies = d.AppliedPolicies,
                decisionId,
            }, Json),
        };
        denied.Headers.Add(new HeaderValueOption { Header = new HeaderValue { Key = "content-type", Value = "application/json" } });
        denied.Headers.Add(new HeaderValueOption { Header = new HeaderValue { Key = "x-eg-decision-id", Value = decisionId } });
        foreach (var h in extra) denied.Headers.Add(new HeaderValueOption { Header = h });
        return new CheckResponse { Status = new Status { Code = grpc, Message = d.ReasonCode }, DeniedResponse = denied };
    }

    private static string SourceIp(CheckRequest r, IDictionary<string, string> headers)
    {
        if (headers.TryGetValue("x-forwarded-for", out var xff) && xff.Length > 0) return xff.Split(',')[0].Trim();
        return r.Attributes?.Source?.Address?.SocketAddress?.Address ?? "";
    }
}
