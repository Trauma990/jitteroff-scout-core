using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Scout.Contracts;
using Scout.Core;
using Scout.Privacy;

namespace Scout.Probes;

public interface IConnectionFactory { Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken); }
public sealed class SocketConnectionFactory : IConnectionFactory
{
    public async Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch { socket.Dispose(); throw; }
    }
}

public sealed class Runner
{
    private readonly IResolver resolver;
    private readonly IAddressPolicy policy;
    private readonly IConnectionFactory connections;
    private readonly Func<X509ChainPolicy>? testChainPolicyFactory;
    private readonly TimeSpan overallBudget;
    public Runner()
        : this(new SystemResolver(), new PublicAddressPolicy(), new SocketConnectionFactory(), null, null) { }
    internal Runner(IResolver resolver, IAddressPolicy policy, IConnectionFactory connections)
        : this(resolver, policy, connections, null, null) { }
    internal Runner(IResolver resolver, IAddressPolicy policy, IConnectionFactory connections, Func<X509ChainPolicy>? testChainPolicyFactory, TimeSpan? testOverallBudget = null)
    {
        this.resolver = resolver;
        this.policy = policy;
        this.connections = connections;
        this.testChainPolicyFactory = testChainPolicyFactory;
        overallBudget = testOverallBudget ?? TimeSpan.FromSeconds(90);
    }
    public async Task<RunReport> RunAsync(Profile profile, int samples, CancellationToken cancellationToken = default)
    {
        if (profile is null || profile.Endpoints is null) throw new ProfileException("Invalid profile model.");
        // Freeze caller-owned lists before validation and probing so they cannot change after the check.
        var endpoints = profile.Endpoints.Select(endpoint => endpoint is null
            ? throw new ProfileException("Invalid endpoint.")
            : endpoint with
            {
                Checks = endpoint.Checks?.ToArray() ?? throw new ProfileException("Invalid checks."),
                ExpectedStatus = endpoint.ExpectedStatus?.ToArray()
            }).ToArray();
        profile = profile with { Endpoints = endpoints };
        ProfileParser.ValidateModel(profile);
        if (samples is < 1 or > 3) throw new ArgumentOutOfRangeException(nameof(samples));
        var planned = (from sample in Enumerable.Range(0, samples) from endpoint in profile.Endpoints from probe in endpoint.Checks select new PlannedCheck(endpoint.EndpointId, probe, sample)).ToArray();
        var results = new List<CheckResult>();
        var started = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        using var tokens = new Tokeniser();
        var status = "complete";
        foreach (var plan in planned)
        {
            if (cancellationToken.IsCancellationRequested) { status = "cancelled"; break; }
            if (stopwatch.Elapsed >= overallBudget)
            {
                results.Add(new CheckResult(plan.EndpointId, plan.Probe, plan.SampleIndex, "skipped", "budget_exhausted", 0));
                status = "partial";
                continue;
            }
            var endpoint = profile.Endpoints.Single(e => e.EndpointId == plan.EndpointId);
            var previous = results.LastOrDefault(x => x.EndpointId == plan.EndpointId && x.SampleIndex == plan.SampleIndex);
            if (plan.Probe != "dns" && previous is not null && previous.Status != "pass")
            {
                var reason = previous.ReasonCode == "budget_exhausted" ? "budget_exhausted" : "dependency_failed";
                results.Add(new CheckResult(plan.EndpointId, plan.Probe, plan.SampleIndex, "skipped", reason, 0));
                if (reason == "budget_exhausted") status = "partial";
                continue;
            }
            var duration = plan.Probe switch { "dns" => 5, "tcp" => 3, "tls" => 5, "http" => 8, _ => throw new InvalidOperationException() };
            var remaining = overallBudget - stopwatch.Elapsed;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(duration) < remaining ? TimeSpan.FromSeconds(duration) : remaining);
            var checkWatch = Stopwatch.StartNew();
            CheckResult result;
            try
            {
                result = await CheckAsync(endpoint, plan, tokens, timeout.Token);
            }
            catch (OperationCanceledException)
            {
                result = cancellationToken.IsCancellationRequested
                    ? Result("cancelled", "user_cancelled")
                    : remaining <= TimeSpan.FromSeconds(duration) ? Result("skipped", "budget_exhausted") : Result("fail", "timeout");
            }
            catch (AddressBlockedException) { result = Result("blocked", "address_policy"); }
            catch (AuthenticationException) { result = Result("fail", "tls_validation_failed"); }
            catch (IOException e) when (e.InnerException is AuthenticationException) { result = Result("fail", "tls_validation_failed"); }
            catch (SocketException) { result = Result("fail", "network_error"); }
            catch (IOException) { result = Result("fail", "io_error"); }
            catch (Exception) { result = Result("inconclusive", "probe_error"); }
            checkWatch.Stop();
            result = result with { DurationMs = checkWatch.ElapsedMilliseconds };
            results.Add(result);
            if (result.Status is "blocked" or "inconclusive" || result.ReasonCode == "budget_exhausted") status = "partial";
            if (result.Status == "cancelled") { status = "cancelled"; break; }
            CheckResult Result(string s, string r) => new(plan.EndpointId, plan.Probe, plan.SampleIndex, s, r, 0);
        }
        if (status == "complete" && results.Count != planned.Length) status = "partial";
        var commit = typeof(Runner).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(x => x.Key == "ScoutCommit")?.Value ?? "unknown";
        var report = new RunReport(ScoutContract.ReportSchema, Guid.NewGuid().ToString("D"), "0.1.0", commit,
            profile.ProfileId, profile.ProfileVersion, profile.Digest, started, stopwatch.ElapsedMilliseconds,
            System.Runtime.InteropServices.RuntimeInformation.OSDescription, ScoutContract.PolicyVersion, samples, "none", status,
            planned, results, new PrivacySummary("ephemeral_hmac", "Tokens are per run. Endpoint IDs and profile IDs remain visible; this is not full anonymization."));
        ReportValidator.Validate(report);
        return report;
    }

    private async Task<CheckResult> CheckAsync(Endpoint endpoint, PlannedCheck plan, Tokeniser tokens, CancellationToken ct)
    {
        var addresses = await resolver.ResolveAsync(endpoint.Host, ct);
        if (addresses.Length == 0) return Result("fail", "dns_no_answer");
        if (addresses.Length > 64 || addresses.Any(x => !policy.IsAllowed(x))) throw new AddressBlockedException();
        var selected = addresses[0]; // Socket never receives the hostname.
        var family = selected.AddressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6";
        var addressToken = tokens.Token("ip", selected.ToString());
        if (plan.Probe == "dns") return Result("pass", "resolved", family, addressToken);
        await using var raw = await connections.ConnectAsync(selected, endpoint.Port, ct);
        if (plan.Probe == "tcp") return Result("pass", "connected", family, addressToken);
        using var ssl = new SslStream(raw, leaveInnerStreamOpen: true, (_, _, _, errors) => errors == SslPolicyErrors.None);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = endpoint.Host,
            EnabledSslProtocols = SslProtocols.None,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            CertificateChainPolicy = testChainPolicyFactory?.Invoke() ?? new X509ChainPolicy
            {
                DisableCertificateDownloads = true,
                RevocationMode = X509RevocationMode.NoCheck
            }
        }, ct);
        if (plan.Probe == "tls") return Result("pass", "certificate_valid", family, addressToken, revocation: "not_performed");
        var hostHeader = endpoint.Port == 443 ? endpoint.Host : $"{endpoint.Host}:{endpoint.Port}";
        var request = $"{endpoint.HttpMethod} {endpoint.HttpPath} HTTP/1.1\r\nHost: {hostHeader}\r\nConnection: close\r\nUser-Agent: scout-core/0.1\r\n\r\n";
        await ssl.WriteAsync(Encoding.ASCII.GetBytes(request), ct);
        await ssl.FlushAsync(ct);
        var (statusCode, reason) = await HttpProtocol.ReadStatusAsync(ssl, ct);
        if (statusCode is null) return Result("fail", reason, family, addressToken, revocation: "not_performed");
        var code = statusCode.Value;
        var matches = endpoint.ExpectedStatus!.Contains(code);
        return Result(matches ? "pass" : "fail", matches ? "expected_status" : "unexpected_status", family, addressToken, code, "not_performed");

        CheckResult Result(string s, string r, string? f = null, string? token = null, int? http = null, string? revocation = null) => new(plan.EndpointId, plan.Probe, plan.SampleIndex, s, r, 0, f, token, http, revocation);
    }
}
