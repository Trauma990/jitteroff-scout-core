using System.Net;
using System.Net.Sockets;
using Scout.Contracts;

namespace Scout.Core;

public interface IAddressPolicy { bool IsAllowed(IPAddress address); }
public sealed class PublicAddressPolicy : IAddressPolicy
{
    public bool IsAllowed(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return false;
        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            // Fail closed on non-global, documentation, benchmarking and metadata ranges.
            if (b[0] is 0 or 10 or 127 or >= 224) return false;
            if (b[0] == 100 && b[1] is >= 64 and <= 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] is >= 16 and <= 31) return false;
            if (b[0] == 192 && (b[1] == 168 || b[1] == 0 || b[1] == 2)) return false;
            if (b[0] == 192 && b[1] == 88 && b[2] == 99) return false; // deprecated 6to4 relay
            if (b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)) return false;
            if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
            return true;
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if ((b[0] & 0xe0) != 0x20) return false; // global unicast only
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return false;
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00) return false; // Teredo
            if (b[0] == 0x20 && b[1] == 0x02) return false; // 6to4 embeds IPv4 destinations
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x02) return false; // benchmarking
            if (b[0] == 0x3f && b[1] == 0xff) return false; // documentation
            return true;
        }
        return false;
    }
    public void ValidateAll(IReadOnlyList<IPAddress> addresses)
    {
        if (addresses.Count is 0 or > 64 || addresses.Any(x => !IsAllowed(x))) throw new AddressBlockedException();
    }
}

public sealed class AddressBlockedException : Exception;
public interface IResolver { Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken); }
public sealed class SystemResolver : IResolver
{
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Dns.GetHostAddressesAsync(host, cancellationToken);
}

public static class ReportValidator
{
    private static readonly IReadOnlySet<string> Reasons = new HashSet<string>([
        "resolved", "connected", "certificate_valid", "expected_status", "unexpected_status", "dns_no_answer",
        "address_policy", "user_cancelled", "budget_exhausted", "timeout", "tls_validation_failed",
        "network_error", "io_error", "probe_error", "dependency_failed", "http_incomplete_headers",
        "http_headers_too_large", "http_invalid_status"
    ], StringComparer.Ordinal);
    public static void Validate(RunReport report)
    {
        if (report.SchemaVersion != ScoutContract.ReportSchema || report.PolicyVersion != ScoutContract.PolicyVersion || report.SamplesRequested is < 1 or > 3 || report.Aggregation != "none") throw new InvalidDataException("Invalid report contract.");
        if (report.RunStatus is not ("complete" or "partial" or "cancelled" or "error")) throw new InvalidDataException("Invalid run_status.");
        if (report.ProfileDigest is null || report.ProfileDigest.Length != 64 || !report.ProfileDigest.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')) throw new InvalidDataException("Invalid profile digest.");
        if (report.ProfileId is null || report.ProfileVersion is null || report.Platform is null || report.ToolVersion is null || report.ToolCommit is null || report.PrivacySummary is null || report.PrivacySummary.Mode != "ephemeral_hmac" || report.PrivacySummary.Warning is null) throw new InvalidDataException("Missing report metadata.");
        if (report.ToolCommit != "unknown" && (report.ToolCommit.Length != 40 || !report.ToolCommit.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))) throw new InvalidDataException("Invalid tool commit.");
        if (report.PlannedChecks is null || report.Checks is null || report.PlannedChecks.Count is < 1 or > 120 || report.Checks.Count > report.PlannedChecks.Count) throw new InvalidDataException("Invalid check count.");
        var planned = new HashSet<(string, string, int)>();
        foreach (var check in report.PlannedChecks)
        {
            if (!planned.Add((check.EndpointId, check.Probe, check.SampleIndex)) || !ScoutContract.ProbeOrder.Contains(check.Probe) || check.SampleIndex < 0 || check.SampleIndex >= report.SamplesRequested) throw new InvalidDataException("Invalid planned checks.");
        }
        if (planned.Select(x => x.Item1).Distinct(StringComparer.Ordinal).Count() > 10) throw new InvalidDataException("Too many endpoints.");
        foreach (var group in report.PlannedChecks.GroupBy(x => (x.EndpointId, x.SampleIndex)))
        {
            var probes = group.Select(x => x.Probe).ToArray();
            for (var i = 0; i < probes.Length; i++) if (probes[i] != ScoutContract.ProbeOrder[i]) throw new InvalidDataException("Invalid check plan order.");
        }
        foreach (var endpoint in report.PlannedChecks.GroupBy(x => x.EndpointId, StringComparer.Ordinal))
        {
            var samples = endpoint.GroupBy(x => x.SampleIndex).OrderBy(x => x.Key).ToArray();
            if (samples.Length != report.SamplesRequested) throw new InvalidDataException("Missing planned sample.");
            var template = samples[0].Select(x => x.Probe).ToArray();
            for (var i = 0; i < samples.Length; i++)
                if (samples[i].Key != i || !samples[i].Select(x => x.Probe).SequenceEqual(template)) throw new InvalidDataException("Inconsistent sample plan.");
        }
        var actual = new HashSet<(string, string, int)>();
        foreach (var check in report.Checks)
        {
            var key = (check.EndpointId, check.Probe, check.SampleIndex);
            if (!planned.Contains(key) || !actual.Add(key) || !ScoutContract.FinalStatuses.Contains(check.Status) || !Reasons.Contains(check.ReasonCode) || check.DurationMs < 0) throw new InvalidDataException("Invalid check result.");
            if (!ValidStatusReason(check)) throw new InvalidDataException("Status and reason disagree.");
            if (check.AddressFamily is not null and not ("ipv4" or "ipv6") || check.AddressToken is not null && (check.AddressToken.Length != 67 || !check.AddressToken.StartsWith("ip_", StringComparison.Ordinal) || !check.AddressToken[3..].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')) || check.RevocationCheck is not null and not "not_performed" || check.HttpStatus is < 100 or > 599) throw new InvalidDataException("Invalid check metadata.");
            if (check.Status == "skipped" && check.ReasonCode == "dependency_failed")
            {
                var position = ScoutContract.ProbeOrder.ToList().IndexOf(check.Probe);
                if (position < 1 || !report.Checks.Any(x => x.EndpointId == check.EndpointId && x.SampleIndex == check.SampleIndex && ScoutContract.ProbeOrder.ToList().IndexOf(x.Probe) < position && (x.Status is "fail" or "blocked" or "inconclusive"))) throw new InvalidDataException("Missing dependency failure evidence.");
            }
        }
        if (report.RunStatus == "complete" && (actual.Count != planned.Count || report.Checks.Any(x => x.Status is "inconclusive" or "blocked" or "cancelled" || x.Status == "skipped" && x.ReasonCode != "dependency_failed"))) throw new InvalidDataException("Incomplete run cannot report complete.");
        if (report.RunStatus == "partial" && actual.Count == planned.Count && report.Checks.All(x => x.Status is "pass" or "fail" || x.Status == "skipped" && x.ReasonCode == "dependency_failed")) throw new InvalidDataException("Complete run cannot report partial.");
    }
    private static bool ValidStatusReason(CheckResult check) => check.Status switch
    {
        "pass" => check.ReasonCode == check.Probe switch
        {
            "dns" => "resolved", "tcp" => "connected", "tls" => "certificate_valid", "http" => "expected_status", _ => ""
        },
        "fail" => check.ReasonCode is "dns_no_answer" or "timeout" or "network_error" or "io_error" or "tls_validation_failed" or "http_incomplete_headers" or "http_headers_too_large" or "http_invalid_status" or "unexpected_status",
        "inconclusive" => check.ReasonCode == "probe_error",
        "blocked" => check.ReasonCode == "address_policy",
        "skipped" => check.ReasonCode is "dependency_failed" or "budget_exhausted",
        "cancelled" => check.ReasonCode == "user_cancelled",
        _ => false
    };
}
