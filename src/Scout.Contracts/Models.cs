using System.Text.Json.Serialization;

namespace Scout.Contracts;

public sealed record Profile(string SchemaVersion, string ProfileId, string ProfileVersion, IReadOnlyList<Endpoint> Endpoints, string Digest);
public sealed record Endpoint(string EndpointId, string Host, int Port, IReadOnlyList<string> Checks, string? HttpMethod, string? HttpPath, IReadOnlyList<int>? ExpectedStatus);

public sealed record PlannedCheck(string EndpointId, string Probe, int SampleIndex);
public sealed record CheckResult(string EndpointId, string Probe, int SampleIndex, string Status, string ReasonCode, long DurationMs, string? AddressFamily = null, string? AddressToken = null, int? HttpStatus = null, string? RevocationCheck = null);
public sealed record PrivacySummary(string Mode, string Warning);
public sealed record RunReport(
    string SchemaVersion, string ReportId, string ToolVersion, string ToolCommit,
    string ProfileId, string ProfileVersion, string ProfileDigest,
    DateTimeOffset StartedAtUtc, long DurationMs, string Platform, string PolicyVersion,
    int SamplesRequested, string Aggregation, string RunStatus,
    IReadOnlyList<PlannedCheck> PlannedChecks, IReadOnlyList<CheckResult> Checks,
    PrivacySummary PrivacySummary);

public static class ScoutContract
{
    public const string ProfileSchema = "0.1";
    public const string ReportSchema = "0.1";
    public const string PolicyVersion = "public-address-v2";
    public static readonly IReadOnlyList<string> ProbeOrder = ["dns", "tcp", "tls", "http"];
    public static readonly IReadOnlySet<string> FinalStatuses = new HashSet<string>(["pass", "fail", "inconclusive", "blocked", "skipped", "cancelled"], StringComparer.Ordinal);
}
