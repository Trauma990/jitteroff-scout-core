using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Scout.Contracts;
using Scout.Core;

namespace Scout.Reporting;

public static class Reports
{
    private static readonly string[] RequiredReportFields = [
        "schema_version", "report_id", "tool_version", "tool_commit", "profile_id", "profile_version",
        "profile_digest", "started_at_utc", "duration_ms", "platform", "policy_version",
        "samples_requested", "aggregation", "run_status", "planned_checks", "checks", "privacy_summary"
    ];
    private static readonly string[] RequiredPlannedFields = ["endpoint_id", "probe", "sample_index"];
    private static readonly string[] RequiredResultFields = ["endpoint_id", "probe", "sample_index", "status", "reason_code", "duration_ms"];
    private static readonly string[] RequiredPrivacyFields = ["mode", "warning"];
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16
    };
    public static string ToJson(RunReport report)
    {
        ReportValidator.Validate(report);
        var json = JsonSerializer.Serialize(report, JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > 2 * 1024 * 1024) throw new InvalidDataException("Report exceeds 2 MiB.");
        return json;
    }
    public static RunReport FromJson(byte[] bytes)
    {
        if (bytes.Length is 0 or > 2 * 1024 * 1024) throw new InvalidDataException("Report size is invalid.");
        using (var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 }))
        {
            var root = document.RootElement;
            RequireFields(root, RequiredReportFields);
            var planned = root.GetProperty("planned_checks");
            var checks = root.GetProperty("checks");
            if (planned.ValueKind != JsonValueKind.Array || checks.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Invalid report check arrays.");
            foreach (var item in planned.EnumerateArray()) RequireFields(item, RequiredPlannedFields);
            foreach (var item in checks.EnumerateArray()) RequireFields(item, RequiredResultFields);
            RequireFields(root.GetProperty("privacy_summary"), RequiredPrivacyFields);
        }
        var report = JsonSerializer.Deserialize<RunReport>(bytes, JsonOptions) ?? throw new InvalidDataException("Invalid report.");
        ReportValidator.Validate(report);
        return report;
    }
    private static void RequireFields(JsonElement item, IEnumerable<string> required)
    {
        if (item.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected report object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in item.EnumerateObject())
            if (!seen.Add(property.Name)) throw new InvalidDataException("Duplicate report field.");
        foreach (var field in required)
            if (!item.TryGetProperty(field, out var value) || value.ValueKind == JsonValueKind.Null)
                throw new InvalidDataException($"Missing or null report field: {field}.");
    }
    public static string ToMarkdown(RunReport report)
    {
        ReportValidator.Validate(report);
        var sb = new StringBuilder();
        sb.AppendLine("# Scout Core report");
        sb.AppendLine();
        sb.AppendLine($"Run status: {EscapeMarkdown(report.RunStatus)}");
        sb.AppendLine($"Profile: {EscapeMarkdown(report.ProfileId)} ({EscapeMarkdown(report.ProfileVersion)})");
        sb.AppendLine($"Digest: `{report.ProfileDigest}`");
        sb.AppendLine();
        foreach (var check in report.Checks)
            sb.AppendLine($"- {EscapeMarkdown(check.EndpointId)} / {EscapeMarkdown(check.Probe)} / sample {check.SampleIndex + 1}: **{EscapeMarkdown(check.Status)}** ({EscapeMarkdown(check.ReasonCode)})");
        sb.AppendLine();
        sb.AppendLine(EscapeMarkdown(report.PrivacySummary.Warning));
        return sb.ToString();
    }
    public static string ToHtml(RunReport report)
    {
        ReportValidator.Validate(report);
        var sb = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Scout Core report</title><style>body{font:16px system-ui;max-width:58rem;margin:3rem auto;padding:0 1rem;color:#e6fff2;background:#061b15}li{padding:.4rem}</style></head><body><h1>Scout Core report</h1>");
        sb.Append("<p>Run status: ").Append(WebUtility.HtmlEncode(report.RunStatus)).Append("</p><p>Profile: ").Append(WebUtility.HtmlEncode(report.ProfileId)).Append("</p><ul>");
        foreach (var check in report.Checks)
            sb.Append("<li>").Append(WebUtility.HtmlEncode(check.EndpointId)).Append(" / ").Append(WebUtility.HtmlEncode(check.Probe)).Append(" / ").Append(WebUtility.HtmlEncode(check.Status)).Append(" ( ").Append(WebUtility.HtmlEncode(check.ReasonCode)).Append(" )</li>");
        sb.Append("</ul><p>").Append(WebUtility.HtmlEncode(report.PrivacySummary.Warning)).Append("</p></body></html>");
        return sb.ToString();
    }
    public static string Diff(RunReport oldReport, RunReport newReport)
    {
        ReportValidator.Validate(oldReport);
        ReportValidator.Validate(newReport);
        if (oldReport.ProfileId != newReport.ProfileId || oldReport.ProfileDigest != newReport.ProfileDigest || oldReport.PolicyVersion != newReport.PolicyVersion) throw new InvalidDataException("Reports are not comparable: profile or policy differs.");
        var sb = new StringBuilder("# Scout Core comparison\n\n");
        sb.AppendLine($"Samples: {oldReport.SamplesRequested} → {newReport.SamplesRequested} (aggregation: none)");
        sb.AppendLine($"Platform: {EscapeMarkdown(oldReport.Platform)} → {EscapeMarkdown(newReport.Platform)}");
        sb.AppendLine($"Run status: {oldReport.RunStatus} → {newReport.RunStatus}");
        foreach (var old in oldReport.Checks)
        {
            var current = newReport.Checks.FirstOrDefault(x => x.EndpointId == old.EndpointId && x.Probe == old.Probe && x.SampleIndex == old.SampleIndex);
            if (current is null) sb.AppendLine($"- {EscapeMarkdown(old.EndpointId)} / {old.Probe} / sample {old.SampleIndex + 1}: absent from newer report");
            else if (old.Status != current.Status || old.ReasonCode != current.ReasonCode) sb.AppendLine($"- {EscapeMarkdown(old.EndpointId)} / {old.Probe} / sample {old.SampleIndex + 1}: {old.Status} ({old.ReasonCode}) → {current.Status} ({current.ReasonCode})");
        }
        foreach (var current in newReport.Checks)
            if (!oldReport.Checks.Any(x => x.EndpointId == current.EndpointId && x.Probe == current.Probe && x.SampleIndex == current.SampleIndex)) sb.AppendLine($"- {EscapeMarkdown(current.EndpointId)} / {current.Probe} / sample {current.SampleIndex + 1}: newly recorded ({current.Status}/{current.ReasonCode})");
        sb.AppendLine("No automatic causal or quality conclusion is made.");
        return sb.ToString();
    }
    public static async Task WriteAtomicAsync(string path, string contents, bool overwrite, CancellationToken ct = default)
    {
        var full = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(full) ?? throw new IOException("Invalid output path.");
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("Output directory does not exist.");
        if (!overwrite && File.Exists(full)) throw new IOException("Output already exists; use --overwrite.");
        var temp = Path.Combine(directory, ".scout-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await File.WriteAllTextAsync(temp, contents, new UTF8Encoding(false), ct);
            File.Move(temp, full, overwrite);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    private static string EscapeMarkdown(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("`", "\\`", StringComparison.Ordinal).Replace("*", "\\*", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal).Replace("[", "\\[", StringComparison.Ordinal).Replace("]", "\\]", StringComparison.Ordinal).Replace("(", "\\(", StringComparison.Ordinal).Replace(")", "\\)", StringComparison.Ordinal).Replace("!", "\\!", StringComparison.Ordinal).Replace("#", "\\#", StringComparison.Ordinal).Replace("|", "\\|", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
}
