using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using Scout.Contracts;
using Scout.Core;
using Scout.Probes;
using Scout.Reporting;

namespace Scout.Tests;

public class RetestRegressionTests
{
    [Theory]
    [InlineData("profile_id")]
    [InlineData("endpoint_id")]
    [InlineData("profile_version")]
    [InlineData("host")]
    public async Task TrailingNewlineIsRejectedBeforeAnyResolution(string field)
    {
        var source = new Profile("0.1", "profile", "0.1.0",
            [new Endpoint("web", "example.com", 443, ["dns"], null, null, null)], new string('a', 64));
        var parsed = JsonNode.Parse("""{"schema_version":"0.1","profile_id":"profile","profile_version":"0.1.0","endpoints":[{"endpoint_id":"web","host":"example.com","port":443,"checks":["dns"]}]}""")!;
        if (field == "endpoint_id" || field == "host") parsed["endpoints"]![0]![field] = parsed["endpoints"]![0]![field]!.GetValue<string>() + "\n";
        else parsed[field] = parsed[field]!.GetValue<string>() + "\n";
        Assert.Throws<ProfileException>(() => ProfileParser.Parse(Encoding.UTF8.GetBytes(parsed.ToJsonString())));

        var endpoint = source.Endpoints[0];
        source = field switch
        {
            "profile_id" => source with { ProfileId = "profile\n" },
            "profile_version" => source with { ProfileVersion = "0.1.0\n" },
            "endpoint_id" => source with { Endpoints = [endpoint with { EndpointId = "web\n" }] },
            _ => source with { Endpoints = [endpoint with { Host = "example.com\n" }] }
        };
        var resolver = new CountingResolver();
        await Assert.ThrowsAsync<ProfileException>(() => new Runner(resolver, new PublicAddressPolicy(), new NoConnect()).RunAsync(source, 1));
        Assert.Equal(0, resolver.Calls);
    }

    [Theory]
    [InlineData("tcp", 2)]
    [InlineData("tls", 3)]
    public async Task EmptyDnsAtLaterProbeKeepsValidFailureReport(string lastProbe, int emptyOnCall)
    {
        var probes = lastProbe == "tcp" ? new[] { "dns", "tcp" } : new[] { "dns", "tcp", "tls" };
        var profile = new Profile("0.1", "profile", "0.1.0",
            [new Endpoint("web", "example.com", 443, probes, null, null, null)], new string('a', 64));
        var resolver = new EmptyOnCallResolver(emptyOnCall);
        var report = await new Runner(resolver, new PublicAddressPolicy(), new MemoryConnect()).RunAsync(profile, 1);
        Assert.Equal("complete", report.RunStatus);
        Assert.Equal("fail", report.Checks[^1].Status);
        Assert.Equal("dns_no_answer", report.Checks[^1].ReasonCode);
        Assert.Equal("pass", report.Checks[0].Status);
        Assert.Equal(emptyOnCall, resolver.Calls);
        Assert.Equal(1, ReportOutcome.ExitCode(Reports.FromJson(Encoding.UTF8.GetBytes(Reports.ToJson(report)))));
    }

    [Theory]
    [InlineData("2001:100::1", false)]
    [InlineData("2001:5::1", false)]
    [InlineData("2001:1::4", false)]
    [InlineData("2001:2::1", false)]
    [InlineData("2001:10::1", false)]
    [InlineData("2001:1::1", true)]
    [InlineData("2001:1::2", true)]
    [InlineData("2001:1::3", true)]
    [InlineData("2001:3::1", true)]
    [InlineData("2001:4:112::1", true)]
    [InlineData("2001:20::1", true)]
    [InlineData("2001:30::1", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("3fff::1", false)]
    public void IanaIpv6ExceptionsAreAppliedExactly(string address, bool allowed) =>
        Assert.Equal(allowed, new PublicAddressPolicy().IsAllowed(IPAddress.Parse(address)));

    [Theory]
    [InlineData("started_at_utc")]
    [InlineData("duration_ms")]
    [InlineData("sample_index")]
    [InlineData("null_check")]
    [InlineData("null_planned")]
    [InlineData("profile_version_newline")]
    public void ImportedReportRequiresEveryObservationField(string defect)
    {
        var report = ValidReport();
        var node = JsonNode.Parse(Reports.ToJson(report))!;
        switch (defect)
        {
            case "started_at_utc":
            case "duration_ms": node.AsObject().Remove(defect); break;
            case "sample_index": node["checks"]![0]!.AsObject().Remove(defect); break;
            case "null_check": node["checks"]![0] = null; break;
            case "null_planned": node["planned_checks"]![0] = null; break;
            case "profile_version_newline": node["profile_version"] = "0.1.0\n"; break;
        }
        Assert.Throws<InvalidDataException>(() => Reports.FromJson(Encoding.UTF8.GetBytes(node.ToJsonString())));
    }

    [Fact]
    public void ValidatorRejectsNullCheckRecordsWithoutCrashing()
    {
        var report = ValidReport();
        Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(report with { Checks = [null!] }));
        Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(report with { PlannedChecks = [null!] }));
    }

    [Fact]
    public async Task CliRenderTreatsInvalidReportAsInputError()
    {
        var directory = Path.Combine(Path.GetTempPath(), "scout-retest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var node = JsonNode.Parse(Reports.ToJson(ValidReport()))!;
            node["run_status"] = "forged";
            var input = Path.Combine(directory, "invalid.json");
            var output = Path.Combine(directory, "report.md");
            await File.WriteAllTextAsync(input, node.ToJsonString());
            var cli = Path.Combine(AppContext.BaseDirectory, "Scout.Cli.dll");
            Assert.True(File.Exists(cli), $"CLI build output missing: {cli}");
            var start = new ProcessStartInfo("dotnet")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            foreach (var argument in new[] { cli, "render", input, "--format", "markdown", "--out", output }) start.ArgumentList.Add(argument);
            using var process = Process.Start(start)!;
            var error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(2, process.ExitCode);
            Assert.Contains("Input or output error", error);
            Assert.False(File.Exists(output));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static RunReport ValidReport() => new("0.1", Guid.NewGuid().ToString("D"), "0.1.0", "unknown",
        "profile", "0.1.0", new string('a', 64), DateTimeOffset.UtcNow, 1, "test",
        ScoutContract.PolicyVersion, 1, "none", "complete", [new PlannedCheck("web", "dns", 0)],
        [new CheckResult("web", "dns", 0, "pass", "resolved", 1, "ipv4", "ip_" + new string('a', 64))],
        new PrivacySummary("ephemeral_hmac", "Per-run tokens."));

    private sealed class CountingResolver : IResolver
    {
        public int Calls { get; private set; }
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        { Calls++; return Task.FromResult(new[] { IPAddress.Parse("1.1.1.1") }); }
    }
    private sealed class EmptyOnCallResolver(int emptyOnCall) : IResolver
    {
        public int Calls { get; private set; }
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult(++Calls == emptyOnCall ? Array.Empty<IPAddress>() : [IPAddress.Parse("1.1.1.1")]);
    }
    private sealed class NoConnect : IConnectionFactory
    {
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No connection permitted.");
    }
    private sealed class MemoryConnect : IConnectionFactory
    {
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken) =>
            Task.FromResult<Stream>(new MemoryStream());
    }
}
