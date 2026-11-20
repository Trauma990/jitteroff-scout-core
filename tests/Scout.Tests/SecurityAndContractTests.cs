using System.Net;
using System.Net.Sockets;
using System.Text;
using Scout.Contracts;
using Scout.Core;
using Scout.Privacy;
using Scout.Probes;
using Scout.Reporting;

namespace Scout.Tests;

public class SecurityAndContractTests
{
    private static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);
    private static Profile Profile(string checks = "[\"dns\",\"tcp\"]") => ProfileParser.Parse(Utf8($$"""{"schema_version":"0.1","profile_id":"public-demo","profile_version":"0.1.0","endpoints":[{"endpoint_id":"web","host":"example.com","port":443,"checks":{{checks}}}]}"""));

    [Theory]
    [InlineData("{\"schema_version\":\"0.1\",\"schema_version\":\"0.1\"}")]
    [InlineData("{\"schema_version\":\"0.1\",\"profile_id\":\"ok\",\"profile_version\":\"0.1.0\",\"endpoints\":[],\"include\":\"file:///etc/passwd\"}")]
    public void MaliciousOrUnknownProfileFieldsAreRejected(string json) => Assert.Throws<ProfileException>(() => ProfileParser.Parse(Utf8(json)));

    [Fact]
    public void InvalidUtf8AndOversizedProfilesAreRejected()
    {
        Assert.Throws<ProfileException>(() => ProfileParser.Parse([0xff, 0xfe]));
        Assert.Throws<ProfileException>(() => ProfileParser.Parse(new byte[128 * 1024 + 1]));
    }

    [Fact]
    public void HttpRequestLineInjectionIsRejected()
    {
        var bytes = Utf8("""{"schema_version":"0.1","profile_id":"test","profile_version":"0.1.0","endpoints":[{"endpoint_id":"web","host":"example.com","port":443,"checks":["dns","tcp","tls","http"],"http_method":"GET","http_path":"/home injected","expected_status":[200]}]}""");
        Assert.Throws<ProfileException>(() => ProfileParser.Parse(bytes));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("169.254.169.254")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("fc00::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2002:0a00:0001::1")]
    [InlineData("3fff::1")]
    public void PublicPolicyBlocksNonPublicAddresses(string address) => Assert.False(new PublicAddressPolicy().IsAllowed(IPAddress.Parse(address)));

    [Fact]
    public async Task SsrfMixedDnsAnswerMakesZeroConnections()
    {
        var connector = new CountingConnector();
        var resolver = new SequenceResolver([IPAddress.Parse("1.1.1.1"), IPAddress.Loopback]);
        var report = await new Runner(resolver, new PublicAddressPolicy(), connector).RunAsync(Profile(), 1);
        Assert.Equal(0, connector.Calls);
        Assert.Equal("partial", report.RunStatus);
        Assert.Equal("blocked", report.Checks[0].Status);
        Assert.Equal("address_policy", report.Checks[0].ReasonCode);
    }

    [Fact]
    public async Task DnsRebindingBetweenChecksIsBlockedWithoutConnecting()
    {
        var connector = new CountingConnector();
        var resolver = new SequenceResolver([IPAddress.Parse("1.1.1.1")], [IPAddress.Loopback]);
        var report = await new Runner(resolver, new PublicAddressPolicy(), connector).RunAsync(Profile(), 1);
        Assert.Equal("pass", report.Checks[0].Status);
        Assert.Equal("blocked", report.Checks[1].Status);
        Assert.Equal("partial", report.RunStatus);
        Assert.Equal(0, connector.Calls);
    }

    [Fact]
    public async Task SocketPinsValidatedIpEvenIfResolverWouldRebindNext()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var endpoint = new Endpoint("web", "example.com", port, ["dns", "tcp"], null, null, null);
            var profile = new Profile("0.1", "public-demo", "0.1.0", [endpoint], new string('a', 64));
            var resolver = new SequenceResolver([IPAddress.Loopback], [IPAddress.Loopback], [IPAddress.Parse("127.0.0.2")]);
            var accept = listener.AcceptTcpClientAsync();
            var report = await new Runner(resolver, new LoopbackFixturePolicy(), new SocketConnectionFactory()).RunAsync(profile, 1);
            using var received = await accept.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal(2, resolver.Calls); // one DNS query per check; no hidden lookup during connect
            Assert.Equal("complete", report.RunStatus);
            Assert.All(report.Checks, x => Assert.Equal("pass", x.Status));
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task CancellationDuringConnectionCannotClaimSuccess()
    {
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var runner = new Runner(new SequenceResolver([IPAddress.Parse("1.1.1.1")]), new PublicAddressPolicy(), new HangingConnector());
        var report = await runner.RunAsync(Profile(), 1, cancel.Token);
        Assert.Equal("cancelled", report.RunStatus);
        Assert.Contains(report.Checks, x => x.Status == "cancelled");
        Assert.DoesNotContain(report.Checks, x => x.Probe == "tcp" && x.Status == "pass");
    }

    [Fact]
    public async Task ExhaustedTotalBudgetIsPartialAndExplicitlySkipped()
    {
        var runner = new Runner(new SequenceResolver([IPAddress.Parse("1.1.1.1")]), new PublicAddressPolicy(), new HangingConnector(), null, TimeSpan.FromMilliseconds(40));
        var report = await runner.RunAsync(Profile(), 1);
        Assert.Equal("partial", report.RunStatus);
        Assert.Contains(report.Checks, x => x.Status == "skipped" && x.ReasonCode == "budget_exhausted");
        Assert.DoesNotContain(report.Checks, x => x.Probe == "tcp" && x.Status == "pass");
    }

    [Fact]
    public async Task UnexpectedProbeErrorIsInconclusiveAndPartial()
    {
        var report = await new Runner(new SequenceResolver([IPAddress.Parse("1.1.1.1")]), new PublicAddressPolicy(), new CountingConnector()).RunAsync(Profile(), 1);
        Assert.Equal("partial", report.RunStatus);
        Assert.Equal("inconclusive", report.Checks[^1].Status);
        var json = Reports.ToJson(report);
        Assert.DoesNotContain("example.com", json);
        Assert.DoesNotContain("1.1.1.1", json);
    }

    [Fact]
    public async Task RedirectHeaderCannotTriggerSecondRequestOrBodyRead()
    {
        var headers = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 4\r\n\r\n";
        using var stream = new MemoryStream(Utf8(headers + "BODY"));
        var (status, reason) = await HttpProtocol.ReadStatusAsync(stream, CancellationToken.None);
        Assert.Equal(302, status);
        Assert.Equal("received_status", reason);
        Assert.Equal(Utf8(headers).Length, stream.Position); // The redirect and body were never followed/read.
    }

    [Fact]
    public async Task OversizedHttpHeadersStopAtLimit()
    {
        using var stream = new MemoryStream(Utf8("HTTP/1.1 200 OK\r\nX-Pad: " + new string('a', 20000) + "\r\n\r\n"));
        var (status, reason) = await HttpProtocol.ReadStatusAsync(stream, CancellationToken.None);
        Assert.Null(status);
        Assert.Equal("http_headers_too_large", reason);
        Assert.Equal(16 * 1024, stream.Position);
    }

    [Fact]
    public void IncompleteReportCannotClaimComplete()
    {
        var report = Report("complete", []);
        Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(report));
    }

    [Fact]
    public void UnknownOrBlockedCannotClaimComplete()
    {
        var result = new CheckResult("web", "dns", 0, "inconclusive", "probe_error", 1);
        Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(Report("complete", [result])));
    }

    [Fact]
    public void ForgedPassWithProbeErrorReasonIsRejected()
    {
        var result = new CheckResult("web", "dns", 0, "pass", "probe_error", 1);
        Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(Report("complete", [result])));
    }

    [Fact]
    public void ImportedHttpPassWithoutFinalStatusIsRejected()
    {
        var report = Report("partial", [new CheckResult("web", "http", 0, "pass", "expected_status", 1,
            "ipv4", "ip_" + new string('a', 64), null, "not_performed")]) with
        {
            PlannedChecks = [new PlannedCheck("web", "dns", 0), new PlannedCheck("web", "tcp", 0),
                new PlannedCheck("web", "tls", 0), new PlannedCheck("web", "http", 0)]
        };
        Assert.Throws<InvalidDataException>(() => Reports.ToJson(report));
        Assert.Throws<InvalidDataException>(() => Reports.ToHtml(report));
    }

    [Fact]
    public void ImportedDnsPassWithoutAddressEvidenceIsRejected()
    {
        var report = Report("complete", [new CheckResult("web", "dns", 0, "pass", "resolved", 1)]) with
        {
            Checks = [new CheckResult("web", "dns", 0, "pass", "resolved", 1)]
        };
        Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(report));
    }

    [Fact]
    public void ImportedDnsFailureCannotClaimHttpReason()
    {
        var report = Report("complete", [new CheckResult("web", "dns", 0, "fail", "unexpected_status", 1)]);
        Assert.Throws<InvalidDataException>(() => Reports.ToJson(report));
    }

    [Fact]
    public void MissingRequestedSampleCannotClaimComplete()
    {
        var report = Report("complete", [new CheckResult("web", "dns", 0, "pass", "resolved", 1)]) with { SamplesRequested = 2 };
        Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(report));
    }

    [Fact]
    public void TokensDifferAcrossRunsAndDoNotRevealSource()
    {
        using var first = new Tokeniser();
        using var second = new Tokeniser();
        var a = first.Token("ip", "10.42.1.9");
        Assert.Equal(67, a.Length); // ip_ plus the full 256-bit HMAC digest
        Assert.Equal(a, first.Token("ip", "10.42.1.9"));
        Assert.NotEqual(a, second.Token("ip", "10.42.1.9"));
        Assert.DoesNotContain("10.42.1.9", a);
    }

    [Fact]
    public async Task SyntheticAddressAndDomainNeverAppearInAnyReportFormat()
    {
        for (var i = 1; i <= 20; i++)
        {
            var address = $"8.8.8.{i}";
            var domain = $"synthetic-{i}.example";
            var endpoint = new Endpoint("neutral-id", domain, 443, ["dns", "tcp"], null, null, null);
            var profile = new Profile("0.1", "neutral-profile", "0.1.0", [endpoint], new string('a', 64));
            var report = await new Runner(new SequenceResolver([IPAddress.Parse(address)]), new PublicAddressPolicy(), new CountingConnector()).RunAsync(profile, 1);
            foreach (var rendered in new[] { Reports.ToJson(report), Reports.ToHtml(report), Reports.ToMarkdown(report) })
            {
                Assert.DoesNotContain(address, rendered);
                Assert.DoesNotContain(domain, rendered);
            }
        }
    }

    [Fact]
    public void HtmlRejectsInjectedIdentifier()
    {
        var report = Report("complete", [new CheckResult("<script>alert(1)</script>", "dns", 0, "pass", "resolved", 1)], "<script>alert(1)</script>");
        Assert.Throws<InvalidDataException>(() => Reports.ToHtml(report));
    }

    [Fact]
    public void MarkdownRejectsInjectedIdentifier()
    {
        var id = "[click](https://attacker.example)";
        var report = Report("complete", [new CheckResult(id, "dns", 0, "pass", "resolved", 1)], id);
        Assert.Throws<InvalidDataException>(() => Reports.ToMarkdown(report));
    }

    [Fact]
    public void DiffRejectsDifferentDigest()
    {
        var a = Report("complete", [new CheckResult("web", "dns", 0, "pass", "resolved", 1)]);
        Assert.Throws<InvalidDataException>(() => Reports.Diff(a, a with { ProfileDigest = new string('b', 64) }));
    }

    [Fact]
    public void DiffCallsOutMissingObservation()
    {
        var older = Report("complete", [new CheckResult("web", "dns", 0, "pass", "resolved", 1)]);
        var newer = Report("partial", []);
        Assert.Contains("absent from newer report", Reports.Diff(older, newer));
    }

    private static RunReport Report(string runStatus, IReadOnlyList<CheckResult> checks, string id = "web") => new(
        "0.1", Guid.NewGuid().ToString(), "0.1.0", "unknown", "public-demo", "0.1.0", new string('a', 64), DateTimeOffset.UtcNow,
        1, "test", ScoutContract.PolicyVersion, 1, "none", runStatus, [new PlannedCheck(id, "dns", 0)],
        checks.Select(x => x.Status == "pass" ? x with { AddressFamily = "ipv4", AddressToken = "ip_" + new string('a', 64) } : x).ToArray(),
        new PrivacySummary("ephemeral_hmac", "Not full anonymization."));

    private sealed class CountingConnector : IConnectionFactory
    {
        public int Calls { get; private set; }
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken) { Calls++; throw new InvalidOperationException("Unexpected network connection"); }
    }
    private sealed class HangingConnector : IConnectionFactory
    {
        public async Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException();
        }
    }
    private sealed class SequenceResolver(params IPAddress[][] answers) : IResolver
    {
        public int Calls { get; private set; }
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(answers[Math.Min(Calls++, answers.Length - 1)]);
    }
    // Test fixture only. Production CLI always constructs PublicAddressPolicy.
    private sealed class LoopbackFixturePolicy : IAddressPolicy
    {
        public bool IsAllowed(IPAddress address) => IPAddress.IsLoopback(address);
    }
}
