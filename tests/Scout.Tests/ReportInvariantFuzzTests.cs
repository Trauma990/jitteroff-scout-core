using System.Net;
using System.Text;
using System.Text.Json;
using Scout.Contracts;
using Scout.Core;
using Scout.Probes;
using Scout.Reporting;

namespace Scout.Tests;

public class ReportInvariantFuzzTests
{
    [Fact]
    public async Task SeededNetworkObservationsDoNotRevealRawHostsOrAddresses()
    {
        var random = new Random(0x5C0);
        for (var i = 0; i < 128; i++)
        {
            var host = $"private-input-{i}.example.org";
            var address = i % 2 == 0
                ? IPAddress.Parse($"11.{random.Next(1, 255)}.{random.Next(1, 255)}.{random.Next(1, 255)}")
                : IPAddress.Parse($"2606:4700::{i + 1:x}");
            var profile = new Profile("0.1", "public-profile", "0.1.0",
                [new Endpoint("endpoint", host, 443, ["dns"], null, null, null)], new string('a', 64));
            var report = await new Runner(new FixedResolver(address), new PublicAddressPolicy(),
                new NeverConnect()).RunAsync(profile, 1);

            Assert.Equal("complete", report.RunStatus);
            Assert.Equal("pass", report.Checks[0].Status);
            foreach (var rendered in new[] { Reports.ToJson(report), Reports.ToHtml(report), Reports.ToMarkdown(report) })
            {
                Assert.DoesNotContain(host, rendered);
                Assert.DoesNotContain(address.ToString(), rendered);
            }
        }
    }

    [Fact]
    public void SeededMissingOrUnknownObservationsCannotClaimComplete()
    {
        var random = new Random(0xC0DE);
        var planned = Enumerable.Range(0, 3).Select(i => new PlannedCheck("endpoint", "dns", i)).ToArray();
        var invalid = new (string Status, string Reason)[]
        {
            ("unknown", "probe_error"), ("inconclusive", "probe_error"),
            ("blocked", "address_policy"), ("skipped", "budget_exhausted"),
            ("cancelled", "user_cancelled")
        };

        for (var i = 0; i < 128; i++)
        {
            var count = random.Next(0, 4);
            var checks = Enumerable.Range(0, count)
                .Select(sample => new CheckResult("endpoint", "dns", sample, "pass", "resolved", 1, "ipv4", "ip_" + new string('a', 64)))
                .ToArray();
            if (count == 3)
            {
                var (status, reason) = invalid[random.Next(invalid.Length)];
                var index = random.Next(checks.Length);
                checks[index] = new CheckResult("endpoint", "dns", index, status, reason, 1);
            }

            var report = new RunReport("0.1", Guid.NewGuid().ToString("D"), "0.1.0", "unknown",
                "public-profile", "0.1.0", new string('a', 64), DateTimeOffset.UtcNow, 1,
                "test", ScoutContract.PolicyVersion, 3, "none", "complete", planned, checks,
                new PrivacySummary("ephemeral_hmac", "Endpoint IDs remain public."));
            Assert.Throws<InvalidDataException>(() => ReportValidator.Validate(report));
            Assert.Throws<InvalidDataException>(() => Reports.ToJson(report));
        }
    }

    [Fact]
    public async Task SeededNetworkErrorsAndResponseBodiesNeverEnterReports()
    {
        var random = new Random(0x5EC);
        for (var i = 0; i < 64; i++)
        {
            var host = $"hidden-{i}.example.org";
            var secret = $"private-token-{i}-{random.NextInt64():x}";
            var body = $"private-body-{i}-{random.NextInt64():x}";
            var profile = new Profile("0.1", "public-profile", "0.1.0",
                [new Endpoint("endpoint", host, 443, i % 2 == 0 ? ["dns"] : ["dns", "tcp"], null, null, null)], new string('a', 64));
            var resolver = i % 2 == 0 ? (IResolver)new ThrowingResolver($"{host} {secret}") : new FixedResolver(IPAddress.Parse("1.1.1.1"));
            var report = await new Runner(resolver, new PublicAddressPolicy(),
                i % 2 == 0 ? new NeverConnect() : new ThrowingConnector($"{host} {secret}")).RunAsync(profile, 1);

            Assert.Equal("partial", report.RunStatus);
            Assert.Equal(3, ReportOutcome.ExitCode(report));
            Assert.Contains(report.Checks, x => x.Status == "inconclusive");
            foreach (var rendered in new[] { Reports.ToJson(report), Reports.ToHtml(report), Reports.ToMarkdown(report) })
            {
                Assert.DoesNotContain(host, rendered);
                Assert.DoesNotContain(secret, rendered);
            }

            var wire = $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\n\r\n{body}";
            using var stream = new MemoryStream(Encoding.ASCII.GetBytes(wire));
            var (status, _) = await HttpProtocol.ReadStatusAsync(stream, CancellationToken.None);
            Assert.Equal(200, status);
            Assert.Equal(wire.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4, stream.Position);
        }
    }

    [Fact]
    public void SeededValidAndInvalidReportModelsHaveFailClosedExitCodes()
    {
        var random = new Random(0x5A7E);
        var cases = new (string RunStatus, string? CheckStatus, string? Reason, int? ExpectedExit)[]
        {
            ("complete", "pass", "resolved", 0),
            ("complete", "fail", "dns_no_answer", 1),
            ("partial", "inconclusive", "probe_error", 3),
            ("partial", "blocked", "address_policy", 3),
            ("partial", "skipped", "budget_exhausted", 3),
            ("cancelled", "cancelled", "user_cancelled", 130),
            ("partial", null, null, 3),
            ("complete", null, null, null),
            ("complete", "inconclusive", "probe_error", null),
            ("complete", "unknown", "probe_error", null)
        };

        for (var i = 0; i < 128; i++)
        {
            var item = cases[random.Next(cases.Length)];
            var checks = item.CheckStatus is null ? Array.Empty<CheckResult>() :
                [new CheckResult("public-endpoint", "dns", 0, item.CheckStatus, item.Reason!, 1,
                    item.CheckStatus == "pass" ? "ipv4" : null,
                    item.CheckStatus == "pass" ? "ip_" + new string('a', 64) : null)];
            var report = new RunReport("0.1", Guid.NewGuid().ToString("D"), "0.1.0", "unknown",
                "public-profile", "0.1.0", new string('a', 64), DateTimeOffset.UtcNow, 1,
                "test", ScoutContract.PolicyVersion, 1, "none", item.RunStatus,
                [new PlannedCheck("public-endpoint", "dns", 0)], checks,
                new PrivacySummary("ephemeral_hmac", "Endpoint IDs remain public."));

            if (item.ExpectedExit is int expected)
            {
                Assert.Equal(expected, ReportOutcome.ExitCode(report));
                Assert.NotEmpty(Reports.ToJson(report));
            }
            else
            {
                Assert.Throws<InvalidDataException>(() => ReportOutcome.ExitCode(report));
                Assert.Throws<InvalidDataException>(() => Reports.ToJson(report));
            }
        }
    }

    [Fact]
    public void SeededUntrustedProfileIdentifiersRejectInjection()
    {
        var random = new Random(0x1D5);
        var invalidPrefixes = new[] { "<script>", "[link]", "../../", "-", " ", "\r\n", "حساب" };
        for (var i = 0; i < 64; i++)
        {
            var malicious = invalidPrefixes[i % invalidPrefixes.Length] + random.NextInt64().ToString("x");
            var json = JsonSerializer.Serialize(new
            {
                schema_version = "0.1",
                profile_id = "public-profile",
                profile_version = "0.1.0",
                endpoints = new[] { new { endpoint_id = malicious, host = "example.com", port = 443, checks = new[] { "dns" } } }
            });
            Assert.Throws<ProfileException>(() => ProfileParser.Parse(Encoding.UTF8.GetBytes(json)));
        }
    }

    private sealed class FixedResolver(IPAddress address) : IResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { address });
    }

    private sealed class ThrowingResolver(string message) : IResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(message);
    }

    private sealed class ThrowingConnector(string message) : IConnectionFactory
    {
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(message);
    }

    private sealed class NeverConnect : IConnectionFactory
    {
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("A DNS-only probe must not open a connection.");
    }
}
