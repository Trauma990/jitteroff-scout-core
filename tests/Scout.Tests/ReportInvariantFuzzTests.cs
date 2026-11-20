using System.Net;
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
                .Select(sample => new CheckResult("endpoint", "dns", sample, "pass", "resolved", 1))
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

    private sealed class FixedResolver(IPAddress address) : IResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { address });
    }

    private sealed class NeverConnect : IConnectionFactory
    {
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("A DNS-only probe must not open a connection.");
    }
}
