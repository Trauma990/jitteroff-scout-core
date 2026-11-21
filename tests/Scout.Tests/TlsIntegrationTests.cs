using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Scout.Contracts;
using Scout.Core;
using Scout.Probes;
using Scout.Reporting;

namespace Scout.Tests;

public class TlsIntegrationTests
{
    [Fact]
    public async Task EmptyDnsAtHttpProbeReturnsAValidFailureReport()
    {
        using var cert = CreateCertificate("example.com", false);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var endpoint = new Endpoint("web", "example.com", port, ["dns", "tcp", "tls", "http"], "GET", "/", [200]);
            var profile = new Profile("0.1", "fixture", "0.1.0", [endpoint], new string('a', 64));
            var server = Task.Run(async () =>
            {
                using var tcp = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                tcp.Close();
                using var tlsTcp = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                using var tls = new SslStream(tlsTcp.GetStream(), false);
                try { await tls.AuthenticateAsServerAsync(cert); await tls.ReadExactlyAsync(new byte[1]); }
                catch (IOException) { }
            });
            var resolver = new EmptyAtFourthResolver();
            var report = await new Runner(resolver, new LoopbackFixturePolicy(), new SocketConnectionFactory(), () => TrustFixture(cert)).RunAsync(profile, 1);
            await server.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(4, resolver.Calls);
            Assert.Equal("complete", report.RunStatus);
            Assert.Equal(["pass", "pass", "pass", "fail"], report.Checks.Select(x => x.Status));
            Assert.Equal("dns_no_answer", report.Checks[^1].ReasonCode);
            Assert.Equal(1, ReportOutcome.ExitCode(Reports.FromJson(Encoding.UTF8.GetBytes(Reports.ToJson(report)))));
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task UntrustedCertificateChainIsRejected()
    {
        using var cert = CreateCertificate("example.com", false);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var profile = new Profile("0.1", "fixture", "0.1.0", [new Endpoint("web", "example.com", port, ["dns", "tcp", "tls"], null, null, null)], new string('a', 64));
            var server = Task.Run(async () =>
            {
                using var first = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                first.Close();
                using var second = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                using var tls = new SslStream(second.GetStream(), false);
                try { await tls.AuthenticateAsServerAsync(cert); await tls.ReadExactlyAsync(new byte[1]); }
                catch (IOException) { }
            });
            var report = await new Runner(new FixedResolver(), new LoopbackFixturePolicy(), new SocketConnectionFactory()).RunAsync(profile, 1);
            await server.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("complete", report.RunStatus);
            Assert.Equal("fail", report.Checks[^1].Status);
            Assert.Equal("tls_validation_failed", report.Checks[^1].ReasonCode);
        }
        finally { listener.Stop(); }
    }

    [Theory]
    [InlineData("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\n\r\nprivate-body-secret", "unexpected_status")]
    [InlineData("oversize", "http_headers_too_large")]
    public async Task HttpsRedirectAndHeaderLimitDoNotFollowOrOverread(string response, string expectedReason)
    {
        using var cert = CreateCertificate("example.com", false);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var endpoint = new Endpoint("web", "example.com", port, ["dns", "tcp", "tls", "http"], "GET", "/", [200]);
            var profile = new Profile("0.1", "fixture", "0.1.0", [endpoint], new string('a', 64));
            var server = Task.Run(async () =>
            {
                using var tcp = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                tcp.Close();
                using var tlsTcp = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                using (var tls = new SslStream(tlsTcp.GetStream(), false))
                {
                    await tls.AuthenticateAsServerAsync(cert);
                    try { await tls.ReadExactlyAsync(new byte[1]); } catch (IOException) { }
                }
                using var httpTcp = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                using var httpTls = new SslStream(httpTcp.GetStream(), false);
                await httpTls.AuthenticateAsServerAsync(cert);
                using var reader = new StreamReader(httpTls, Encoding.ASCII, leaveOpen: true);
                while (await reader.ReadLineAsync() is { Length: > 0 }) { }
                var bytes = Encoding.ASCII.GetBytes(response == "oversize" ? "HTTP/1.1 200 OK\r\nX-Pad: " + new string('a', 20000) + "\r\n\r\n" : response);
                await httpTls.WriteAsync(bytes);
                await httpTls.FlushAsync();
                await Task.Delay(100);
            });
            var runner = new Runner(new FixedResolver(), new LoopbackFixturePolicy(), new SocketConnectionFactory(), () => TrustFixture(cert));
            var report = await runner.RunAsync(profile, 1);
            await server.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("complete", report.RunStatus);
            Assert.Equal("fail", report.Checks[^1].Status);
            Assert.Equal(expectedReason, report.Checks[^1].ReasonCode);
            foreach (var rendered in new[] { Reports.ToJson(report), Reports.ToHtml(report), Reports.ToMarkdown(report) })
                Assert.DoesNotContain("private-body-secret", rendered);
            Assert.False(listener.Pending());
        }
        finally { listener.Stop(); }
    }

    [Theory]
    [InlineData("example.com", false, "pass")]
    [InlineData("wrong.example.com", false, "fail")]
    [InlineData("example.com", true, "fail")]
    public async Task TlsHostnameChainAndExpiryAreChecked(string certificateName, bool expired, string expectedStatus)
    {
        using var cert = CreateCertificate(certificateName, expired);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var endpoint = new Endpoint("web", "example.com", port, ["dns", "tcp", "tls"], null, null, null);
            var profile = new Profile("0.1", "fixture", "0.1.0", [endpoint], new string('a', 64));
            string? serverError = null;
            var server = Task.Run(async () =>
            {
                using var first = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                first.Close();
                using var second = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(5));
                using var stream = new SslStream(second.GetStream(), false);
                try { await stream.AuthenticateAsServerAsync(cert); await stream.ReadExactlyAsync(new byte[1]); }
                catch (Exception e) { serverError = e.GetType().Name + ": " + e.Message; } // Client rejection may close the test socket.
            });
            var runner = new Runner(new FixedResolver(), new LoopbackFixturePolicy(), new SocketConnectionFactory(), () => TrustFixture(cert));
            var report = await runner.RunAsync(profile, 1);
            await server.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("complete", report.RunStatus);
            Assert.True(report.Checks[^1].Status == expectedStatus, $"Actual: {report.Checks[^1].Status}/{report.Checks[^1].ReasonCode}; server: {serverError}");
        }
        finally { listener.Stop(); }
    }

    private static X509Certificate2 CreateCertificate(string name, bool expired)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(name);
        request.CertificateExtensions.Add(names.Build());
        using var generated = request.CreateSelfSigned(expired ? DateTimeOffset.UtcNow.AddDays(-3) : DateTimeOffset.UtcNow.AddDays(-1), expired ? DateTimeOffset.UtcNow.AddDays(-1) : DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pkcs12, "fixture"), "fixture", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
    }
    private static X509ChainPolicy TrustFixture(X509Certificate2 cert)
    {
        var chain = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, DisableCertificateDownloads = true, RevocationMode = X509RevocationMode.NoCheck };
        chain.CustomTrustStore.Add(cert);
        return chain;
    }

    private sealed class FixedResolver : IResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Loopback });
    }
    private sealed class EmptyAtFourthResolver : IResolver
    {
        public int Calls { get; private set; }
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult(++Calls == 4 ? Array.Empty<IPAddress>() : [IPAddress.Loopback]);
    }
    private sealed class LoopbackFixturePolicy : IAddressPolicy
    {
        public bool IsAllowed(IPAddress address) => IPAddress.IsLoopback(address);
    }
}
