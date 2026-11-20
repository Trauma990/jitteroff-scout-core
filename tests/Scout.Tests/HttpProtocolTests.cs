using System.Text;
using Scout.Contracts;
using Scout.Core;
using Scout.Probes;

namespace Scout.Tests;

public class HttpProtocolTests
{
    [Theory]
    [InlineData("HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\n\r\nPRIVATE", 200)]
    [InlineData("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n", 204)]
    [InlineData("HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 404 Not Found\r\n\r\n", 404)]
    public async Task InformationalResponsesAreNotFinal(string wire, int expected)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(wire));
        var (status, reason) = await HttpProtocol.ReadStatusAsync(stream, CancellationToken.None);
        Assert.Equal(expected, status);
        Assert.Equal("received_status", reason);
        Assert.Equal(wire.LastIndexOf("\r\n\r\n", StringComparison.Ordinal) + 4, stream.Position);
    }

    [Theory]
    [InlineData("HTTP/1.1 103 Early Hints\r\n\r\n", "http_incomplete_headers")]
    [InlineData("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", "http_switching_protocols")]
    public async Task NoFinalResponseCannotPass(string wire, string expectedReason)
    {
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(wire));
        var (status, reason) = await HttpProtocol.ReadStatusAsync(stream, CancellationToken.None);
        Assert.Null(status);
        Assert.Equal(expectedReason, reason);
    }

    [Fact]
    public async Task InformationalHeadersShareTheTotalLimit()
    {
        var wire = "HTTP/1.1 103 Early Hints\r\nX-Pad: " + new string('a', 9000) + "\r\n\r\n"
            + "HTTP/1.1 103 Early Hints\r\nX-Pad: " + new string('b', 9000) + "\r\n\r\nHTTP/1.1 200 OK\r\n\r\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(wire));
        var (status, reason) = await HttpProtocol.ReadStatusAsync(stream, CancellationToken.None);
        Assert.Null(status);
        Assert.Equal("http_headers_too_large", reason);
        Assert.Equal(16 * 1024, stream.Position);
    }

    [Fact]
    public async Task RepeatedInformationalResponsesAreBounded()
    {
        var wire = string.Concat(Enumerable.Repeat("HTTP/1.1 103 Early Hints\r\n\r\n", 9)) + "HTTP/1.1 200 OK\r\n\r\n";
        using var stream = new MemoryStream(Encoding.ASCII.GetBytes(wire));
        var (status, reason) = await HttpProtocol.ReadStatusAsync(stream, CancellationToken.None);
        Assert.Null(status);
        Assert.Equal("http_too_many_informational", reason);
    }

    [Fact]
    public void InformationalExpectedStatusIsRejectedByParserAndLibraryRunner()
    {
        const string json = """
            {"schema_version":"0.1","profile_id":"test","profile_version":"0.1.0","endpoints":[{"endpoint_id":"web","host":"example.com","port":443,"checks":["dns","tcp","tls","http"],"http_method":"HEAD","http_path":"/","expected_status":[103]}]}
            """;
        Assert.Throws<ProfileException>(() => ProfileParser.Parse(Encoding.UTF8.GetBytes(json)));
        var profile = new Profile("0.1", "test", "0.1.0",
            [new Endpoint("web", "example.com", 443, ["dns", "tcp", "tls", "http"], "HEAD", "/", [103])], new string('a', 64));
        Assert.Throws<ProfileException>(() => ProfileParser.ValidateModel(profile));
    }

    [Fact]
    public async Task LibraryRunnerRejectsUnsafeCallerBuiltProfileBeforeNetwork()
    {
        var profile = new Profile("0.1", "test", "0.1.0",
            [new Endpoint("web", "127.0.0.1", 443, ["dns"], null, null, null)], new string('a', 64));
        await Assert.ThrowsAsync<ProfileException>(() => new Runner().RunAsync(profile, 1));
    }

    [Fact]
    public async Task CallerMutationAfterValidationCannotChangeProbeTarget()
    {
        var endpoints = new List<Endpoint>
        {
            new("web", "example.com", 443, ["dns", "tcp"], null, null, null)
        };
        var profile = new Profile("0.1", "test", "0.1.0", endpoints, new string('a', 64));
        var resolver = new MutatingResolver(() => endpoints[0] =
            new Endpoint("web", "127.0.0.1", 443, ["dns", "tcp"], null, null, null));
        var report = await new Runner(resolver, new PublicAddressPolicy(), new MemoryConnector()).RunAsync(profile, 1);
        Assert.Equal("complete", report.RunStatus);
        Assert.Equal(["example.com", "example.com"], resolver.Hosts);
    }

    [Theory]
    [InlineData("192.0.0.1", false)]
    [InlineData("192.0.2.1", false)]
    [InlineData("192.0.1.1", true)]
    [InlineData("192.2.0.1", true)]
    public void IPv4RulesUseExactSpecialPrefixes(string address, bool allowed) =>
        Assert.Equal(allowed, new PublicAddressPolicy().IsAllowed(System.Net.IPAddress.Parse(address)));

    private sealed class MutatingResolver(Action mutate) : IResolver
    {
        public List<string> Hosts { get; } = [];
        public Task<System.Net.IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            Hosts.Add(host);
            if (Hosts.Count == 1) mutate();
            return Task.FromResult(new[] { System.Net.IPAddress.Parse("1.1.1.1") });
        }
    }

    private sealed class MemoryConnector : IConnectionFactory
    {
        public Task<Stream> ConnectAsync(System.Net.IPAddress address, int port, CancellationToken cancellationToken) =>
            Task.FromResult<Stream>(new MemoryStream());
    }
}
