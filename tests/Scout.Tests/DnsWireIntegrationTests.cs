using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Scout.Contracts;
using Scout.Core;
using Scout.Probes;
using Scout.Reporting;

namespace Scout.Tests;

public class DnsWireIntegrationTests
{
    [Fact]
    public async Task RebindingOnRealDnsSocketBlocksLoopbackBeforeTcpConnect()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        await using var dns = new ChangingDnsServer(
            [IPAddress.Parse("1.1.1.1")],
            [IPAddress.Loopback]);

        var profile = ProfileFor(((IPEndPoint)listener.LocalEndpoint).Port);
        var report = await new Runner(new WireDnsResolver(dns.Port), new PublicAddressPolicy(),
            new SocketConnectionFactory()).RunAsync(profile, 1);

        Assert.Equal(2, dns.RequestCount);
        Assert.Equal("partial", report.RunStatus);
        Assert.Equal(["pass", "blocked"], report.Checks.Select(x => x.Status).ToArray());
        Assert.Equal("address_policy", report.Checks[1].ReasonCode);
        Assert.False(listener.Pending());
        Assert.DoesNotContain("127.0.0.1", Reports.ToJson(report));
    }

    [Fact]
    public async Task MixedPublicAndLoopbackDnsWireAnswerMakesNoConnection()
    {
        await using var dns = new ChangingDnsServer(
            [IPAddress.Parse("1.1.1.1"), IPAddress.Loopback]);
        var connector = new FailIfCalledConnector();

        var report = await new Runner(new WireDnsResolver(dns.Port), new PublicAddressPolicy(),
            connector).RunAsync(ProfileFor(443), 1);

        Assert.Equal(1, dns.RequestCount);
        Assert.Equal(0, connector.Calls);
        Assert.Equal("blocked", report.Checks[0].Status);
        Assert.Equal("partial", report.RunStatus);
    }

    private static Profile ProfileFor(int port) => new("0.1", "wire-fixture", "0.1.0",
        [new Endpoint("web", "example.com", port, ["dns", "tcp"], null, null, null)], new string('a', 64));

    private sealed class FailIfCalledConnector : IConnectionFactory
    {
        public int Calls { get; private set; }
        public Task<Stream> ConnectAsync(IPAddress address, int port, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("The policy should block before any connection.");
        }
    }

    // The test resolver exchanges actual DNS datagrams with the local test server.
    // Production always uses SystemResolver and PublicAddressPolicy.
    private sealed class WireDnsResolver(int port) : IResolver
    {
        public async Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            var name = EncodeName(host);
            var query = new byte[12 + name.Length + 4];
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(0, 2), 0x1234);
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(2, 2), 0x0100);
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(4, 2), 1);
            name.CopyTo(query, 12);
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(12 + name.Length, 2), 1);
            BinaryPrimitives.WriteUInt16BigEndian(query.AsSpan(14 + name.Length, 2), 1);

            using var client = new UdpClient(AddressFamily.InterNetwork);
            await client.SendAsync(query, new IPEndPoint(IPAddress.Loopback, port), cancellationToken);
            var reply = (await client.ReceiveAsync(cancellationToken)).Buffer;
            if (reply.Length < query.Length || BinaryPrimitives.ReadUInt16BigEndian(reply) != 0x1234)
                throw new InvalidDataException("Invalid fixture DNS response.");
            var answerCount = BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(6, 2));
            var offset = query.Length;
            var answers = new List<IPAddress>();
            for (var i = 0; i < answerCount; i++)
            {
                if (offset + 16 > reply.Length || reply[offset] != 0xc0 || reply[offset + 1] != 0x0c)
                    throw new InvalidDataException("Invalid fixture DNS answer.");
                if (BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(offset + 2, 2)) != 1 ||
                    BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(offset + 10, 2)) != 4)
                    throw new InvalidDataException("Expected an IPv4 DNS answer.");
                answers.Add(new IPAddress(reply.AsSpan(offset + 12, 4)));
                offset += 16;
            }
            return answers.ToArray();
        }

        private static byte[] EncodeName(string host)
        {
            using var output = new MemoryStream();
            foreach (var label in host.Split('.'))
            {
                var bytes = Encoding.ASCII.GetBytes(label);
                output.WriteByte((byte)bytes.Length);
                output.Write(bytes);
            }
            output.WriteByte(0);
            return output.ToArray();
        }
    }

    private sealed class ChangingDnsServer : IAsyncDisposable
    {
        private readonly UdpClient socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly CancellationTokenSource stop = new();
        private readonly IPAddress[][] answers;
        private readonly Task worker;
        private int requestCount;

        public ChangingDnsServer(params IPAddress[][] answers)
        {
            this.answers = answers;
            worker = ServeAsync();
        }

        public int Port => ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
        public int RequestCount => Volatile.Read(ref requestCount);

        private async Task ServeAsync()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var request = await socket.ReceiveAsync(stop.Token);
                    var index = Interlocked.Increment(ref requestCount) - 1;
                    var chosen = answers[Math.Min(index, answers.Length - 1)];
                    var query = request.Buffer;
                    if (query.Length < 17) continue;
                    var response = new byte[query.Length + 16 * chosen.Length];
                    query.CopyTo(response, 0);
                    response[2] = 0x81;
                    response[3] = 0x80;
                    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6, 2), (ushort)chosen.Length);
                    for (var i = 0; i < chosen.Length; i++)
                    {
                        var offset = query.Length + 16 * i;
                        response[offset] = 0xc0;
                        response[offset + 1] = 0x0c;
                        response[offset + 3] = 1;
                        response[offset + 5] = 1;
                        response[offset + 11] = 4;
                        chosen[i].GetAddressBytes().CopyTo(response, offset + 12);
                    }
                    await socket.SendAsync(response, request.RemoteEndPoint, stop.Token);
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
        }

        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            socket.Dispose();
            await worker;
            stop.Dispose();
        }
    }
}
