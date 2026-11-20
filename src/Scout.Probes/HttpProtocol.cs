using System.Text;

namespace Scout.Probes;

public static class HttpProtocol
{
    // Reads the final status and headers. Informational responses share one bounded header budget.
    // No Location handling and no body read.
    public static async Task<(int? Status, string Reason)> ReadStatusAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[16 * 1024];
        var used = 0;
        var responseStart = 0;
        var informationalResponses = 0;
        while (true)
        {
            if (used == header.Length) return (null, "http_headers_too_large");
            var n = await stream.ReadAsync(header.AsMemory(used, 1), cancellationToken);
            if (n == 0) return (null, "http_incomplete_headers");
            used += n;
            if (used - responseStart < 4 || header[used - 4] != '\r' || header[used - 3] != '\n' || header[used - 2] != '\r' || header[used - 1] != '\n') continue;

            var line = Encoding.ASCII.GetString(header, responseStart, used - responseStart).Split("\r\n", 2)[0];
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || parts[0] != "HTTP/1.1" || parts[1].Length != 3 || !parts[1].All(char.IsAsciiDigit) || !int.TryParse(parts[1], out var code) || code is < 100 or > 599) return (null, "http_invalid_status");
            if (code == 101) return (null, "http_switching_protocols");
            if (code >= 200) return (code, "received_status");
            if (++informationalResponses > 8) return (null, "http_too_many_informational");
            responseStart = used;
        }
    }
}
