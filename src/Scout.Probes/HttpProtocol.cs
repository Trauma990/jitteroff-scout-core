using System.Text;

namespace Scout.Probes;

public static class HttpProtocol
{
    // Reads only the status line and headers. No Location handling and no body read.
    public static async Task<(int? Status, string Reason)> ReadStatusAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[16 * 1024];
        var used = 0;
        while (used < header.Length)
        {
            var n = await stream.ReadAsync(header.AsMemory(used, 1), cancellationToken);
            if (n == 0) return (null, "http_incomplete_headers");
            used += n;
            if (used >= 4 && header[used - 4] == '\r' && header[used - 3] == '\n' && header[used - 2] == '\r' && header[used - 1] == '\n') break;
        }
        if (used == header.Length && !(header[used - 4] == '\r' && header[used - 3] == '\n' && header[used - 2] == '\r' && header[used - 1] == '\n')) return (null, "http_headers_too_large");
        var line = Encoding.ASCII.GetString(header, 0, used).Split("\r\n", 2)[0];
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || parts[0] != "HTTP/1.1" || parts[1].Length != 3 || !parts[1].All(char.IsAsciiDigit) || !int.TryParse(parts[1], out var code) || code is < 100 or > 599) return (null, "http_invalid_status");
        return (code, "received_status");
    }
}
