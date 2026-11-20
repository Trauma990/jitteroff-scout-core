using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Scout.Contracts;

public sealed class ProfileException(string message) : Exception(message);

public static partial class ProfileParser
{
    private const int MaxBytes = 128 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly HashSet<string> RootKeys = ["schema_version", "profile_id", "profile_version", "endpoints"];
    private static readonly HashSet<string> EndpointKeys = ["endpoint_id", "host", "port", "checks", "http_method", "http_path", "expected_status"];

    public static Profile Parse(byte[] bytes)
    {
        if (bytes.Length is 0 or > MaxBytes) throw new ProfileException("Profile size must be 1..131072 bytes.");
        try { _ = StrictUtf8.GetString(bytes); }
        catch (DecoderFallbackException) { throw new ProfileException("Profile must be valid UTF-8."); }
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            var root = doc.RootElement;
            RequireObject(root, RootKeys);
            var schema = String(root, "schema_version");
            if (schema != ScoutContract.ProfileSchema) throw new ProfileException("Unsupported profile schema_version.");
            var profileId = String(root, "profile_id");
            ValidateId(profileId, "profile_id");
            var version = String(root, "profile_version");
            if (version.Length > 64 || !VersionRegex().IsMatch(version)) throw new ProfileException("Invalid profile_version.");
            var source = Get(root, "endpoints");
            if (source.ValueKind != JsonValueKind.Array || source.GetArrayLength() is 0 or > 10) throw new ProfileException("endpoints must contain 1..10 entries.");
            var endpoints = new List<Endpoint>();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in source.EnumerateArray())
            {
                RequireObject(item, EndpointKeys);
                var id = String(item, "endpoint_id");
                ValidateId(id, "endpoint_id");
                if (!ids.Add(id)) throw new ProfileException("Duplicate endpoint_id.");
                var host = String(item, "host");
                ValidateHost(host);
                var port = Int(item, "port");
                if (port is < 1 or > 65535) throw new ProfileException("Invalid port.");
                var checksJson = Get(item, "checks");
                if (checksJson.ValueKind != JsonValueKind.Array || checksJson.GetArrayLength() is < 1 or > 4) throw new ProfileException("Invalid checks.");
                var checks = checksJson.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString()! : throw new ProfileException("Invalid check.")).ToArray();
                for (var i = 0; i < checks.Length; i++) if (checks[i] != ScoutContract.ProbeOrder[i]) throw new ProfileException("Checks must be an ordered unique prefix of dns,tcp,tls,http.");
                string? method = null, path = null;
                int[]? statuses = null;
                if (checks.Contains("http"))
                {
                    method = String(item, "http_method");
                    if (method is not ("HEAD" or "GET")) throw new ProfileException("Only HEAD and GET are supported.");
                    path = String(item, "http_path");
                    if (!ValidPath(path)) throw new ProfileException("Invalid http_path.");
                    var expected = Get(item, "expected_status");
                    if (expected.ValueKind != JsonValueKind.Array || expected.GetArrayLength() is < 1 or > 6) throw new ProfileException("Invalid expected_status.");
                    statuses = expected.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.Number && x.TryGetInt32(out var n) ? n : throw new ProfileException("Invalid HTTP status.")).ToArray();
                    if (statuses.Any(x => x is < 200 or > 599) || statuses.Distinct().Count() != statuses.Length) throw new ProfileException("Invalid or repeated final HTTP status.");
                }
                else if (item.TryGetProperty("http_method", out _) || item.TryGetProperty("http_path", out _) || item.TryGetProperty("expected_status", out _)) throw new ProfileException("HTTP fields require the http check.");
                endpoints.Add(new Endpoint(id, host, port, checks, method, path, statuses));
            }
            var profile = new Profile(schema, profileId, version, endpoints, Convert.ToHexStringLower(SHA256.HashData(bytes)));
            ValidateModel(profile);
            return profile;
        }
        catch (JsonException) { throw new ProfileException("Invalid JSON or excessive nesting."); }
    }

    // Runner is a public library entry point, so it must not trust caller-built records.
    public static void ValidateModel(Profile profile)
    {
        if (profile is null || profile.SchemaVersion != ScoutContract.ProfileSchema) throw new ProfileException("Invalid profile model.");
        ValidateId(profile.ProfileId, "profile_id");
        if (profile.ProfileVersion is null || profile.ProfileVersion.Length > 64 || !VersionRegex().IsMatch(profile.ProfileVersion)) throw new ProfileException("Invalid profile_version.");
        if (profile.Digest is null || profile.Digest.Length != 64 || !profile.Digest.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')) throw new ProfileException("Invalid profile digest.");
        if (profile.Endpoints is null || profile.Endpoints.Count is < 1 or > 10) throw new ProfileException("Invalid endpoints.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var endpoint in profile.Endpoints)
        {
            if (endpoint is null) throw new ProfileException("Invalid endpoint.");
            ValidateId(endpoint.EndpointId, "endpoint_id");
            if (!ids.Add(endpoint.EndpointId)) throw new ProfileException("Duplicate endpoint_id.");
            ValidateHost(endpoint.Host);
            if (endpoint.Port is < 1 or > 65535 || endpoint.Checks is null || endpoint.Checks.Count is < 1 or > 4) throw new ProfileException("Invalid endpoint checks or port.");
            for (var i = 0; i < endpoint.Checks.Count; i++)
                if (endpoint.Checks[i] != ScoutContract.ProbeOrder[i]) throw new ProfileException("Checks must be an ordered unique prefix of dns,tcp,tls,http.");
            if (endpoint.Checks.Contains("http"))
            {
                if (endpoint.HttpMethod is not ("HEAD" or "GET") || endpoint.HttpPath is null || !ValidPath(endpoint.HttpPath) || endpoint.ExpectedStatus is null || endpoint.ExpectedStatus.Count is < 1 or > 6 || endpoint.ExpectedStatus.Any(x => x is < 200 or > 599) || endpoint.ExpectedStatus.Distinct().Count() != endpoint.ExpectedStatus.Count)
                    throw new ProfileException("Invalid HTTP fields.");
            }
            else if (endpoint.HttpMethod is not null || endpoint.HttpPath is not null || endpoint.ExpectedStatus is not null) throw new ProfileException("HTTP fields require the http check.");
        }
    }

    private static void RequireObject(JsonElement element, HashSet<string> allowed)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new ProfileException("Expected JSON object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name)) throw new ProfileException("Duplicate JSON key.");
            if (!allowed.Contains(property.Name)) throw new ProfileException("Unknown JSON key.");
        }
    }
    private static JsonElement Get(JsonElement obj, string name) => obj.TryGetProperty(name, out var value) ? value : throw new ProfileException($"Missing {name}.");
    private static string String(JsonElement obj, string name) => Get(obj, name) is var value && value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new ProfileException($"Invalid {name}.");
    private static int Int(JsonElement obj, string name) => Get(obj, name) is var value && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) ? number : throw new ProfileException($"Invalid {name}.");
    private static void ValidateId(string id, string field)
    {
        if (id is null || id.Length is < 1 or > 64 || !IdRegex().IsMatch(id)) throw new ProfileException($"Invalid {field}.");
    }
    private static void ValidateHost(string host)
    {
        if (host is null || host.Length is < 4 or > 253 || host.EndsWith('.') || host.Contains(':') || host.Contains('/') || host != host.ToLowerInvariant() || !host.Contains('.')) throw new ProfileException("Invalid DNS host.");
        var labels = host.Split('.');
        if (labels.Any(x => x.Length is < 1 or > 63 || !LabelRegex().IsMatch(x)) || labels[^1].All(char.IsDigit)) throw new ProfileException("Invalid DNS host.");
        if (System.Net.IPAddress.TryParse(host, out _)) throw new ProfileException("IP literals are not allowed.");
        try { if (new IdnMapping().GetAscii(host) != host) throw new ProfileException("Use lowercase ASCII/Punycode DNS names."); }
        catch (ArgumentException) { throw new ProfileException("Invalid IDN hostname."); }
    }
    private static bool ValidPath(string path) => path.Length is >= 1 and <= 1024 && path[0] == '/' && !path.StartsWith("//", StringComparison.Ordinal) && !path.Any(c => c is '?' or '#' or '\\' || c < '!' || c > '~');
    [GeneratedRegex("^[a-z0-9][a-z0-9._-]*$", RegexOptions.CultureInvariant)] private static partial Regex IdRegex();
    [GeneratedRegex("^[0-9]+\\.[0-9]+\\.[0-9]+$", RegexOptions.CultureInvariant)] private static partial Regex VersionRegex();
    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", RegexOptions.CultureInvariant)] private static partial Regex LabelRegex();
}
