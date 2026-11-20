using Scout.Contracts;
using Scout.Core;
using Scout.Probes;
using Scout.Reporting;

return await MainAsync(args);

static async Task<int> MainAsync(string[] args)
{
    using var interrupt = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; interrupt.Cancel(); };
    try
    {
        if (args.Length == 0) return Usage();
        switch (args[0])
        {
            case "validate" when args.Length == 2:
            {
                var profile = ProfileParser.Parse(await ReadBoundedAsync(args[1], 128 * 1024, interrupt.Token));
                Console.WriteLine($"Valid profile: {profile.ProfileId} v{profile.ProfileVersion}\nSHA-256: {profile.Digest}");
                return 0;
            }
            case "plan" when args.Length == 2:
            {
                var profile = ProfileParser.Parse(await ReadBoundedAsync(args[1], 128 * 1024, interrupt.Token));
                Console.WriteLine($"Profile: {profile.ProfileId} v{profile.ProfileVersion}\nSHA-256: {profile.Digest}");
                foreach (var endpoint in profile.Endpoints) Console.WriteLine($"- {endpoint.EndpointId}: {string.Join(", ", endpoint.Checks)}");
                Console.WriteLine("No network requests were made. Review the profile file before granting consent to run.");
                return 0;
            }
            case "run" when args.Length >= 6:
            {
                var profile = ProfileParser.Parse(await ReadBoundedAsync(args[1], 128 * 1024, interrupt.Token));
                var flags = ParseFlags(args, 2, ["--allow-profile-digest", "--out", "--samples", "--overwrite"]);
                if (!flags.TryGetValue("--allow-profile-digest", out var consent) || consent != profile.Digest || !flags.TryGetValue("--out", out var output)) throw new ProfileException("Explicit matching --allow-profile-digest and --out are required.");
                var samples = 1;
                if (flags.TryGetValue("--samples", out var s) && !int.TryParse(s, out samples)) throw new ProfileException("Invalid sample count.");
                var runner = new Runner();
                var report = await runner.RunAsync(profile, samples, interrupt.Token);
                await Reports.WriteAtomicAsync(output, Reports.ToJson(report), flags.ContainsKey("--overwrite"), CancellationToken.None);
                Console.WriteLine($"Report written. Run status: {report.RunStatus}; checks: {report.Checks.Count}/{report.PlannedChecks.Count}; pass={report.Checks.Count(x => x.Status == "pass")}; fail={report.Checks.Count(x => x.Status == "fail")}; blocked={report.Checks.Count(x => x.Status == "blocked")}; inconclusive={report.Checks.Count(x => x.Status == "inconclusive")}; skipped={report.Checks.Count(x => x.Status == "skipped")}.");
                if (report.RunStatus == "cancelled") return 130;
                if (report.RunStatus != "complete") return 3;
                return report.Checks.Any(x => x.Status == "fail") ? 1 : 0;
            }
            case "render" when args.Length >= 5:
            {
                var flags = ParseFlags(args, 2, ["--format", "--out", "--overwrite"]);
                if (!flags.TryGetValue("--format", out var format) || !flags.TryGetValue("--out", out var output)) return Usage();
                var report = Reports.FromJson(await ReadBoundedAsync(args[1], 2 * 1024 * 1024, interrupt.Token));
                var contents = format switch { "html" => Reports.ToHtml(report), "markdown" => Reports.ToMarkdown(report), _ => throw new ProfileException("Format must be html or markdown.") };
                await Reports.WriteAtomicAsync(output, contents, flags.ContainsKey("--overwrite"), interrupt.Token);
                return 0;
            }
            case "diff" when args.Length >= 5:
            {
                var flags = ParseFlags(args, 3, ["--out", "--overwrite"]);
                if (!flags.TryGetValue("--out", out var output)) return Usage();
                var older = Reports.FromJson(await ReadBoundAsync(args[1], interrupt.Token));
                var newer = Reports.FromJson(await ReadBoundAsync(args[2], interrupt.Token));
                await Reports.WriteAtomicAsync(output, Reports.Diff(older, newer), flags.ContainsKey("--overwrite"), interrupt.Token);
                return 0;
            }
            default: return Usage();
        }
    }
    catch (OperationCanceledException) { Console.Error.WriteLine("Cancelled."); return 130; }
    catch (Exception e) when (e is ProfileException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentOutOfRangeException)
    { Console.Error.WriteLine("Input or output error: " + (e is ProfileException ? e.Message : e.GetType().Name)); return 2; }
    catch (Exception) { Console.Error.WriteLine("Internal error; no success is reported."); return 3; }
}

static Dictionary<string, string> ParseFlags(string[] args, int offset, string[] allowed)
{
    var options = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var i = offset; i < args.Length; i++)
    {
        var flag = args[i];
        if (!allowed.Contains(flag) || options.ContainsKey(flag)) throw new ProfileException("Unknown or repeated flag.");
        if (flag == "--overwrite") { options[flag] = "true"; continue; }
        if (++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal)) throw new ProfileException("Missing flag value.");
        options[flag] = args[i];
    }
    return options;
}
static Task<byte[]> ReadBoundAsync(string path, CancellationToken ct) => ReadBoundedAsync(path, 2 * 1024 * 1024, ct);
static async Task<byte[]> ReadBoundedAsync(string path, int maxBytes, CancellationToken ct)
{
    var file = new FileInfo(path);
    if (file.Length is 0 || file.Length > maxBytes) throw new ProfileException("Input file size is outside the allowed range.");
    await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
    var buffer = new byte[file.Length];
    await stream.ReadExactlyAsync(buffer, ct);
    if (stream.ReadByte() != -1) throw new ProfileException("Input changed while reading.");
    return buffer;
}
static int Usage()
{
    Console.Error.WriteLine("Usage: scout validate|plan <profile.json> | run <profile.json> --allow-profile-digest <sha256> --out <report.json> [--samples 1..3] [--overwrite] | render <report.json> --format html|markdown --out <file> | diff <old.json> <new.json> --out <file>");
    return 2;
}
