using System.Security.Cryptography;
using System.Text;

namespace Scout.Privacy;

public sealed class Tokeniser : IDisposable
{
    private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
    public string Token(string category, string value)
    {
        var bytes = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(category + "\0" + value));
        return category + "_" + Convert.ToHexStringLower(bytes);
    }
    public void Dispose() => CryptographicOperations.ZeroMemory(key);
}
