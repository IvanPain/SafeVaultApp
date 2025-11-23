using System.Security.Cryptography;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace SafeVault.Web.Security
{
    public class Argon2PasswordHasher : IPasswordHasher<ApplicationUser>
    {
        // Tuned parameters for server performance and security (adjust to your infra)
        private const int SaltSize = 16;
        private const int HashSize = 32;
        private const int Iterations = 3;
        private const int MemoryKb = 64 * 1024; // 64 MB
        private const int Parallelism = 2;

        public string HashPassword(ApplicationUser user, string password)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var hash = ComputeArgon2id(password, salt);

            // Format: $argon2id$v=19$m=65536,t=3,p=2$<base64salt>$<base64hash>
            return $"$argon2id$v=19$m={MemoryKb},t={Iterations},p={Parallelism}$" +
                   $"{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        }

        public PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword, string providedPassword)
        {
            try
            {
                var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
                // parts: ["argon2id","v=19","m=65536,t=3,p=2","<salt>","<hash>"]
                var salt = Convert.FromBase64String(parts[3]);
                var expected = Convert.FromBase64String(parts[4]);
                var actual = ComputeArgon2id(providedPassword, salt);

                return CryptographicOperations.FixedTimeEquals(expected, actual)
                    ? PasswordVerificationResult.Success
                    : PasswordVerificationResult.Failed;
            }
            catch
            {
                return PasswordVerificationResult.Failed;
            }
        }

        private static byte[] ComputeArgon2id(string password, byte[] salt)
        {
            var argon = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                Iterations = Iterations,
                MemorySize = MemoryKb,
                DegreeOfParallelism = Parallelism
            };
            return argon.GetBytes(HashSize);
        }
    }
}
