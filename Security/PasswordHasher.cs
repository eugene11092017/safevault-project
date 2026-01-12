using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace SafeVault.Security
{
    public static class PasswordHasher
    {
        private const int SaltSize = 16; // 128 bits
        private const int HashSize = 32; // 256 bits
        private const int Iterations = 100000;

        // Hash password with salt using PBKDF2
        public static (string Hash, string Salt) HashPassword(string password)
        {
            // Generate a random salt
            byte[] saltBytes = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }

            // Derive a 256-bit subkey (use HMACSHA256 with 100,000 iterations)
            byte[] hashBytes = KeyDerivation.Pbkdf2(
                password: password,
                salt: saltBytes,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: Iterations,
                numBytesRequested: HashSize);

            string hash = Convert.ToBase64String(hashBytes);
            string salt = Convert.ToBase64String(saltBytes);

            return (hash, salt);
        }

        // Verify password against stored hash and salt
        public static bool VerifyPassword(string password, string storedHash, string storedSalt)
        {
            try
            {
                byte[] saltBytes = Convert.FromBase64String(storedSalt);
                byte[] storedHashBytes = Convert.FromBase64String(storedHash);

                // Hash the provided password with the stored salt
                byte[] hashBytes = KeyDerivation.Pbkdf2(
                    password: password,
                    salt: saltBytes,
                    prf: KeyDerivationPrf.HMACSHA256,
                    iterationCount: Iterations,
                    numBytesRequested: HashSize);

                // Compare the hashes securely (constant-time comparison)
                return CryptographicOperations.FixedTimeEquals(hashBytes, storedHashBytes);
            }
            catch
            {
                return false;
            }
        }

        // Generate a secure random token
        public static string GenerateSecureToken(int length = 32)
        {
            byte[] tokenBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenBytes);
            }
            return Convert.ToBase64String(tokenBytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");
        }
    }
}