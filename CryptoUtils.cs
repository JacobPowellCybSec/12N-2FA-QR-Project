using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public static class CryptoUtils
{
    public static string Encrypt(string plainText, AsymmetricKeyParameter publicKey)
    {
        Console.WriteLine($"Pre-Encrypt Data: " + plainText);
        try
        {
            var engine = new Pkcs1Encoding(new RsaEngine());
            engine.Init(true, publicKey); // true for encryption
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBytes = engine.ProcessBlock(plainBytes, 0, plainBytes.Length);
            return Convert.ToBase64String(cipherBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Encryption failed: {ex.Message}");
            return null;
        }
    }

    public static string Decrypt(string cipherText, AsymmetricKeyParameter privateKey)
    {
        try
        {
            var engine = new Pkcs1Encoding(new RsaEngine());
            engine.Init(false, privateKey); // false for decryption
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            byte[] plainBytes = engine.ProcessBlock(cipherBytes, 0, cipherBytes.Length);
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption failed: {ex.Message}");
            return null;
        }
    }
}

