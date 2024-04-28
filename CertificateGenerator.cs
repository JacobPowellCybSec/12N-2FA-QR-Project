using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Operators;
using System;
using System.IO;
using Android.Content;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using System.Text;

public class CertificateGenerator
{
    public string PublicKeyPath { get; private set; }
    public string PrivateKeyPath { get; private set; }
    public string CertificatePath { get; private set; }

    private AsymmetricCipherKeyPair keyPair;
    private readonly string certsPath;

    public CertificateGenerator(Context context)
    {
        certsPath = context.GetExternalFilesDir(null)?.AbsolutePath;
        if (string.IsNullOrEmpty(certsPath))
        {
            throw new InvalidOperationException("Failed to get the external files directory.");
        }

        //TestEncryptionDecryption();
    }

    public string GenerateAndStoreCertificate(string subjectName)
    {
        try
        {
            keyPair = GenerateKeyPair();
            X509Certificate certificate = GenerateSelfSignedCertificate(keyPair, subjectName);
            string serialNumber = certificate.SerialNumber.ToString();
            string certificateFilePath = Path.Combine(certsPath, $"{serialNumber}.pem");

            SaveCertificateToPemFile(certificate, certificateFilePath);
            SaveKeyToPemFile(keyPair.Public, Path.Combine(certsPath, "public_key.pem"));
            SaveKeyToPemFile(keyPair.Private, Path.Combine(certsPath, "private_key.pem"));

            UpdatePaths(serialNumber);
            DisplayCertificateInfo(certificate);

            return serialNumber;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error generating and storing certificate: {ex.Message}");
            return null;
        }
    }

    private AsymmetricCipherKeyPair GenerateKeyPair()
    {
        RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        Console.WriteLine("Key Pair Generated:");
        Console.WriteLine("Public Key: " + ConvertKeyToString(keyPair.Public));
        Console.WriteLine("Private Key: " + ConvertKeyToString(keyPair.Private));

        return keyPair;
    }

    private X509Certificate GenerateSelfSignedCertificate(AsymmetricCipherKeyPair keyPair, string subjectName)
    {
        var serialNumber = new BigInteger(140, new SecureRandom()).Abs();
        var issuer = new X509Name($"CN={subjectName}");
        var notBefore = DateTime.UtcNow.Date;
        var notAfter = notBefore.AddYears(2);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serialNumber);
        certGen.SetIssuerDN(issuer);
        certGen.SetSubjectDN(issuer);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);
        certGen.SetPublicKey(keyPair.Public);

        ISignatureFactory sigFactory = new Asn1SignatureFactory("SHA256WithRSAEncryption", keyPair.Private);
        X509Certificate certificate = certGen.Generate(sigFactory);
        return certificate;
    }

    private string ConvertKeyToString(AsymmetricKeyParameter key)
    {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(key);
        pemWriter.Writer.Flush();
        return writer.ToString();
    }

    private void SaveCertificateToPemFile(X509Certificate certificate, string filePath)
    {
        using (var writer = new StreamWriter(filePath))
        {
            new PemWriter(writer).WriteObject(certificate);
            writer.Flush();
        }
    }

    private void SaveKeyToPemFile(AsymmetricKeyParameter key, string filePath)
    {
        using (var writer = new StreamWriter(filePath))
        {
            new PemWriter(writer).WriteObject(key);
            writer.Flush();
        }
    }

    private void UpdatePaths(string serialNumber)
    {
        PublicKeyPath = Path.Combine(certsPath, "public_key.pem");
        PrivateKeyPath = Path.Combine(certsPath, "private_key.pem");
        CertificatePath = Path.Combine(certsPath, $"{serialNumber}.pem");
    }

    private void DisplayCertificateInfo(X509Certificate certificate)
    {
        Console.WriteLine("Certificate Information:");
        Console.WriteLine($"Subject Name: {certificate.SubjectDN}");
        Console.WriteLine($"Issuer Name: {certificate.IssuerDN}");
        Console.WriteLine($"Serial Number: {certificate.SerialNumber}");
        Console.WriteLine($"Valid From: {certificate.NotBefore}");
        Console.WriteLine($"Valid Until: {certificate.NotAfter}");
        Console.WriteLine($"Public Key stored at: {PublicKeyPath}");
        Console.WriteLine($"Private Key stored at: {PrivateKeyPath}");
        Console.WriteLine($"Certificate stored at: {CertificatePath}");
    }

    public X509Certificate LoadCertificate(string certFileName)
    {
        // Ensure the .pem extension is included in the filename
        if (!certFileName.EndsWith(".pem"))
        {
            certFileName += ".pem";
        }

        string filePath = Path.Combine(certsPath, certFileName);
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Certificate file not found: {filePath}");
            return null;
        }

        try
        {
            using (var reader = File.OpenText(filePath))
            {
                PemReader pemReader = new PemReader(reader);
                return pemReader.ReadObject() as X509Certificate;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to load certificate from {filePath}: {ex.Message}");
            return null;
        }
    }

    // Method to test encryption and decryption
    public void TestEncryptionDecryption()
    {
        string testMessage = "Hello, this is a test!";
        Console.WriteLine("Testing Encryption and Decryption Process:");
        Console.WriteLine($"Original Message: {testMessage}");

        if (keyPair == null || keyPair.Public == null || keyPair.Private == null)
        {
            Console.WriteLine("Key pair is not initialized. Generating key pair.");
            GenerateAndStoreCertificate("Test Subject"); // Optionally pass a subject name
        }

        // Encrypt the message
        string encryptedMessage = Encrypt(testMessage, keyPair.Public);
        Console.WriteLine($"Encrypted Message: {encryptedMessage}");

        // Decrypt the message
        string decryptedMessage = Decrypt(encryptedMessage, keyPair.Private);
        Console.WriteLine($"Decrypted Message: {decryptedMessage}");

        // Check if the original and decrypted messages match
        Console.WriteLine("Test Result: " + (testMessage == decryptedMessage ? "Success" : "Failure"));
    }

    private string Encrypt(string plainText, AsymmetricKeyParameter publicKey)
    {
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

    private string Decrypt(string cipherText, AsymmetricKeyParameter privateKey)
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
