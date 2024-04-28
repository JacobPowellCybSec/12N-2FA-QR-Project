using System;
using System.Text;
using System.Collections.Generic;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

public class QRGenerator
{
    private X509Certificate certificate;

    public QRGenerator(X509Certificate cert)
    {
        if (cert == null)
            throw new ArgumentNullException(nameof(cert), "Certificate cannot be null.");

        certificate = cert;
    }

    public string Generate12NData(Dictionary<string, string> fields)
    {
        StringBuilder encryptedDataBuilder = new StringBuilder();
        StringBuilder plainDataBuilder = new StringBuilder();

        // Get the certificate ID, which is used in the encryption process
        string certificateId = GetCertificateId(certificate);
        Console.WriteLine($"Using Certificate ID: {certificateId}");

        // Begin both data strings with the 12N standard header
        string header = "[)>" + (char)30 + "06" + (char)29 + "12N" + (char)31;
        encryptedDataBuilder.Append(header);
        plainDataBuilder.Append(header);

        // Append the Encryption Field Identifier (ZENC) for encrypted data
        string encryptionRecord = "ZENC" + certificateId + (char)31;
        encryptedDataBuilder.Append(encryptionRecord);

        // Process each field for both encrypted and plain data
        foreach (var field in fields)
        {
            string encryptedData = CryptoUtils.Encrypt(field.Value, certificate.GetPublicKey());
            encryptedDataBuilder.Append(field.Key + ":" + encryptedData + (char)31); // Unit Separator for encrypted
            plainDataBuilder.Append(field.Key + ":" + field.Value + (char)31); // Unit Separator for plain
        }

        // Append the End of Transmission character sequence
        encryptedDataBuilder.Append((char)30); // RS
        encryptedDataBuilder.Append((char)4);  // EOT
        plainDataBuilder.Append((char)30);     // RS
        plainDataBuilder.Append((char)4);      // EOT

        // Output the plain data version to the console for verification
        Console.WriteLine("Plain 12N Data: " + plainDataBuilder.ToString());

        Console.WriteLine("Encrypted 12N Data: " + encryptedDataBuilder.ToString());

        // Return only the encrypted data
        return encryptedDataBuilder.ToString();
    }

    public string GetCertificateId(X509Certificate certificate)
    {
        // Get the serial number from the certificate
        string serialNumber = certificate.SerialNumber.ToString();
        Console.WriteLine($"Certificate Serial Number: {serialNumber}");
        return serialNumber;
    }
}


