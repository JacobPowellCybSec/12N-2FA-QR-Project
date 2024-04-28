using Android.App;
using ZXing.Mobile;
using ZXing;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Android.Content;
using Android.Support.V4.App;
using Android.Support.V4.Content;
using Android.Content.PM;
using Android.App.Admin;

namespace App15
{
    public class QRScanner
    {
        private Activity activity;
        private MobileBarcodeScanner scanner;
        private string certsPath;
        private readonly string privateKeyPath;  // Path for the private key file

        private DatabaseHelper dbHelper;

        public QRScanner(Context context)
        {
            // Ensure context is not null
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context), "Context cannot be null.");
            }
            dbHelper = new DatabaseHelper(context);
            Console.WriteLine("DatabaseHelper has been initialized in QRScanner constructor.");
        }

        public QRScanner(Activity activity)
        {
            this.activity = activity ?? throw new ArgumentNullException(nameof(activity), "Activity cannot be null.");
            MobileBarcodeScanner.Initialize(activity.Application);
            scanner = new MobileBarcodeScanner();
            dbHelper = new DatabaseHelper(activity);  // Initialize with activity context
            Console.WriteLine("DatabaseHelper has been initialized with Activity context in QRScanner constructor.");

            Java.IO.File directory = activity.GetDir("certs", FileCreationMode.Private);
            certsPath = directory.AbsolutePath;
            privateKeyPath = Path.Combine(Android.OS.Environment.ExternalStorageDirectory.AbsolutePath, "Android", "data", "com.companyname.App15", "files", "private_key.pem");
        }

        public async Task ScanQR()
        {
            if (ContextCompat.CheckSelfPermission(activity, Android.Manifest.Permission.Camera) != Permission.Granted)
            {
                ActivityCompat.RequestPermissions(activity, new[] { Android.Manifest.Permission.Camera }, 0);
                Console.WriteLine("Requesting camera permission");
            }
            else
            {
                var options = new MobileBarcodeScanningOptions
                {
                    PossibleFormats = new List<BarcodeFormat> { BarcodeFormat.QR_CODE }
                };

                var result = await scanner.Scan(options);
                if (result != null)
                {
                    Console.WriteLine($"QR Code scanned: {result.Text}");
                    await ProcessScanResult(result.Text);
                }
                else
                {
                    Console.WriteLine("Scan cancelled or no QR Code detected");
                }
            }
        }

        private async Task ProcessScanResult(string scannedData)
        {
            try
            {
                Console.WriteLine($"Processing scan result: {scannedData}");

                if (scannedData.Contains("ZENC"))
                {
                    string certId = ExtractCertificateId(scannedData);
                    string encryptedData = ExtractEncryptedData(scannedData);
                    string decryptedData = DecryptDataWithCertificate(certId, encryptedData, dbHelper);
                    DisplayResult(decryptedData ?? "Failed to decrypt the QR Code.");
                }
                else if (Is12NQRCode(scannedData))
                {
                    // Handle specific "12N" QR codes, which are not encrypted
                    QRDecoder decoder = new QRDecoder();
                    var decodedData = decoder.Decode12NQRCode(scannedData);
                    var displayData = FormatDecodedData(decodedData);
                    DisplayResult("12N QR Code:\n" + displayData);
                }
                else
                {
                    // Handle regular QR codes
                    DisplayResult("Regular QR Code:\n" + scannedData);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing QR code: {ex.Message}");
                DisplayError($"Failed to process QR code: {ex.Message}");
            }
        }

        private string DecryptDataWithCertificate(string certId, string encryptedData, DatabaseHelper dbHelper)
        {
            // Log starting the decryption process
            Console.WriteLine("Starting decryption process...");

            // Check for null or empty encrypted data
            if (string.IsNullOrEmpty(encryptedData))
            {
                Console.WriteLine("Encrypted data is null or empty.");
                return null;
            }

            // Ensure the dbHelper is properly initialized
            if (dbHelper == null)
            {
                Console.WriteLine("DatabaseHelper instance is not initialized.");
                return null;
            }

            // Check if the private key file exists
            if (!File.Exists(privateKeyPath))
            {
                Console.WriteLine($"Private key file not found at path: {privateKeyPath}");
                return null;
            }

            AsymmetricKeyParameter privateKey = null;

            try
            {
                // Load the private key
                privateKey = LoadPrivateKey(privateKeyPath);
                if (privateKey == null)
                {
                    Console.WriteLine("Failed to load the private key.");
                    return null;
                }
                Console.WriteLine("Private key loaded successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading private key: {ex.Message}");
                return null;
            }

            try
            {
                // The encrypted data should end with RS and potentially EOT (Record Separator and End Of Transmission)
                int endOfDataIndex = encryptedData.LastIndexOf((char)30); // Find last occurrence of RS
                if (endOfDataIndex != -1)
                {
                    encryptedData = encryptedData.Substring(0, endOfDataIndex); // Strip off the RS and EOT
                }

                var fields = encryptedData.Split((char)31); // Split the data using US (Unit Separator)
                StringBuilder decryptedDataBuilder = new StringBuilder();
                bool p065DataMatch = false;

                foreach (var field in fields)
                {
                    int colonIndex = field.IndexOf(':');
                    if (colonIndex == -1) continue; // Skip if no colon found, indicating an invalid field

                    string fieldId = field.Substring(0, colonIndex);
                    string base64Data = field.Substring(colonIndex + 1);

                    Console.WriteLine($"Field: {fieldId}, Encoded Data: {base64Data}");

                    string decryptedData = CryptoUtils.Decrypt(base64Data, privateKey); // Assume CryptoUtils.Decrypt handles null inputs gracefully
                    if (string.IsNullOrEmpty(decryptedData))
                    {
                        Console.WriteLine($"Error decrypting field {fieldId}");
                        continue;
                    }

                    decryptedData = decryptedData.Trim(); // Trim to remove any extraneous whitespace
                    Console.WriteLine($"Field: {fieldId}, Decrypted Data: {decryptedData}");
                    decryptedDataBuilder.AppendLine($"{fieldId}: {decryptedData}");

                    // Specifically check for the P065 field and its presence in the database
                    if (fieldId.Equals("P065"))
                    {
                        Console.WriteLine("Checking database for P065 data...");
                        if (dbHelper.CodeExists(decryptedData))
                        {
                            p065DataMatch = true;
                            Console.WriteLine("P065 data verified against the database.");
                        }
                        else
                        {
                            Console.WriteLine("No matching P065 data found in the database.");
                        }
                    }
                }

                if (!p065DataMatch)
                {
                    Console.WriteLine("Decrypted P065 data does not match any entry in the database.");
                }

                return decryptedDataBuilder.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during decryption or database check: {ex.Message}");
                return null;
            }
        }

        private string ExtractCertificateId(string data)
        {
            // Locate "ZENC" and extract the certificate ID following it
            int startIndex = data.IndexOf("ZENC");
            if (startIndex != -1)
            {
                int unitSeparatorIndex = data.IndexOf((char)31, startIndex);
                if (unitSeparatorIndex != -1)
                {
                    string certificateId = data.Substring(startIndex + 4, unitSeparatorIndex - startIndex - 4);
                    return certificateId;
                }
            }
            return null;  // If no ZENC or malformatted, return null
        }

        private string ExtractEncryptedData(string data)
        {
            // This method should extract encrypted data after the certificate ID
            int zencEndIndex = data.IndexOf((char)31, data.IndexOf("ZENC")) + 1;
            if (zencEndIndex > 0 && zencEndIndex < data.Length)
            {
                return data.Substring(zencEndIndex);  // Extract everything after ZENC tag
            }
            return null;
        }

        private AsymmetricKeyParameter LoadPrivateKey(string filePath)
        {
            try
            {
                using (StreamReader reader = new StreamReader(filePath))
                {
                    PemReader pemReader = new PemReader(reader);
                    object keyObject = pemReader.ReadObject();
                    Console.WriteLine("Key read from file successfully.");

                    if (keyObject is AsymmetricCipherKeyPair keyPair)
                    {
                        Console.WriteLine("Key is part of a key pair.");
                        return keyPair.Private;
                    }
                    else if (keyObject is AsymmetricKeyParameter keyParam)
                    {
                        Console.WriteLine("Key is a single asymmetric key parameter.");
                        return keyParam;
                    }
                    else
                    {
                        Console.WriteLine("No recognizable key format was found.");
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to read private key from file: {ex.Message}");
                return null;
            }
        }

        private void DisplayResult(string message)
        {
            activity.RunOnUiThread(() =>
            {
                new AlertDialog.Builder(activity)
                    .SetTitle("Scanned QR Code")
                    .SetMessage(message)
                    .SetPositiveButton("OK", (sender, args) => { /* Intentionally left blank */ })
                    .Show();
            });
        }

        private void DisplayError(string errorMessage)
        {
            activity.RunOnUiThread(() =>
            {
                new AlertDialog.Builder(activity)
                    .SetTitle("Error")
                    .SetMessage(errorMessage)
                    .SetPositiveButton("OK", (sender, args) => { /* Intentionally left blank */ })
                    .Show();
            });
        }

       private string FormatDecodedData(Dictionary<string, string> decodedData)
        {
            StringBuilder builder = new StringBuilder();
            foreach (var pair in decodedData)
            {
                builder.AppendLine($"{pair.Key}: {pair.Value}");
            }
            return builder.ToString();
        }

        private bool Is12NQRCode(string data)
        {
            string headerPattern = Regex.Escape("[)>") + Regex.Escape(((char)30).ToString()) + "06" + Regex.Escape(((char)29).ToString()) + "12N";
            string trailerPattern = Regex.Escape(((char)30).ToString()) + Regex.Escape(((char)4).ToString());

            bool is12N = Regex.IsMatch(data, headerPattern) && Regex.IsMatch(data, trailerPattern);
            Console.WriteLine($"Is12NQRCode check: {is12N}");
            return is12N;
        }
    }
}
