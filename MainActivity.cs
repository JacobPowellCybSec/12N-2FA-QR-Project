using Android.App;
using Android.OS;
using Android.Widget;
using ZXing.Mobile;
using ZXing;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System.IO;
using Android.Content;

namespace App15
{
    [Activity(Label = "@string/app_name", MainLauncher = true)]
    public class MainActivity : Activity
    {
        ImageView qrImage;
        ProgressBar activityIndicator;
        QRScanner qrScanner;
        private string certsPath;

        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            MobileBarcodeScanner.Initialize(Application);
            SetContentView(Resource.Layout.activity_main);
            qrImage = FindViewById<ImageView>(Resource.Id.qrImage);

            certsPath = Application.Context.GetExternalFilesDir(null).AbsolutePath;
            qrScanner = new QRScanner(this);

            Button scanQRButton = FindViewById<Button>(Resource.Id.scanQRButton);
            Button makeQRButton = FindViewById<Button>(Resource.Id.makeQRButton);

            scanQRButton.Click += async (sender, e) => await qrScanner.ScanQR();

            makeQRButton.Click += (sender, e) =>
            {
                string certFilePath = EnsureCertificateExists();
                if (!string.IsNullOrWhiteSpace(certFilePath))
                {
                    GenerateAndDisplayQRCode(certFilePath);
                }
                else
                {
                    Console.WriteLine("Certificate generation failed, cannot proceed with QR generation.");
                }
            };
        }

        private string EnsureCertificateExists()
        {
            CertificateGenerator certGenerator = new CertificateGenerator(Application.Context);
            string certFilePath = certGenerator.GenerateAndStoreCertificate("My Application");

            if (certFilePath != null)
            {
                Console.WriteLine("Certificate generated and stored successfully.");
                return Path.Combine(certsPath, certFilePath);
            }
            else
            {
                Console.WriteLine("Failed to generate a new certificate.");
                return null;
            }
        }

        private void GenerateAndDisplayQRCode(string certFilePath)
        {
            X509Certificate certificate = new CertificateGenerator(Application.Context).LoadCertificate(certFilePath);

            if (certificate != null)
            {
                QRGenerator qrGenerator = new QRGenerator(certificate);
                Dictionary<string, string> fields = new Dictionary<string, string>
                {
                    { "P065", "ABC123" },
                    { "B000", "ExampleName" }
                };

                string barcodeValue = qrGenerator.Generate12NData(fields);
                var barcodeWriter = new ZXing.Mobile.BarcodeWriter
                {
                    Format = ZXing.BarcodeFormat.QR_CODE,
                    Options = new ZXing.Common.EncodingOptions
                    {
                        Width = 600,
                        Height = 600
                    }
                };

                var barcodeBitmap = barcodeWriter.Write(barcodeValue);
                qrImage.SetImageBitmap(barcodeBitmap);
                qrImage.Visibility = Android.Views.ViewStates.Visible;
            }
            else
            {
                Console.WriteLine("Certificate loading failed, cannot proceed with QR generation.");
            }
        }
    }
}
