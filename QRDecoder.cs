using System;
using System.Collections.Generic;

namespace App15
{
    public class QRDecoder
    {
        public static readonly char EndOfTransmission = (char)4;
        public static readonly char GroupSeparator = (char)29;
        public static readonly char RecordSeparator = (char)30;
        public static readonly char UnitSeparator = (char)31;

        public static readonly string Header = "[)>" + RecordSeparator + "06" + GroupSeparator + "12N" + UnitSeparator;
        public static readonly string Trailer = RecordSeparator.ToString() + EndOfTransmission;

        public Dictionary<string, string> Decode12NQRCode(string qrData)
        {
            if (!qrData.StartsWith(Header) || !qrData.EndsWith(Trailer))
            {
                throw new ArgumentException("QR code data does not conform to the 12N standard.");
            }

            int contentStartIndex = Header.Length;
            int contentEndIndex = qrData.Length - Trailer.Length;

            string content = qrData.Substring(contentStartIndex, contentEndIndex - contentStartIndex);
            string[] records = content.Split(UnitSeparator, StringSplitOptions.RemoveEmptyEntries); // Use StringSplitOptions to avoid empty entries
            Dictionary<string, string> dataRecords = new Dictionary<string, string>();

            foreach (var record in records)
            {
                // Assuming FI is always 4 characters and directly followed by user data
                if (record.Length < 4) // Check if the record is too short to contain an FI and user data
                {
                    throw new ArgumentException("Invalid data record in QR code data.");
                }

                string fi = record.Substring(0, 4);
                string userData = record.Length > 4 ? record.Substring(4) : string.Empty;

                // Optionally handle quoted data or file separators here

                dataRecords[fi] = userData;
            }

            return dataRecords;
        }
    }
}
