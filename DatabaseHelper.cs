using Android.Content;
using Android.Database.Sqlite;
using Android.Icu.Text;
using System;

namespace App15
{
    public class DatabaseHelper : SQLiteOpenHelper
    {
        private const string DatabaseName = "secureCodesDatabase.db";
        private const int DatabaseVersion = 1;
        public const string TableSecureCodes = "secure_codes";
        public const string ColumnData = "data"; // This stores the data part of the "P065" field

        private const string CreateTableSecureCodes =
            $"CREATE TABLE {TableSecureCodes} (" +
            $"{ColumnData} TEXT PRIMARY KEY);";

        public DatabaseHelper(Context context) : base(context, DatabaseName, null, DatabaseVersion)
        {
            Console.WriteLine("DatabaseHelper instance created.");
        }

        public override void OnCreate(SQLiteDatabase db)
        {
            Console.WriteLine("Creating database table.");
            db.ExecSQL(CreateTableSecureCodes);
            Console.WriteLine("Table created successfully.");

            // Insert a test entry with code "ABC123"
            Console.WriteLine("Inserting initial test code.");
            InsertCode(db, "ABC123");
            Console.WriteLine("Test code inserted.");
        }

        public override void OnUpgrade(SQLiteDatabase db, int oldVersion, int newVersion)
        {
            // This method can log database upgrade process
            Console.WriteLine($"Upgrading database from version {oldVersion} to {newVersion}.");
            // Add database upgrade logic here
            Console.WriteLine("Database upgrade complete.");
        }

        private void InsertCode(SQLiteDatabase db, string data)
        {
            Console.WriteLine($"Inserting code: {data}");
            ContentValues values = new ContentValues();
            values.Put(ColumnData, data);
            db.Insert(TableSecureCodes, null, values);
            Console.WriteLine("Code inserted successfully.");
        }

        public void InsertCode(string data)
        {
            Console.WriteLine($"Preparing to insert code: {data}");
            using (var db = WritableDatabase)
            {
                InsertCode(db, data);
            }
            Console.WriteLine("Code insertion complete.");
        }

        public bool CodeExists(string data)
        {
            using (var db = ReadableDatabase)
            {
                string[] columns = { ColumnData };
                string selection = $"{ColumnData} = ?";
                string[] selectionArgs = { data };
                using (var cursor = db.Query(TableSecureCodes, columns, selection, selectionArgs, null, null, null))
                {
                    if (cursor != null && cursor.MoveToFirst())
                    {
                        Console.WriteLine($"Code '{data}' exists in the database.");
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"Code '{data}' does not exist in the database.");
                        return false;
                    }
                }
            }
        }

        public void LogAllCodes()
        {
            Console.WriteLine("Querying all codes in database.");
            using (var db = ReadableDatabase)
            {
                string[] columns = { ColumnData };
                using (var cursor = db.Query(TableSecureCodes, columns, null, null, null, null, null))
                {
                    if (cursor.MoveToFirst())
                    {
                        do
                        {
                            string data = cursor.GetString(cursor.GetColumnIndexOrThrow(ColumnData));
                            Console.WriteLine($"Database contains code: {data}");
                        } while (cursor.MoveToNext());
                    }
                    else
                    {
                        Console.WriteLine("Database is empty.");
                    }
                }
            }
            Console.WriteLine("Completed querying all codes.");
        }
    }
}