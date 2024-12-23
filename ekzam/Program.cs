using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CardProcessor
{
    // Handles configuration constants
    public static class Config
    {
        public static readonly byte[] Key = new byte[32] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        public static readonly byte[] IV = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        public static readonly byte[] Salt = new byte[16] { 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
    }

    // Handles encryption and decryption logic
    public class CryptoService
    {
        public string Encrypt(string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Config.Key;
                aes.IV = Config.IV;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        byte[] saltedPlainBytes = AddSalt(plainBytes);
                        cs.Write(saltedPlainBytes, 0, saltedPlainBytes.Length);
                        cs.FlushFinalBlock();
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public string Decrypt(string cipherText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Config.Key;
                aes.IV = Config.IV;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (MemoryStream output = new MemoryStream())
                {
                    cs.CopyTo(output);
                    byte[] saltedPlainBytes = output.ToArray();
                    return Encoding.UTF8.GetString(RemoveSalt(saltedPlainBytes));
                }
            }
        }

        private byte[] AddSalt(byte[] plainBytes)
        {
            byte[] saltedBytes = new byte[plainBytes.Length + Config.Salt.Length];
            Buffer.BlockCopy(Config.Salt, 0, saltedBytes, 0, Config.Salt.Length);
            Buffer.BlockCopy(plainBytes, 0, saltedBytes, Config.Salt.Length, plainBytes.Length);
            return saltedBytes;
        }

        private byte[] RemoveSalt(byte[] saltedBytes)
        {
            byte[] plainBytes = new byte[saltedBytes.Length - Config.Salt.Length];
            Buffer.BlockCopy(saltedBytes, Config.Salt.Length, plainBytes, 0, plainBytes.Length);
            return plainBytes;
        }
    }

    // Handles hashing logic
    public class HashService
    {
        public string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                foreach (byte b in bytes)
                {
                    builder.Append(b.ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }

    // Handles JSON processing logic
    public class CardProcessorService
    {
        private readonly CryptoService _cryptoService;
        private readonly HashService _hashService;

        public CardProcessorService(CryptoService cryptoService, HashService hashService)
        {
            _cryptoService = cryptoService;
            _hashService = hashService;
        }

        public JObject ProcessCards(string jsonData)
        {
            JObject jsonObject = JObject.Parse(jsonData);

            foreach (var card in jsonObject["cards"])
            {
                string cvc = card["cvc"].ToString();
                card["cvc"] = _hashService.ComputeSha256Hash(cvc);

                card["name"] = _cryptoService.Encrypt(card["name"].ToString());
                card["family"] = _cryptoService.Encrypt(card["family"].ToString());
                card["month"] = _cryptoService.Encrypt(card["month"].ToString());
                card["year"] = _cryptoService.Encrypt(card["year"].ToString());
                card["number"] = _cryptoService.Encrypt(card["number"].ToString());
            }

            return jsonObject;
        }

        public JObject DecryptCards(string jsonData)
        {
            JObject jsonObject = JObject.Parse(jsonData);

            foreach (var card in jsonObject["cards"])
            {
                card["name"] = _cryptoService.Decrypt(card["name"].ToString());
                card["family"] = _cryptoService.Decrypt(card["family"].ToString());
                card["month"] = _cryptoService.Decrypt(card["month"].ToString());
                card["year"] = _cryptoService.Decrypt(card["year"].ToString());
                card["number"] = _cryptoService.Decrypt(card["number"].ToString());
            }

            return jsonObject;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            string inputFilePath = "Card.json";
            string outputFilePath = "ProcessedCards.json";

            if (!File.Exists(inputFilePath))
            {
                Console.WriteLine("Input file not found!");
                return;
            }

            string jsonData = File.ReadAllText(inputFilePath);

            var cryptoService = new CryptoService();
            var hashService = new HashService();
            var cardProcessorService = new CardProcessorService(cryptoService, hashService);

            JObject processedData = cardProcessorService.ProcessCards(jsonData);
            File.WriteAllText(outputFilePath, processedData.ToString(Formatting.Indented));
            Console.WriteLine("Processing complete. Encrypted data saved to " + outputFilePath);

            bool running = true;
            while (running)
            {
                Console.WriteLine("Options:");
                Console.WriteLine("1: Display encrypted data");
                Console.WriteLine("2: Decrypt and display data");
                Console.WriteLine("3: Display salt, IV, and key");
                Console.WriteLine("4: Exit");

                if (!int.TryParse(Console.ReadLine(), out int choice))
                {
                    Console.WriteLine("Invalid input. Please enter a number.");
                    continue;
                }

                switch (choice)
                {
                    case 1:
                        Console.WriteLine("Encrypted Data:");
                        Console.WriteLine(File.ReadAllText(outputFilePath));
                        break;
                    case 2:
                        string encryptedData = File.ReadAllText(outputFilePath);
                        JObject decryptedData = cardProcessorService.DecryptCards(encryptedData);
                        Console.WriteLine("Decrypted Data:");
                        Console.WriteLine(decryptedData.ToString(Formatting.Indented));
                        break;
                    case 3:
                        Console.WriteLine("Salt, IV, and Key:");
                        Console.WriteLine("Key: " + BitConverter.ToString(Config.Key).Replace("-", " "));
                        Console.WriteLine("IV: " + BitConverter.ToString(Config.IV).Replace("-", " "));
                        Console.WriteLine("Salt: " + BitConverter.ToString(Config.Salt).Replace("-", " "));
                        break;
                    case 4:
                        Console.WriteLine("Exiting...");
                        running = false;
                        break;
                    default:
                        Console.WriteLine("Invalid option. Please try again.");
                        break;
                }
            }
        }
    }
}
