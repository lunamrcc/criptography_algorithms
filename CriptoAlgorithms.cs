using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace ConsoleApplication
{
    class CriptoAlgorithms
    {
        #region TestCases
        static string[] EncryptionVectors()
        {
            string[] vectors = new string[8];
            vectors[0] = "0000000000000000";
            vectors[1] = "C02FAFFEC989D1FC";
            vectors[2] = "4615AA1D33E72F10";
            vectors[3] = "EFAE2347FDDEFA73";
            vectors[4] = "25610288924511C2";
            vectors[5] = "17A6FDC0827E427A";
            vectors[6] = "5495C6ABF1E5DF51";
            vectors[7] = "8CA64DE9C1B123A5";

            return vectors;     
        }        
        static string[] HashVectors()
        {
            string[] vectors = new string[8];
            vectors[0] = "";
            vectors[1] = "a";
            vectors[2] = "abc";
            vectors[3] = "message digest";
            vectors[4] = "abcdefghijklmnopqrstuvwxyz";
            vectors[5] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            vectors[6] = "A...Za...z0...9";
            vectors[7] = "1234567890";

            return vectors;                
        }

        #endregion

        #region RC4
        #endregion

        #region DES

        static byte[] DES_Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            // Checar parámetros.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Initialization Vector");

            // Declarar arreglo de bytes encriptados.
            byte[] encrypted;

            // Crear objeto AES con la Llave y Vector de Inicialización.
            using (DES desAlg = DES.Create())
            {
                desAlg.Key = Key;
                desAlg.IV = IV;

                // Crear Encryptador para el Stream.
                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

                // Crear Stream.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Escribir toda la información en el stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Regresar el mensaje encriptado.
            return encrypted;

        }
        
        static string DES_Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Checar parámetros.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Initialization Vector");

            // Declarar string texto desencriptado.
            string plaintext = null;

            // Crear objeto AES con la Llave y Vector de Inicialización.
            using (DES desAlg = DES.Create())
            {
                desAlg.Key = Key;
                desAlg.IV = IV;

                // Crear Desencriptador para el Stream.
                ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV);

                // Crear Stream.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Leer bytes desencriptados del Stream.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            // Regresar el mensaje desencriptado
            return plaintext;

        }

        #endregion

        #region AES (Rijndael)

        static byte[] AES_Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            // Checar parámetros.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Initialization Vector");

            // Declarar arreglo de bytes encriptados.
            byte[] encrypted;

            // Crear objeto AES con la Llave y Vector de Inicialización.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Crear Encryptador para el Stream.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Crear Stream.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Escribir toda la información en el stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Regresar el mensaje encriptado.
            return encrypted;

        }
        
        static string AES_Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Checar parámetros.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Initialization Vector");

            // Declarar string texto desencriptado.
            string plaintext = null;

            // Crear objeto AES con la Llave y Vector de Inicialización.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Crear Desencriptador para el Stream.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Crear Stream.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Leer bytes desencriptados del Stream.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            // Regresar el mensaje desencriptado
            return plaintext;

        }

        #endregion

        #region MD5

        static string MD5_GenerateHash(MD5 md5Hash, string input)
        {

            // Convertir el string a byte[] y generar hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Crear StringBuilder para crear string de bytes.
            StringBuilder sBuilder = new StringBuilder();

            // Recorrer byte[] y transformarlo en string hexadecimal.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Regresar hash hexadecimal
            return sBuilder.ToString();
        }
        
        static bool MD5_VerifyHash(MD5 md5Hash, string input, string hash)
        {
            // Hash el input
            string hashOfInput = MD5_GenerateHash(md5Hash, input);

            // Crear StringComparer para comparar los hash
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        #endregion
        
        #region SHA-1

        static string SHA1_GenerateHash(SHA1 shaHash, string input)
        {

            // Convertir el string a byte[] y generar hash.
            byte[] data = shaHash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Crear StringBuilder para crear string de bytes.
            StringBuilder sBuilder = new StringBuilder();

            // Recorrer byte[] y transformarlo en string hexadecimal.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Regresar hash hexadecimal
            return sBuilder.ToString();
        }

        static bool SHA1_VerifyHash(SHA1 shaHash, string input, string hash)
        {
            // Hash el input
            string hashOfInput = SHA1_GenerateHash(shaHash, input);

            // Crear StringComparer para comparar los hash
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        #endregion
        
        #region SHA-256

        static string SHA256_GenerateHash(SHA256 sha256Hash, string input)
        {

            // Convertir el string a byte[] y generar hash.
            byte[] data = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Crear StringBuilder para crear string de bytes.
            StringBuilder sBuilder = new StringBuilder();

            // Recorrer byte[] y transformarlo en string hexadecimal.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Regresar hash hexadecimal
            return sBuilder.ToString();
        }

        static bool SHA256_VerifyHash(SHA256 sha256Hash, string input, string hash)
        {
            // Hash el input
            string hashOfInput = SHA256_GenerateHash(sha256Hash, input);

            // Crear StringComparer para comparar los hash
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        #endregion

        #region RSA-OAEP
        #endregion

        #region RSA-PSS

        public static byte[] RSAPSS_GenerateSignature(byte[] DataToSign, RSAParameters Key)
    {
        try
        {   
            // Crear nueva Instacia RSA             
            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

            RSAalg.ImportParameters(Key);

            // Firmar la información 
            return RSAalg.SignData(DataToSign, new SHA256CryptoServiceProvider());
        }
        catch(CryptographicException e)
        {
            Console.WriteLine(e.Message);

            return null;
        }
    }

        public static bool RSAPSS_VerifySignatura(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
    {
        try
        {
            // Crear nueva Instacia RSA  
            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

            RSAalg.ImportParameters(Key);

            // Verificar la firma
            return RSAalg.VerifyData(DataToVerify, new SHA256CryptoServiceProvider(), SignedData); 

        }
        catch(CryptographicException e)
        {
            Console.WriteLine(e.Message);

            return false;
        }
    }
        
        #endregion
        
        static string ByteArrayToString(byte[] bA)
        {
            return BitConverter.ToString(bA).Replace("-","");
        }

        static void Main(string[] args)
        {
            int opc;
            string[] testVectors = EncryptionVectors();
            string[] hashVectors = HashVectors();
            int j = 0;
            List<byte[]> byteArray =  new List<byte[]>();            
            List<string> stringArray =  new List<string>();
            byte[] signedData;
            // Create a UnicodeEncoder to convert between byte array and string.
            ASCIIEncoding ByteConverter = new ASCIIEncoding();

            Console.WriteLine("Cryptography"); 
            Console.WriteLine("1. RC4");
            Console.WriteLine("2. DES");
            Console.WriteLine("3. AES (Rijndael)");
            Console.WriteLine("4. MD5");
            Console.WriteLine("5. SHA1");
            Console.WriteLine("6. SHA256");
            Console.WriteLine("7. RSA-OAEP");
            Console.WriteLine("8. RSA-PSS");
            Console.WriteLine("9. DSA");
            Console.WriteLine("Type the number of the algorithm you want to test: "); 
            opc = Convert.ToInt32(Console.ReadLine());

            Console.WriteLine("Type the number of times you want to test the algorithm: "); 
            int times = Convert.ToInt32(Console.ReadLine());

            var watch = System.Diagnostics.Stopwatch.StartNew();

            switch(opc)
            {
                case 1:
                break;

                // DES
                case 2: 
                    using (DES myDES = DES.Create())
                    {
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0; 
                            
                            // Encrypt the string to an array of bytes.
                            byte[] encrypted = DES_Encrypt(testVectors[j], myDES.Key, myDES.IV);
                            byteArray.Add(encrypted);

                            j++;
                        }

                        j = 0;
                        watch.Stop();
                        Console.WriteLine("DES Encryption: " + watch.ElapsedMilliseconds);

                        watch = System.Diagnostics.Stopwatch.StartNew();   
                        foreach (byte[] encrypted in byteArray)
                        {
                            // Decrypt the bytes to a string.
                            DES_Decrypt(encrypted, myDES.Key, myDES.IV);
                        }                       

                        watch.Stop();
                        Console.WriteLine("DES Decryption: " + watch.ElapsedMilliseconds);
                    }
                break;

                // AES
                case 3: 
                    using (Aes myAES = Aes.Create())
                    {
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0; 
                            
                            // Encrypt the string to an array of bytes.
                            byte[] encrypted = AES_Encrypt(testVectors[j], myAES.Key, myAES.IV);
                            byteArray.Add(encrypted);

                            j++;
                        }

                        j = 0;
                        watch.Stop();
                        Console.WriteLine("AES Encryption: " + watch.ElapsedMilliseconds);

                        watch = System.Diagnostics.Stopwatch.StartNew();   
                        foreach (byte[] encrypted in byteArray)
                        {
                            // Decrypt the bytes to a string.
                            AES_Decrypt(encrypted, myAES.Key, myAES.IV);
                        }                       

                        watch.Stop();
                        Console.WriteLine("AES Decryption: " + watch.ElapsedMilliseconds);
                    }
                break;  

                // MD5  
                case 4:
                    using (MD5 md5Hash = MD5.Create())
                    {
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0;                
                            
                            string hash = MD5_GenerateHash(md5Hash, testVectors[j]);
                            stringArray.Add(hash);                        
                                    
                        j++;

                        }

                        j = 0;
                        watch.Stop();
                        Console.WriteLine("MD5 Encryption: " + watch.ElapsedMilliseconds);

                        watch = System.Diagnostics.Stopwatch.StartNew(); 
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0; 

                            MD5_VerifyHash(md5Hash, testVectors[j], stringArray[i]);
                        }

                        watch.Stop();
                        Console.WriteLine("MD5 Decryption: " + watch.ElapsedMilliseconds);
                    }
                break;

                // SHA 1
                case 5:
                    using (SHA1 shaHash = SHA1.Create())
                    {
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0;                
                            
                            string hash = SHA1_GenerateHash(shaHash, testVectors[j]);
                            stringArray.Add(hash);                        
                                    
                        j++;

                        }

                        j = 0;
                        watch.Stop();
                        Console.WriteLine("SHA1 Encryption: " + watch.ElapsedMilliseconds);

                        watch = System.Diagnostics.Stopwatch.StartNew(); 
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0; 

                            SHA1_VerifyHash(shaHash, testVectors[j], stringArray[i]);
                        }

                        watch.Stop();
                        Console.WriteLine("SHA1 Decryption: " + watch.ElapsedMilliseconds);
                    }
                break;

                // SHA 256
                case 6:
                    using (SHA256 shaHash = SHA256.Create())
                    {
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0;                
                                
                            string hash = SHA256_GenerateHash(shaHash, testVectors[j]);
                            stringArray.Add(hash);                        
                                        
                            j++;
                        }

                        j = 0;
                        watch.Stop();
                        Console.WriteLine("SHA256 Encryption: " + watch.ElapsedMilliseconds);

                        watch = System.Diagnostics.Stopwatch.StartNew(); 
                        for(int i = 0; i < times; i ++)
                        {
                            if(j % 8 == 0) j = 0; 

                            SHA256_VerifyHash(shaHash, testVectors[j], stringArray[i]);
                        }

                        watch.Stop();
                        Console.WriteLine("SHA256 Decryption: " + watch.ElapsedMilliseconds);
                    }
                break;

                // RSA-OAEP
                case 7:
                break;

                // RSA-PPS
                case 8:

                    RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                    RSAParameters Key = RSAalg.ExportParameters(true);                    

                    for(int i = 0; i < times; i ++)
                    {
                        if(j % 8 == 0) j = 0;
                        
                        byte[] data = ByteConverter.GetBytes(hashVectors[j]);
                        signedData = RSAPSS_GenerateSignature(data, Key);
                        byteArray.Add(signedData);

                        j++;
                    }

                    j = 0;
                    watch.Stop();
                    Console.WriteLine("RSA PSS Signature: " + watch.ElapsedMilliseconds);                    

                    watch = System.Diagnostics.Stopwatch.StartNew();
                    for (int i = 0; i < times; i++)
                    {
                        if(j % 8 == 0) j = 0;

                        byte[] data = ByteConverter.GetBytes(hashVectors[j]);
                        RSAPSS_VerifySignatura(data, byteArray[i], Key); 
                    }                   
                    watch.Stop();
                    Console.WriteLine("RSA PSS Encryption: " + watch.ElapsedMilliseconds);

                break;

                // DSA
                case 9:

                DSACryptoServiceProvider DSA = new DSACryptoServiceProvider();
                DSASignatureFormatter DSAFormatter = new DSASignatureFormatter(DSA);

                //Set the hash algorithm to SHA1.
			    DSAFormatter.SetHashAlgorithm("SHA1");

                byte[] Hash = {59,4,248,102,77,97,142,201,210,12,224,93,25,41,100,197,213,134,130,135};

                for(int i = 0; i < times; i ++)
                {
                    if(j % 8 == 0) j = 0;
                        
                    signedData = DSAFormatter.CreateSignature(Hash);
                    byteArray.Add(signedData);

                    j++;
                }

                j = 0;
                watch.Stop();
                Console.WriteLine("DSA Signature: " + watch.ElapsedMilliseconds); 
                watch = System.Diagnostics.Stopwatch.StartNew();
                for (int i = 0; i < times; i++)
                {
                    if(j % 8 == 0) j = 0;
                    DSASignatureDeformatter DSADeformatter = new DSASignatureDeformatter(DSA);

                    DSADeformatter.VerifySignature(Hash, byteArray[i]);

                    j++;
                }                   
                    watch.Stop();
                    Console.WriteLine("RSA PSS Encryption: " + watch.ElapsedMilliseconds);
                
                break;
			    
            }                        
            
        }
        
    }
    
}