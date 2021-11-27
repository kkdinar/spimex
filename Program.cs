using System;
using System.Net;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace spimexSend
{    
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string certificate = GetServerCertificate();
                string file = @"C:\spimex\ContractReport.xml.sig";
                byte[] fileText = ReadFile(file);
                //string encryptFileText = Encrypt_EnvelopedCms(fileText, certificate);
                string encryptFileText = Convert.ToBase64String(fileText);
                SendSpimex(encryptFileText);
            }
            catch (Exception ex)
            {
                ErrorLog(ex.Message);
            }
                        
            Console.ReadLine();         
        }
        private static void ErrorLog(string errorText)
        {
            string writePath = @"C:\spimex\Error.txt";
            string text = DateTime.Now.ToString("dd/MM/yyyy hh:mm:ss") + ": " + errorText + "\n";
            using (StreamWriter sw = new StreamWriter(writePath, true, Encoding.UTF8))
            {
                sw.WriteLine(text);
            }
            Console.WriteLine(@"Текст ОШИБКИ записан в файл 'C:\spimex\Error.txt'");
        }

        /**
         * Получение сертификата актуального серверного ключа
         */
        private static string GetServerCertificate()
        {
            string result = "";
            string url = "https://dev-front.spimex.com:5443/otc/server-certificate";
            //Отключаем проверку сертификатов SSL
            //ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(Convert.ToString(url));
            //Метод GET - получить файл
            req.Method = "GET";
            req.ContentType = "application/json-rpc;charset=utf-8";

            //Получение ответа в поток
            HttpWebResponse resp;
            try
            {
                resp = (HttpWebResponse)req.GetResponse();
                if (resp.StatusCode == HttpStatusCode.OK)
                {
                    Stream receiveStream = resp.GetResponseStream();
                    StreamReader readStream = null;

                    if (resp.CharacterSet == null)
                    {
                        readStream = new StreamReader(receiveStream);
                    }
                    else
                    {
                        readStream = new StreamReader(receiveStream, Encoding.GetEncoding(resp.CharacterSet));
                    }
                    result = readStream.ReadToEnd();
                    resp.Close();
                    readStream.Close();
                }
                else
                {
                    result = "ERROR: " + resp.StatusCode.ToString();
                    ErrorLog(result);
                }
            }
            //catch (WebException ex) Exception
            catch (Exception ex)
            {
                ErrorLog(ex.Message);
                //WebResponse errResp = ex.Response;
                //using (Stream respStream = errResp.GetResponseStream())
                //{
                //    StreamReader reader = new StreamReader(respStream);
                //    result = reader.ReadToEnd();
                //    ErrorLog(result);
                //}
            }

            //Превращаем ответ в Объект answer для доступа к его свойствам
            //SpimexAnswer answer = DeserializedData(result);
            //var ser = new DataContractJsonSerializer(typeof(SpimexAnswer));
            //SpimexAnswer answer = ser as SpimexAnswer;
            // запись в файл
            

            string begin = "-----BEGIN CERTIFICATE-----";
            //string end = "-----END CERTIFICATE-----";
            //int indexBegin = result.IndexOf(begin) + 28;
            //int indexEnd = result.IndexOf(end);
            //int length = indexEnd - indexBegin - 1;
            //string res = result.Substring(indexBegin, length);
            int indexBegin = result.IndexOf(begin);
            int length = result.Length - indexBegin - 2;
            string res = result.Substring(indexBegin, length);
            //Console.WriteLine(res);
            //Console.WriteLine(res+"|");
            //Console.WriteLine("Cert Lenth = ");
            //Console.WriteLine(res.Length);

            //using (FileStream fstream = new FileStream(@"C:\cert.p7b", FileMode.OpenOrCreate))
            //{
            //    // преобразуем строку в байты
            //    byte[] _array = System.Text.Encoding.Default.GetBytes(res);
            //    // запись массива байтов в файл
            //    fstream.Write(_array, 0, _array.Length);
            //    Console.WriteLine("Текст записан в файл");
            //}

            return res;
        }

        /**
         * Чтение данных из файла
         */
        private static byte[] ReadFile(string file)
        {
            byte[] array;
            // чтение из файла
            using (FileStream fstream = File.OpenRead(file))
            {
                // преобразуем строку в байты
                array = new byte[fstream.Length];
                // считываем данные
                fstream.Read(array, 0, array.Length);
                // декодируем байты в строку
                //string textFromFile = Encoding.UTF8.GetString(array);
                //Console.WriteLine($"Текст из файла: {textFromFile}");
            }
            return array;
        }

        public static string Encrypt_EnvelopedCms(byte[] data, string certificate)
        {
            X509Certificate2 encryptingCert;
            encryptingCert = new X509Certificate2(Encoding.UTF8.GetBytes(certificate));

            // create ContentInfo
            ContentInfo plainContent = new ContentInfo(data);

            // EnvelopedCms represents encrypted data
            EnvelopedCms encryptedData = new EnvelopedCms(plainContent);

            // add a recipient
            CmsRecipient recipient = new CmsRecipient(encryptingCert);

            // encrypt data with public key of recipient
            encryptedData.Encrypt(recipient);

            // create PKCS #7 byte array
            byte[] encryptedBytes = encryptedData.Encode();

            return Convert.ToBase64String(encryptedBytes);
        }

        private static void SendSpimex(string encryptFileText)
        {
            string url = "https://dev-front.spimex.com:5443/otc/async-requests";
            string requestUid = Guid.NewGuid().ToString();

            // запись в файл
            using (FileStream fstream = new FileStream(@"C:\spimex\Guid.txt", FileMode.OpenOrCreate))
            {
                // преобразуем строку в байты
                byte[] array = Encoding.Default.GetBytes(requestUid);
                // запись массива байтов в файл
                fstream.Write(array, 0, array.Length);
                //Console.WriteLine("Текст записан в файл");
            }

            string fileName = "file.xml";
            string json = "{\"requestUid\" :\"" + requestUid + "\"";
            json = json + ",\"fileName\"   :\"" + fileName + "\"";
            json = json + ",\"fileContent\":\"" + encryptFileText + "\"" + "}";
            //Console.WriteLine($"json={json}");
            using (StreamWriter sw = new StreamWriter(@"C:\spimex\Guid.txt", true, Encoding.UTF8))
            {
                sw.WriteLine(json);
            }

            byte[] postByteArray = Encoding.UTF8.GetBytes(json);
            string responseFromSpimex;
            try
            {
                //ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                WebRequest req = WebRequest.Create(Convert.ToString(url));
                req.Method = "POST";
                req.ContentType = "application/json-rpc;charset=utf-8";
                Stream dataStream = req.GetRequestStream();
                dataStream.Write(postByteArray, 0, postByteArray.Length);
                dataStream.Close();
                WebResponse resp = req.GetResponse();
                dataStream = resp.GetResponseStream();
                StreamReader rdr = new StreamReader(dataStream);
                //Считываем ответ от spimex.com
                responseFromSpimex = rdr.ReadToEnd();
                //Закрываем считыватель, поток, соединение
                rdr.Close();
                dataStream.Close();
                resp.Close();

                Console.WriteLine(responseFromSpimex);
                // запись в файл
                //using (FileStream fstream = new FileStream(@"C:\spimex\Guid.txt", FileMode.OpenOrCreate))
                //{
                //    string data = DateTime.Now.ToString("dd/MM/yyyy hh:mm:ss") + ": " + responseFromSpimex + "\n";
                //    // преобразуем строку в байты
                //    byte[] array = Encoding.Default.GetBytes(data);
                //    // запись массива байтов в файл
                //    fstream.Write(array, 0, array.Length);
                //    //Console.WriteLine("Текст записан в файл");
                //}

                //Превращаем ответ в Объект answer для доступа к его свойствам
                //SpimexAnswer answer = DeserializedData(responseFromSpimex);
                //Если ошибка
                //if(answer.result == "ERROR")
                //{
                //    string errorMessage = answer.errorMessage;
                //}

                //Возврат ответа
                //return (responseFromSBIS);
            }
            catch (Exception ex)
            {
                //Если что-то пошло не так, выводим ошибочку о том, что же пошло не так.
                //return (Convert.ToString("ERROR: " + ex.Message));
                //Console.WriteLine(Convert.ToString("ERROR: " + ex.Message));
                ErrorLog(ex.Message);
            }
        }

        /**
         * Зашифровываем файл открытым ключом
         */
        private static string EncryptFile(byte[] fileText, string _certificate)
        {
            //byte[] result;
            /*
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //Говорим что параметры не будут экспортированы
            RSAParameters RSAKeyInfo = RSA.ExportParameters(false);
            //Читаем данные из сертификата
            RSAKeyInfo.Modulus = Convert.FromBase64String(certificate);

            //Import the RSA Key information. This only needs to include the public key information.
            RSA.ImportParameters(RSAKeyInfo);

            //Шифруем текст из файла
            result = RSA.Encrypt(fileText, false);
            */
           
            //tDESalg.GenerateIV();

            // Запоминаем вектор в локальной переменной IVector
            //byte[] IVector = tDESalg.IV;

            //string subCertificate = certificate.Substring(0, 24);
            //byte[] Key = new byte[24];
            //Key = Convert.FromBase64String(subCertificate);
            //Console.WriteLine("Key Length = ");
            //Console.WriteLine(Key.Length);
            /*
            byte[] array;
            string textFromFile = "";
            using (FileStream fstream = File.OpenRead(@"C:\xi_output20210706-083129-405.xml.sign.xml"))
            {

                // преобразуем строку в байты
                array = new byte[fstream.Length];
                // считываем данные
                fstream.Read(array, 0, array.Length);
                // декодируем байты в строку
                textFromFile = Encoding.UTF8.GetString(array);
                //Console.WriteLine($"Текст из файла: {textFromFile}");
            }
            */
            /*
            var input = array;// Encoding.UTF8.GetBytes(textFromFile);


            MD5 md5 = new MD5CryptoServiceProvider();            
            byte[] desKey = md5.ComputeHash(Encoding.UTF8.GetBytes(certificate));
            md5.Clear();
            //byte[] desKey = Encoding.UTF8.GetBytes(certificate);
            //var desKey = md5.ComputeHash(Convert.FromBase64String(certificate));
            TripleDES des = new TripleDESCryptoServiceProvider();
            des.Key = desKey;

            //tDESalg.GenerateKey();

            //des.IV = new byte[des.BlockSize / 8];
            des.Padding = PaddingMode.PKCS7;
            des.Mode = CipherMode.ECB;
            var ct = des.CreateEncryptor();           

            //var input = fileText;
            byte[] output = ct.TransformFinalBlock(input,0,input.Length);
            des.Clear();
            //Console.WriteLine("CreateEncryptor = ");
            //Console.WriteLine(Encoding.UTF8.GetString(output)); ;

            //return output;
            return Convert.ToBase64String(output,0,output.Length);
            */

            //Create the file streams to handle the input and output files.
            //FileStream fin = new FileStream(file, FileMode.Open, FileAccess.Read);
            /*
            MemoryStream fin = new MemoryStream();
            fin.Write(array,0,array.Length);
            fin.Seek(0,SeekOrigin.Begin);

            string outName = @"C:\outName.encript";
            FileStream fout = new FileStream(outName, FileMode.OpenOrCreate, FileAccess.Write);
            fout.SetLength(0);

            //Create variables to help with read and write.
            byte[] bin = new byte[100]; //This is intermediate storage for the encryption.
            long rdlen = 0;              //This is the total number of bytes written.
            long totlen = fin.Length;    //This is the total length of the input file.
            int len;                     //This is the number of bytes to be written at a time.
            // Создаем новый TripleDESCryptoServiceProvider обьект для генерирования вектора инициализации (IV).

            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] desKey = md5.ComputeHash(Encoding.UTF8.GetBytes(certificate));
            md5.Clear();

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = desKey;

            CryptoStream encStream = new CryptoStream(fout, tdes.CreateEncryptor(tdes.Key, tdes.IV), CryptoStreamMode.Write);

            Console.WriteLine("Encrypting...");

            //Read from the input file, then encrypt and write to the output file.
            while (rdlen < totlen)
            {
                len = fin.Read(bin, 0, 100);
                encStream.Write(bin, 0, len);
                rdlen = rdlen + len;
                Console.WriteLine("{0} bytes processed", rdlen);
            }

            encStream.Close();


            //byte[] array;
            //string textFromFile = "";
            using (FileStream fstream = File.OpenRead(@"C:\outName.encript"))
            {

                // преобразуем строку в байты
                array = new byte[fstream.Length];
                // считываем данные
                fstream.Read(array, 0, array.Length);
                // декодируем байты в строку
                textFromFile = Encoding.UTF8.GetString(array);
                //Console.WriteLine($"Текст из файла: {textFromFile}");
            }
            return Convert.ToBase64String(array, 0, array.Length);
            */
            //return result;

            // запись в файл
            //using (FileStream fstream = new FileStream(@"C:\note.txt", FileMode.OpenOrCreate))
            //{
            //    // преобразуем строку в байты
            //    byte[] _array = System.Text.Encoding.Default.GetBytes(_certificate);
            //    // запись массива байтов в файл
            //    fstream.Write(_array, 0, _array.Length);
            //    Console.WriteLine("Текст записан в файл");
            //}


            //
            //X509Certificate2 x509 = new X509Certificate2();
            //x509.Import(_certificate);
            //String content = Encoding.UTF8.GetString(certContent);

            //String base64Content = content.Replace("-----BEGIN CERTIFICATE-----", "").Replace("-----END CERTIFICATE-----", "").Replace("\r", "").Replace("\n", "");

            //byte[] decodedContent = Convert.FromBase64String(_certificate);
            //SignedCms certContainer = new SignedCms();
            // certContainer.Decode(decodedContent);

            // X509Certificate2 cert = new X509Certificate2(@"C:\certificate.cer", string.Empty, X509KeyStorageFlags.MachineKeySet);
            //Console.WriteLine($"Текст из файла: {_certificate}");
            
            X509Certificate2 cert = new X509Certificate2(Encoding.UTF8.GetBytes(_certificate));


            string plaintext = Convert.ToBase64String(fileText);
            var contentInfo = new ContentInfo(Encoding.UTF8.GetBytes(plaintext));
            var envelopedCms = new EnvelopedCms(contentInfo);


            var cmsRecipient = new CmsRecipient(cert);
            envelopedCms.Encrypt(cmsRecipient);

            return Convert.ToBase64String(envelopedCms.Encode());
            
            //return _certificate;
           
        }

        

        public static string _TripleDES(string _certificate)
        {
            byte[] array;
            string textFromFile = "";
            using (FileStream fstream = File.OpenRead(@"C:\xi_output20210706-083129-405.xml.sign.xml"))
            {

                // преобразуем строку в байты
                array = new byte[fstream.Length];
                // считываем данные
                fstream.Read(array, 0, array.Length);
                // декодируем байты в строку
                textFromFile = Encoding.UTF8.GetString(array);
                //Console.WriteLine($"Текст из файла: {textFromFile}");
            }

            X509Certificate2 cert = new X509Certificate2(Encoding.UTF8.GetBytes(_certificate));
            string Key = cert.GetPublicKeyString();

            var des = CreateDes(Key);
            var ct = des.CreateEncryptor();
            var input = Encoding.UTF8.GetBytes(textFromFile);
            var output = ct.TransformFinalBlock(input, 0, input.Length);

            return Convert.ToBase64String(output);
        }


        public static TripleDES CreateDes(string key)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            TripleDES des = new TripleDESCryptoServiceProvider();
            var desKey = md5.ComputeHash(Encoding.UTF8.GetBytes(key));
            des.Key = desKey;
            des.IV = new byte[des.BlockSize / 8];
            des.Padding = PaddingMode.PKCS7;
            des.Mode = CipherMode.ECB;
            return des;
        }

        /**
         * Посылаем файл на биржу
         */
       
                
        /**
         * Десиариализация
         */
        private static SpimexAnswer DeserializedData(string json)
        {
            try
            {
                /*
                SpimexAnswer deserializedData = new SpimexAnswer();
                var ms = new MemoryStream(Encoding.UTF8.GetBytes(json));
                var ser = new DataContractJsonSerializer(typeof(SpimexAnswer));
                deserializedData = ser.ReadObject(ms) as SpimexAnswer;
                ms.Close();
                return deserializedData;*/
                var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
                var serializer = new DataContractJsonSerializer(typeof(SpimexAnswer));
                var item = (SpimexAnswer)serializer.ReadObject(stream);
                if (Equals(item, null)) throw new Exception();
                return item;
            }
            catch (Exception ex)
            {
                Console.WriteLine(Convert.ToString("ERROR: " + ex.Message));
                return (null);
            }
        }

        private static void sqlSet()
        {
            //Параметры соединения с базой SQL
            SqlConnectionStringBuilder connectionString = new SqlConnectionStringBuilder();
            connectionString.DataSource = "serv";
            connectionString.InitialCatalog = "dbo";
            connectionString.UserID = "serv";
            connectionString.Password = "12345";

            //Создаём таблицу с полями
            DataTable dataTable = new DataTable();
            dataTable.Columns.Add("CDate", typeof(DateTime));
            dataTable.Columns.Add("Error", typeof(string));

            //Создаём строку
            DataRow dataRow = dataTable.NewRow();
            dataRow["CDate"] = DateTime.Now;
            dataTable.Rows.Add(dataRow);

            using (SqlConnection connection = new SqlConnection(connectionString.ConnectionString))
            {
                using (SqlBulkCopy bulkCopy = new SqlBulkCopy(connection))
                {
                    bulkCopy.DestinationTableName = "dbo.BN_IncomingLog_H";
                    //Сопоставляем поля таблицы dataTable и таблицы в базе dbo.BN_IncomingLog_H
                    bulkCopy.ColumnMappings.Add("Sender", "Sender");
                    bulkCopy.ColumnMappings.Add("Receiver", "Receiver");
                    bulkCopy.ColumnMappings.Add("TextBody", "InData");
                    bulkCopy.ColumnMappings.Add("Error", "Error");
                    try
                    {
                        connection.Open();
                        bulkCopy.WriteToServer(dataTable);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(Convert.ToString("ERROR: " + ex.Message));
                    }
                }
            }
        }
    }

    [DataContract]
    public class SpimexAnswer
    {

        [DataMember(Name = "result")]
        public string result { get; set; }

        [DataMember(Name = "certContetnt")]
        public string certContetnt { get; set; }

        [DataMember(Name = "errorMessage")]
        public string errorMessage { get; set; }

        [DataMember(Name = "requestUid")]
        public string requestUid { get; set; }

        [DataMember(Name = "fileName")]
        public string fileName { get; set; }

        [DataMember(Name = "fileContent")]
        public string fileContent { get; set; }

    }
}
