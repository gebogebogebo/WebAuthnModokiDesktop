using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;

namespace gebo.CTAP2
{
    public class Common
    {
        // 16進数文字列 => Byte配列
        public static byte[] HexStringToBytes(string str)
        {
            var bs = new List<byte>();
            for (int i = 0; i < str.Length / 2; i++) {
                bs.Add(Convert.ToByte(str.Substring(i * 2, 2), 16));
            }
            // "01-AB-EF" こういう"-"区切りを想定する場合は以下のようにする
            // var bs = str.Split('-').Select(hex => Convert.ToByte(hex, 16));
            return bs.ToArray();
        }

        // Byte配列 => 16進数文字列
        public static string BytesToHexString(byte[] bs)
        {
            var str = BitConverter.ToString(bs);
            // "-"がいらないなら消しておく
            str = str.Replace("-", string.Empty);
            return str;
        }

        public static int ToInt32(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 4);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt32(sub, 0);
        }

        public static int ToInt16(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 2);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt16(sub, 0);
        }

        // バイト配列から一部分を抜き出す
        private static byte[] GetSubArray(byte[] src, int startIndex, int count)
        {
            byte[] dst = new byte[count];
            Array.Copy(src, startIndex, dst, 0, count);
            return dst;
        }

        public static bool GetBit(byte bdata,int bit)
        {
            byte mask = 0x00;
            if( bit == 0) {
                mask = 0x01;
            } else if( bit == 1) {
                mask = 0x02;
            } else if (bit == 2) {
                mask = 0x04;
            } else if (bit == 3) {
                mask = 0x08;
            } else if (bit == 4) {
                mask = 0x10;
            } else if (bit == 5) {
                mask = 0x20;
            } else if (bit == 6) {
                mask = 0x40;
            } else if (bit == 7) {
                mask = 0x80;
            }
            if ((bdata & mask) == mask) {
                return true;
            } else {
                return false;
            }
        }

        internal static byte[] AES256CBC_Encrypt(byte[] key, byte[] data)
        {
            // 暗号化方式はAES
            AesManaged aes = new AesManaged();
            // 鍵の長さ
            aes.KeySize = 256;
            // ブロックサイズ（何文字単位で処理するか）
            aes.BlockSize = 128;
            // 暗号利用モード
            aes.Mode = CipherMode.CBC;
            // 初期化ベクトル(0x00×16byte)
            aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            aes.Key = key;
            // パディング
            aes.Padding = PaddingMode.None;

            // 暗号化
            var encdata = aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

            return (encdata);
        }

        internal static byte[] AES256CBC_Decrypt(byte[] key,byte[] data)
        {
            // 暗号化方式はAES
            AesManaged aes = new AesManaged();
            // 鍵の長さ
            aes.KeySize = 256;
            // ブロックサイズ（何文字単位で処理するか）
            aes.BlockSize = 128;
            // 暗号利用モード
            aes.Mode = CipherMode.CBC;
            // 初期化ベクトル(0x00×16byte)
            aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            aes.Key = key;
            // パディング
            aes.Padding = PaddingMode.None;

            var encdata = aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);

            return (encdata);
        }

    }

    internal static class JsonUtility
    {
        /// 任意のオブジェクトを JSON メッセージへシリアライズします。
        /// </summary>
        public static string Serialize(object obj)
        {
            using (var stream = new MemoryStream()) {
                var serializer = new DataContractJsonSerializer(obj.GetType());
                serializer.WriteObject(stream, obj);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
        public static bool SerializeFile(object obj,string pathname)
        {
            var json = Serialize(obj);
            File.WriteAllText(pathname,json);
            return (true);
        }

        /// <summary>
        /// Jsonメッセージをオブジェクトへデシリアライズします。
        /// </summary>
        public static T Deserialize<T>(string message)
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(message))) {

                var setting = new DataContractJsonSerializerSettings()
                {
                    UseSimpleDictionaryFormat = true,
                };

                var serializer = new DataContractJsonSerializer(typeof(T),setting);

                return (T)serializer.ReadObject(stream);
            }
        }

        public static T DeserializeFile<T>(string pathname)
        {
            string json = "";
            var fs = new StreamReader(pathname);
            try {
                json = fs.ReadToEnd();
            } finally {
                fs.Close();
            }

            return(JsonUtility.Deserialize<T>(json));
        }

    }
}

