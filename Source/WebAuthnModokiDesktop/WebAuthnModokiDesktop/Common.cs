using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;

namespace WebAuthnModokiDesktop
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

        public static byte[] AES256CBCEnc(byte[] key, byte[] data)
        {
            byte[] encdata;
            // pinHashEnc = AES256-CBC(sharedSecret, IV=0, pinsha16)
            // 暗号化鍵
            //const string AesKey = @"<半角32文字（8bit*32文字=256bit）>";

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
            aes.Padding = PaddingMode.PKCS7;

            // 暗号化
            encdata = aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

            // cでは16byteなんだけど、C#ではなぜか32byteとなる（けど先頭16byteは同じ)
            // なので、16byteにする
            encdata = encdata.ToList().Skip(0).Take(16).ToArray();

            return (encdata);
        }

        // 暗号化されたBase64形式の入力文字列をAES復号して平文の文字列を返すメソッド
        public static async Task<byte[]> AES256CBC_Decrypt(byte[] key,byte[] src)
        {
            byte[] data;

            byte[] iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

            // Decryptor（復号器）を用意する
            using (var aes = new AesManaged()) {
                // 鍵の長さ
                //aes.KeySize = 256;
                // ブロックサイズ（何文字単位で処理するか）
                //aes.BlockSize = 128;
                // 暗号利用モード
                //aes.Mode = CipherMode.CBC;
                // パディング
                //aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor(key, iv))
                // 入力ストリームを開く
                using (var inStream = new MemoryStream(src, false))
                // 出力ストリームを用意する
                using (var outStream = new MemoryStream()) {

                    // 復号して一定量ずつ読み出し、それを出力ストリームに書き出す
                    using (var cs = new CryptoStream(inStream, decryptor, CryptoStreamMode.Read)) {
                        byte[] buffer = new byte[128]; // バッファーサイズはBlockSizeの倍数にする
                        int len = 0;
                        while ((len = await cs.ReadAsync(buffer, 0, 128)) > 0)
                            outStream.Write(buffer, 0, len);
                    }
                    // 出力がファイルなら、以上で完了

                    data = outStream.ToArray();
                }
            }

            return data;
        }


        public static string Decrypt(byte[] key,byte[] cipherText)
        {
            var plainText = string.Empty;

            var BLOCK_SIZE = 128;   // 128bit 固定
            var KEY_SIZE = 256;     // 128/192/256bit から選択

            var csp = new AesCryptoServiceProvider();
            csp.BlockSize = BLOCK_SIZE;
            csp.KeySize = KEY_SIZE;
            csp.Mode = CipherMode.CBC;
            csp.Padding = PaddingMode.PKCS7;
            csp.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            csp.Key = key;

            using (var inms = new MemoryStream(cipherText))
            using (var decryptor = csp.CreateDecryptor())
            using (var cs = new CryptoStream(inms, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cs)) {
                plainText = reader.ReadToEnd();
            }

            return plainText;
        }
    }

    public static class JsonUtility
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
            /*
            var fs = new FileStream(pathname, FileMode.Create);
            try {
                fs.Write()
                serializer.WriteObject(fs, obj);
            } finally {
                fs.Close();
            }
            */
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

