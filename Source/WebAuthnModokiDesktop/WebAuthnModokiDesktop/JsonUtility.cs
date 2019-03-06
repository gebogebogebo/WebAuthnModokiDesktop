using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.Serialization.Json;

namespace gebo.CTAP2
{
    internal static class JsonUtility
    {
        /// 任意のオブジェクトを JSON メッセージへシリアライズします。
        public static string Serialize(object obj)
        {
            using (var stream = new MemoryStream()) {
                var serializer = new DataContractJsonSerializer(obj.GetType());
                serializer.WriteObject(stream, obj);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
        public static bool SerializeFile(object obj, string pathname)
        {
            var json = Serialize(obj);
            File.WriteAllText(pathname, json);
            return (true);
        }

        /// Jsonメッセージをオブジェクトへデシリアライズします。
        public static T Deserialize<T>(string message)
        {
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(message))) {

                var setting = new DataContractJsonSerializerSettings() {
                    UseSimpleDictionaryFormat = true,
                };

                var serializer = new DataContractJsonSerializer(typeof(T), setting);

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

            return (JsonUtility.Deserialize<T>(json));
        }

    }
}
