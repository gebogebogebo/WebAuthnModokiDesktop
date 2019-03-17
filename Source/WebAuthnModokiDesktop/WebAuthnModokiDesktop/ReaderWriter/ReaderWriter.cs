using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace gebo.CTAP2.ReaderWriter
{
    public class Writer
    {
        public class WriteData
        {
            public byte recno = 0x00;
            public byte filler = 0xFF;
            public byte[] data1;
            public byte[] data2;
            public byte[] data3;

            public WriteData()
            {
            }

            public WriteData(byte[] userId, string userName, string userDisplayName)
            {
                recno = 0x00;
                filler = 0xFF;
                if (userId == null || userId.Length < 2) {
                    return;
                }
                recno = userId[0];
                //recno[1] = userId[1];
                data1 = userId.ToList().Skip(2).ToArray();

                if (userName != null) {
                    data2 = gebo.CTAP2.Common.HexStringToBytes(userName);
                }
                if (userDisplayName != null) {
                    data3 = gebo.CTAP2.Common.HexStringToBytes(userDisplayName);
                }
            }
        }

        public List<WriteData> CreateWriteDataList(byte[] targetBinary)
        {
            var fs = new MemoryStream(targetBinary);

            var writeDataList = new List<WriteData>();
            for (byte recno = 0; ; recno++) {
                var rec = new WriteData();

                // recno
                rec.recno = recno;

                {
                    byte[] bs = new byte[62];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        break;
                    }
                    rec.data1 = bs.ToList().Take(readSize).ToArray();
                }
                {
                    byte[] bs = new byte[32];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        writeDataList.Add(rec);
                        break;
                    }
                    rec.data2 = bs.ToList().Take(readSize).ToArray();
                }
                {
                    byte[] bs = new byte[32];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        writeDataList.Add(rec);
                        break;
                    }
                    rec.data3 = bs.ToList().Take(readSize).ToArray();
                }

                writeDataList.Add(rec);

            }
            fs.Close();

            return (writeDataList);
        }

        public async Task<string> WriteRec(string rpid, string pin, WriteData rec)
        {
            string result = "";
            try {
                result = await Task<string>.Run(async () => {
                    byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

                    byte[] userid = new byte[] { rec.recno, rec.filler };
                    userid = userid.ToList().Concat(rec.data1).ToArray();

                    string username = (rec.data2 == null) ? "" : gebo.CTAP2.Common.BytesToHexString(rec.data2);
                    string userdisplayname = (rec.data3 == null) ? "" : gebo.CTAP2.Common.BytesToHexString(rec.data3);

                    string json =
                            "{" +
                                @"rp : {" +
                                    string.Format($"id : '{rpid}',") +
                                @"}," +
                                @"user : {" +
                                    string.Format($"id_bytearray:[{string.Join(",", userid)}],") +
                                    string.Format($"name :'{username}',") +
                                    string.Format($"displayName :'{userdisplayname}',") +
                                @"}," +
                                @"pubKeyCredParams: [{type: 'public-key',alg: -7}]," +
                                @"attestation: 'direct'," +
                                @"timeout: 60000," +
                                @"authenticatorSelection : {" +
                                    string.Format($"requireResidentKey : true,") +
                                    @"authenticatorAttachment : 'cross-platform'," +
                                    string.Format($"userVerification : 'discouraged'") +
                                @"}," +
                                string.Format($"challenge:[{string.Join(",", challenge)}],") +
                            "}";

                    var ret = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.Create(gebo.CTAP2.DevParam.GetDefaultParams(), json, pin);
                    if (ret.isSuccess == false) {
                        return ret.msg;
                    }
                    return ("Success");
                });

            } catch (Exception ex) {
                result = ex.Message;
            } finally {

            }
            return result;
        }

    }

    public class Reader
    {
        public class ReadData
        {
            public bool isSuccess;
            public string msg;
            public byte[] data;
        }

        public async Task<ReadData> ReadRecs(string rpid, string pin)
        {
            ReadData result;
            try {
                string uv = "preferred";
                if (string.IsNullOrEmpty(pin) == false) {
                    uv = "discouraged";
                }

                result = await Task<ReadData>.Run(async () => {
                    var readData = new ReadData();

                    byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");
                    var credentialid = new byte[0];

                    string json =
                       "{" +
                            string.Format($"timeout : 60000,") +
                            string.Format($"challenge:[{string.Join(",", challenge)}],") +
                            string.Format($"rpId : '{rpid}',") +
                           @"allowCredentials : [{" +
                               string.Format($"id : [{string.Join(",", credentialid)}],") +
                               string.Format($"type : 'public-key',") +
                           @"}]," +
                           string.Format($"requireUserPresence : 'false',") +
                           string.Format($"userVerification : '{uv}',") +
                        "}";

                    var ret = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.Get(gebo.CTAP2.DevParam.GetDefaultParams(), json, pin);
                    if (ret.isSuccess == false) {
                        readData.isSuccess = false;
                        readData.msg = ret.msg;
                        return readData;
                    }

                    // dataList
                    var dataList = new List<Writer.WriteData>();
                    foreach (var assertion in ret.assertions) {
                        dataList.Add(new Writer.WriteData(assertion.User_Id, assertion.User_Name, assertion.User_DisplayName));
                    }
                    dataList = dataList.OrderBy(x => x.recno).ToList();

                    // data
                    readData.data = new byte[0];
                    foreach (var data in dataList) {
                        var tmp = data.data1.ToList().Concat(data.data2).Concat(data.data3).ToList();
                        readData.data = readData.data.ToList().Concat(tmp).ToArray();
                    }

                    readData.isSuccess = true;
                    readData.msg = "Success";
                    return readData;
                });

            } finally {

            }
            return result;
        }

    }
}
