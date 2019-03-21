using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using gebo.CTAP2.WebAuthnModokiDesktop;

namespace gebo.CTAP2.Util
{
    public class CmdExecuter
    {
        #region Register
        public static int CheckWriteBlockCount(string writeText)
        {
            byte[] targetBinary = System.Text.Encoding.ASCII.GetBytes(writeText);
            var recs = CreateWriteDataList(targetBinary);
            return (recs.Count);
        }

        public static async Task<string> RegisterCmd(string rpid, string pin, string cmd)
        {
            string result="";
            byte[] data = System.Text.Encoding.ASCII.GetBytes(cmd);
            var recs = gebo.CTAP2.Util.CmdExecuter.CreateWriteDataList(data);
            foreach (var rec in recs) {
                result = await gebo.CTAP2.Util.CmdExecuter.WriteRec(rpid, pin, rec);
                if( result != "Success") {
                    break;
                }
            }
            return result;
        }

        internal class DataRecord
        {
            public byte recno = 0x00;
            public byte filler = 0xFF;
            public byte[] data1;
            public byte[] data2;
            public byte[] data3;

            public DataRecord(byte recno)
            {
                this.recno = recno;
                data1 = System.Text.Encoding.ASCII.GetBytes("gebo");
                data2 = new byte[32];
                data3 = new byte[32];
            }

            public DataRecord(byte[] userId, string userName, string userDisplayName)
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

        internal static List<DataRecord> CreateWriteDataList(byte[] targetBinary)
        {
            var fs = new MemoryStream(targetBinary);

            var writeDataList = new List<DataRecord>();
            for (byte recno = 0; ; recno++) {
                var rec = new DataRecord(recno);

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

            if(writeDataList.Count == 1) {
                // 最低でも2レコード必要
                writeDataList.Add(new DataRecord(2));
            }

            return (writeDataList);
        }

        internal static async Task<string> WriteRec(string rpid, string pin, DataRecord rec)
        {
            string result = "";
            try {
                result = await Task<string>.Run(async () => {

                    byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

                    byte[] userid = new byte[] { rec.recno, rec.filler };
                    userid = userid.ToList().Concat(rec.data1).ToArray();

                    string username = (rec.data2 == null) ? "" : gebo.CTAP2.Common.BytesToHexString(rec.data2);
                    string userdisplayname = (rec.data3 == null) ? "" : gebo.CTAP2.Common.BytesToHexString(rec.data3);

                    DevParam devParam = DevParam.GetDefaultParams();
                    var publickey = new PublicKeyforCreate();
                    {
                        publickey.pin = pin;

                        publickey.rp = new PublicKeyforCreate.Rp();
                        publickey.rp.id = rpid;
                        publickey.rp.name = rpid;

                        publickey.user = new PublicKeyforCreate.User();
                        publickey.user.id_bytearray = (byte[])userid.Clone();
                        publickey.user.name = username;
                        publickey.user.displayName = userdisplayname;

                        // rk
                        publickey.authenticatorSelection.requireResidentKey = true;
                        // uv
                        publickey.authenticatorSelection.userVerification = UserVerificationRequirement.discouraged;

                        // challenge
                        publickey.challenge = (byte[])challenge.Clone();
                    }

                    var ret = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.Create(devParam, publickey);
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
        #endregion

        #region Excute
        public static async Task<string> Execute(string rpid, string pin)
        {
            var result = await gebo.CTAP2.Util.CmdExecuter.ReadRecs(rpid, pin);
            if (result.isSuccess) {
                var cmd = result.strdata;
                System.Diagnostics.Process p = new System.Diagnostics.Process();
                //ComSpec(cmd.exe)のパスを取得して、FileNameプロパティに指定
                p.StartInfo.FileName = System.Environment.GetEnvironmentVariable("ComSpec");
                p.StartInfo.CreateNoWindow = true;
                //コマンドラインを指定（"/c"は実行後閉じるために必要）
                p.StartInfo.Arguments = "/c " + cmd;

                p.Start();
            }
            return result.msg;
        }

        internal class ReadData
        {
            public bool isSuccess;
            public string msg;
            public byte[] data;
            public string strdata;
        }

        internal static async Task<ReadData> ReadRecs(string rpid, string pin)
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

                    DevParam devParam = DevParam.GetDefaultParams();

                    var publickey = new PublicKeyforGet();
                    {
                        publickey.pin = pin;
                        publickey.rpId = rpid;
                        publickey.challenge = (byte[])challenge.Clone();
                        publickey.requireUserPresence = false;
                        publickey.userVerification = UserVerificationRequirement.discouraged;
                    }

                    var ret = await gebo.CTAP2.WebAuthnModokiDesktop.Credentials.Get(devParam, publickey);
                    if (ret.isSuccess == false) {
                        readData.isSuccess = false;
                        readData.msg = ret.msg;
                        return readData;
                    }

                    // dataList
                    var dataList = new List<CmdExecuter.DataRecord>();
                    foreach (var assertion in ret.assertions) {
                        dataList.Add(new CmdExecuter.DataRecord(assertion.User_Id, assertion.User_Name, assertion.User_DisplayName));
                    }
                    dataList = dataList.OrderBy(x => x.recno).ToList();

                    // data
                    readData.data = new byte[0];
                    foreach (var data in dataList) {
                        var tmp = data.data2.ToList().Concat(data.data3).ToList();
                        readData.data = readData.data.ToList().Concat(tmp).ToArray();
                    }

                    // to string
                    try {
                        var tmp = System.Text.Encoding.ASCII.GetString(readData.data).ToString();
                        readData.strdata = tmp.TrimEnd('\0');
                    } catch {

                    }

                    readData.isSuccess = true;
                    readData.msg = "Success";
                    return readData;
                });

            } finally {

            }
            return result;
        }

        #endregion
    }
}
