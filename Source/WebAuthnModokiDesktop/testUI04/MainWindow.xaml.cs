using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

using gebo.CTAP2;

namespace testUI04
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private class WriteData
        {
            public byte[] userid;
            public string data1 = "";
            public string data2 = "";
        }

        private List<WriteData> getPrivateKeyFromFile()
        {
            // c:\work\ssl>openssl genrsa > private-key.pem
            // c:\work\ssl>openssl rsa -in private-key.pem -out private-key.der -outform der
            string file = @"C:\work\ssl\private-key_2048.der";
            var fs = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read);

            var writeDataList = new List<WriteData>();
            for (; ; ) {
                var rec = new WriteData();
                {
                    byte[] bs = new byte[62];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        break;
                    }
                    rec.userid = bs;
                }
                {
                    byte[] bs = new byte[32];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        writeDataList.Add(rec);
                        break;
                    }
                    rec.data1 = gebo.CTAP2.Common.BytesToHexString(bs);
                }
                {
                    byte[] bs = new byte[32];
                    int readSize = fs.Read(bs, 0, bs.Length);
                    if (readSize == 0) {
                        writeDataList.Add(rec);
                        break;
                    }
                    rec.data2 = gebo.CTAP2.Common.BytesToHexString(bs);
                }

                writeDataList.Add(rec);

            }
            fs.Close();

            return (writeDataList);
        }

        private async void buttonRegist_Click(object sender, RoutedEventArgs e)
        {
            var writeDataList = getPrivateKeyFromFile();

            string rpid = "gebo2.com";
            string pin = "1234";
            byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

            foreach(var rec in writeDataList) {

                byte[] userid = rec.userid;
                string username = rec.data1;
                string userdisplayname = rec.data2;

//                labelCounter.Content = text;

                string json =
                        "{" +
                            @"rp : {" +
                                string.Format($"id : '{rpid}',") +
                            @"}," +
                            @"user : {" +
                                string.Format($"id_bytearray:[{string.Join(",", userid)}],") +
                                //string.Format($"name :'{username}',") +
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

                var ret = await WebAuthnModokiDesktop.credentials.create(gebo.CTAP2.DevParam.getDefaultParams(), json, pin);
                if (ret.isSuccess == false) {
                    MessageBox.Show(ret.msg);
                    break;
                }
            }

        }

        private async void buttonLoad_Click(object sender, RoutedEventArgs e)
        {
            string rpid = "gebo2.com";
            string pin = "1234";
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
                   string.Format($"userVerification : 'discouraged',") +
                "}";

            var ret = await WebAuthnModokiDesktop.credentials.get(gebo.CTAP2.DevParam.getDefaultParams(), json, pin);
            if (ret.isSuccess == false) {
                MessageBox.Show(ret.msg);
            }

        }
    }
}
