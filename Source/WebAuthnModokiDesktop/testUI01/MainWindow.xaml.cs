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

using System.IO;

namespace testUI01
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

        private void setResponse(WebAuthnModokiDesktop.CTAPauthenticator ctap, WebAuthnModokiDesktop.CTAPResponse res)
        {
            string msg = "<Command>\r\n" + ctap.payloadJson + "\r\n\r\n";

            msg = msg + "<Response>\r\n";
            msg = msg + string.Format($"Status=0x{res.Status:X2}\r\nMsg={res.StatusMsg}\r\n<ResponseData>\r\n");
            msg = msg + res.ResponseDataJson + "\r\n";
            textBox.Text = textBox.Text + msg + "\r\n";

            if (res.GetType() == typeof(WebAuthnModokiDesktop.CTAPResponseAssertion)) {
                var ret = (WebAuthnModokiDesktop.CTAPResponseAssertion)res;
                log(string.Format($"User_Id={Encoding.ASCII.GetString(ret.User_Id)}"));
                log(string.Format($"User_Name={ret.User_Name}"));
                log(string.Format($"User_DisplayName={ret.User_DisplayName}"));
                log(string.Format($"Flags_AttestedCredentialDataIncluded={ret.Flags_AttestedCredentialDataIncluded}"));
                log(string.Format($"Flags_ExtensionDataIncluded={ret.Flags_ExtensionDataIncluded}"));
                log(string.Format($"Flags_UserPresentResult={ret.Flags_UserPresentResult}"));
                log(string.Format($"Flags_UserVerifiedResult={ret.Flags_UserVerifiedResult}"));
                log(string.Format($"NumberOfCredentials={ret.NumberOfCredentials}"));
            }
        }

        private void setResponse(WebAuthnModokiDesktop.commoandstatus res)
        {
            string msg = "<commoandstatus>\r\n" + "isSuccess=" + res.isSuccess + " , " + "msg=" + res.msg + "\r\n";
            textBox.Text = textBox.Text + msg + "\r\n";

            foreach (var cmd in res.commands) {
                setResponse(cmd.cmd, cmd.res);
            }
        }

        private void log(string log)
        {
            textBox.Text = textBox.Text + log + "\r\n";
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {
            log("◆◆◆【test - Start】");
            var ret = WebAuthnModokiDesktop.credentials.test();
            setResponse(ret);
            log("◆◆◆【test - END】");
        }

        private async void button1_Click(object sender, RoutedEventArgs e)
        {
            log("◆◆◆【info - Start】");
            var ret = await WebAuthnModokiDesktop.credentials.info();
            setResponse(ret);
            log("◆◆◆【info - END】");
        }

        private async void button2_Click(object sender, RoutedEventArgs e)
        {
            log("【MakeCredential - Start】");

            byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");
            string rpid = textBox_rpid.Text;
            string user = textBoxUser.Text;
            string pin = textBoxPIN.Text;
            if ((bool)checkMakeCredentialPIN.IsChecked == false) {
                pin = "";
            }

            string requireResidentKey = "false";
            if ((bool)checkMakeCredentialRK.IsChecked == true) {
                requireResidentKey = "true";
            }

            string userVerification = "discouraged";
            if ((bool)checkMakeCredentialUV.IsChecked == true) {
                userVerification = "preferred";
            }

            string json =
                "{" +
                    @"rp : {" +
                        string.Format($"id : '{rpid}',") +
                        string.Format($"name :'GEBO_{rpid}',") +
                    @"}," +
                    @"user : {" +
                        string.Format($"id : '{user}',") +
                        string.Format($"name :'GEBO_{user}',") +
                        string.Format($"displayName :'my name is {user}',") +
                    @"}," +
                    @"pubKeyCredParams: [{type: 'public-key',alg: -7}]," +
                    @"attestation: 'direct'," +
                    @"timeout: 60000," +
                    @"authenticatorSelection : {" +
                        string.Format($"requireResidentKey : {requireResidentKey},") +
                        @"authenticatorAttachment : 'cross-platform'," +
                        string.Format($"userVerification : '{userVerification}'") +
                    @"}," +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                 "}";

            var ret = await WebAuthnModokiDesktop.credentials.create(json, pin);
            setResponse(ret);

            // Export_File
            if (ret.isSuccess == true) {
                if (Directory.Exists(".\\credentials") == false) {
                    Directory.CreateDirectory(".\\credentials");
                }
                string file = string.Format($".\\credentials\\credential_{rpid}_attestation.json");
                WebAuthnModokiDesktop.JsonUtility.SerializeFile(ret.attestation, file);
            }

            log("【MakeCredential - End】");

        }

        private async void button3_Click(object sender, RoutedEventArgs e)
        {
            log("【GetAssertion - Start】");

            byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");
            string rpid = textBox_rpid.Text;
            string pin = textBoxPIN.Text;
            if ((bool)checkGetAssertionPIN.IsChecked == false) {
                pin = "";
            }

            // credential-id
            var credentialid = new byte[0];
            if ((bool)checkGetAssertionCredentialId.IsChecked) {
                string file = string.Format($".\\credentials\\credential_{rpid}_attestation.json");
                var att = WebAuthnModokiDesktop.JsonUtility.DeserializeFile<WebAuthnModokiDesktop.CTAPResponseAttestation>(file);
                 
                credentialid = att.CredentialId;
            }

            string requireUserPresence = "false";
            if ((bool)checkGetAssertionUP.IsChecked == true) {
                requireUserPresence = "true";
            }

            string json =
               "{" +
                   @"publicKey : {" +
                       string.Format($"timeout : 60000,") +
                       string.Format($"challenge:[{string.Join(",", challenge)}],") +
                   @"}," +

                   @"allowCredentials : [{" +
                       string.Format($"id : [{string.Join(",", credentialid)}],") +
                       string.Format($"transports:['usb', 'nfc', 'ble'],") +
                       string.Format($"type : 'public-key',") +
                   @"}]," +

                   @"rp : {" +
                       string.Format($"id : '{rpid}',") +
                   @"}," +
                   string.Format($"requireUserPresence : '{requireUserPresence}'") +
                "}";

            var ret = await WebAuthnModokiDesktop.credentials.get(json, pin);
            setResponse(ret);

            log("【GetAssertion - End】");
        }

        private async void button4_Click(object sender, RoutedEventArgs e)
        {
            log("◆◆◆【setpin - Start】");
            string pin = textBoxPIN.Text;
            var ret = await WebAuthnModokiDesktop.credentials.setpin(pin);
            setResponse(ret);
            log("◆◆◆【setpin - END】");
        }
    }
}
