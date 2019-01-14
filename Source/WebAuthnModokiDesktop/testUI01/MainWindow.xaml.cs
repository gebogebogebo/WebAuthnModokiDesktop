using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace testUI01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        private gebo.CTAP2.DevParam devParam;

        public MainWindow()
        {
            InitializeComponent();

            devParam = gebo.CTAP2.DevParam.getDefaultParams();
        }

        private void setResponse(gebo.CTAP2.CTAPauthenticator ctap, gebo.CTAP2.CTAPResponse res)
        {
            string msg = "<Command>\r\n" + ctap.payloadJson + "\r\n\r\n";

            msg = msg + "<Response>\r\n";
            msg = msg + string.Format($"Status=0x{res.Status:X2}\r\nMsg={res.StatusMsg}\r\n<ResponseData>\r\n");
            msg = msg + res.ResponseDataJson + "\r\n";
            textBox.Text = textBox.Text + msg + "\r\n";

            if (res.GetType() == typeof(gebo.CTAP2.CTAPResponseAssertion)) {
                var ret = (gebo.CTAP2.CTAPResponseAssertion)res;
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

        private void setResponse(WebAuthnModokiDesktop.commandstatus res)
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
            log("◆◆◆【HID Test - Start】");
            var ret = WebAuthnModokiDesktop.credentials.hidcheck(devParam.hidparams);
            setResponse(ret);
            log("◆◆◆【HID Test - END】");
        }

        private async void button1_Click(object sender, RoutedEventArgs e)
        {
            log("◆◆◆【info - Start】");
            var ret = await WebAuthnModokiDesktop.credentials.info(devParam);
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

            var ret = await WebAuthnModokiDesktop.credentials.create(devParam, json, pin);
            setResponse(ret);

            if (ret.isSuccess == true) {
                // Verify
                if( WebAuthnModokiDesktop.CTAPVerify.Verify(ret) ) {
                    log("Verify - OK!");

                    // Export_File
                    WebAuthnModokiDesktop.credentials.serializeAttestationToFile(ret.attestation, string.Format($".\\credentials\\credential_{rpid}_attestation.json"));

                    // Certificate
                    var certpem = WebAuthnModokiDesktop.CTAPVerify.ConvertCertificateDERtoPEM(ret.attestation.AttStmtX5c);
                    System.IO.File.WriteAllText(string.Format($".\\credentials\\credential_{rpid}_attestation_cert.pem"), certpem);

                    // PublicKey
                    var pubkeypem = WebAuthnModokiDesktop.CTAPVerify.ConvertCOSEtoPEM(ret.attestation.CredentialPublicKeyByte);
                    System.IO.File.WriteAllText(string.Format($".\\credentials\\credential_{rpid}_pubkey.pem"), pubkeypem);

                } else {
                    log("Error --- Verify - NG!");
                }
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

            var att = WebAuthnModokiDesktop.credentials.deSerializeAttestationFromFile(string.Format($".\\credentials\\credential_{rpid}_attestation.json"));
            if (att == null) {
                log("Error deSerializeAttestationFromFile");
                return;
            }

            // credential-id
            var credentialid = new byte[0];
            if ((bool)checkGetAssertionCredentialId.IsChecked) {
                credentialid = att.CredentialId;
            }

            string requireUserPresence = "false";
            if ((bool)checkGetAssertionUP.IsChecked == true) {
                requireUserPresence = "true";
            }

            string userVerification = "discouraged";
            if ((bool)checkGetAssertionUV.IsChecked == true) {
                userVerification = "preferred";
            }

            string json =
               "{" +
                    string.Format($"timeout : 60000,") +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                    string.Format($"rpId : '{rpid}',") +
                   @"allowCredentials : [{" +
                       string.Format($"id : [{string.Join(",", credentialid)}],") +
                       string.Format($"type : 'public-key',") +
                   @"}]," +
                   string.Format($"requireUserPresence : '{requireUserPresence}',") +
                   string.Format($"userVerification : '{userVerification}',") +
                "}";

            var ret = await WebAuthnModokiDesktop.credentials.get(devParam, json, pin);
            setResponse(ret);

            if (ret.isSuccess == true) {
                // Verify - check index=0 only
                if (WebAuthnModokiDesktop.CTAPVerify.Verify(ret, att.CredentialPublicKeyByte,0)) {
                    log("Verify - OK!");
                } else {
                    log("Error --- Verify - NG!");
                }
            }

            log("【GetAssertion - End】");
        }

        private async void button4_Click(object sender, RoutedEventArgs e)
        {
            log("◆◆◆【setpin - Start】");
            string pin = textBoxPIN.Text;
            var ret = await WebAuthnModokiDesktop.credentials.setpin(devParam, pin);
            setResponse(ret);
            log("◆◆◆【setpin - END】");
        }

        private void button5_Click(object sender, RoutedEventArgs e)
        {
            log("◆◆◆【no function】");
        }

        private void buttonNFC_Click(object sender, RoutedEventArgs e)
        {
            log("◆◆◆【NFC Test - Start】");
            var ret = WebAuthnModokiDesktop.credentials.nfccheck(devParam.nfcparams);
            setResponse(ret);
            log("◆◆◆【NFC Test - END】");

        }
    }

}
