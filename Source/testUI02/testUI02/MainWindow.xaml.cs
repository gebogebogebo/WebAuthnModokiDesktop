using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using gebo.CTAP2;

namespace testUI02
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        private WebAuthnModokiDesktop.devparam devParams;

        public MainWindow()
        {
            InitializeComponent();
            devParams = WebAuthnModokiDesktop.devparam.getDefaultParams();
        }

        private void logResponse(WebAuthnModokiDesktop.commandstatus res)
        {
            string msg = "<commandstatus>\r\n" + "isSuccess=" + res.isSuccess + " , " + "msg=" + res.msg + "\r\n";
            log(msg);

            foreach (var cmd in res.commands) {
                logResponse(cmd.cmd, cmd.res);
            }
        }
        private void logResponse(CTAPauthenticator ctap, CTAPResponse res)
        {
            string msg = "<Command>\r\n" + ctap.payloadJson + "\r\n\r\n";

            msg = msg + "<Response>\r\n";
            msg = msg + string.Format($"Status=0x{res.Status:X2}\r\nMsg={res.StatusMsg}\r\n<ResponseData>\r\n");
            msg = msg + res.ResponseDataJson + "\r\n";
            log(msg);

            if (res.GetType() == typeof(CTAPResponseAssertion)) {
                var ret = (CTAPResponseAssertion)res;
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
        private void log(string log)
        {
            if( log.Length <= 0) {
                textLog.Text = "";
                return;
            }
            textLog.Text = textLog.Text + log + "\r\n";
        }

        private async void button1_Click(object sender, RoutedEventArgs e)
        {
            log("");
            log("<Info>");
            var response = await WebAuthnModokiDesktop.credentials.info(devParams);
            logResponse(response);
            if( response.isSuccess == true) {
                MessageBox.Show("Success!\r\n\r\nHID=" + response.HidInfo+"\r\nNFC=" + response.NfcInfo);
            } else {
                MessageBox.Show("Failed!");
            }
            log("<Info-End>");
        }

        byte[] CredentialId = null;
        byte[] CredentialPublicKeyByte = null;
        private async void buttonRegister_Click(object sender, RoutedEventArgs e)
        {
            labelRegisterResult.Content = "";
            log("");
            log("<Register>");

            byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

            string user = textRegisterUserName.Text;
            string rk = "false";
            if ((bool)checkRegisterRk.IsChecked == true) {
                rk = "true";
            }
            string pin = textPIN.Text;

            string uv = "discouraged";
            if ((bool)checkUV.IsChecked) {
                uv = "preferred";
            }

            string json =
                "{" +
                    "rp : {" +
                        string.Format($"id : 'demo.WebauthnMODOKI.gebogebo.com',") +
                    "}," +
                    "user : {" +
                        string.Format($"id : '{user}',") +
                        string.Format($"name :'name_{user}',") +
                        string.Format($"displayName :'my name is {user}',") +
                    "}," +
                    "pubKeyCredParams: [{type: 'public-key',alg: -7}]," +
                    "timeout: 60000," +
                    "authenticatorSelection : {" +
                        string.Format($"requireResidentKey : {rk},") +
                        string.Format($"userVerification : '{uv}'") +
                    "}," +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                 "}";
            var response = await WebAuthnModokiDesktop.credentials.create(devParams, json, pin);
            if (response.isSuccess == true) {
                log("---");
                log("Registration successful!");
                log("---");
                textLoginUserName.Text = user;
                labelRegisterResult.Content = "successful!";
            } else {
                log("---");
                log("Registration failed!");
                log("---");
                labelRegisterResult.Content = "failed!";
            }

            logResponse(response);

            if( response.isSuccess == true) {
                if( checkRegisterVerify.IsChecked == true) {
                    if (WebAuthnModokiDesktop.CTAPVerify.Verify(response) == false) {
                        log("---");
                        log("Registration Verify failed!");
                        log("---");
                        textLoginUserName.Text = "";
                        labelRegisterResult.Content = "Verify failed!";
                        return;
                    }
                    log("---");
                    log("Registration Verify ok!");
                    log("---");
                }

                CredentialId = response.attestation.CredentialId;
                CredentialPublicKeyByte = response.attestation.CredentialPublicKeyByte;
            }
            log("<Register-END>");
        }

        private async void buttonLogin_Click(object sender, RoutedEventArgs e)
        {
            labeLoginResult.Content = "";
            log("");
            log("<Login>");

            if ( CredentialId == null) {
                log("Error - Please register first");
                return;
            }

            string uv = "discouraged";
            if ((bool)checkUV.IsChecked) {
                uv = "preferred";
            }

            byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

            string pin = textPIN.Text;

            string json =
                "{" +
                    string.Format($"timeout : 60000,") +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                    string.Format($"rpId : 'demo.WebauthnMODOKI.gebogebo.com',") +
                    "allowCredentials : [{" +
                        string.Format($"id : [{string.Join(",", CredentialId)}],") +
                        string.Format($"type : 'public-key',") +
                    "}]," +
                    string.Format($"requireUserPresence : 'true',") +
                    string.Format($"userVerification : '{uv}',") +
                "}";

            var response = await WebAuthnModokiDesktop.credentials.get(devParams, json, pin);

            if(response.isSuccess == true) {
                log("---");
                log("Authentication successful!");
                log("---");
                labeLoginResult.Content = "successful!";

                if (checkLoginVerify.IsChecked == true) {
                    if (WebAuthnModokiDesktop.CTAPVerify.Verify(response,this.CredentialPublicKeyByte) == false) {
                        log("---");
                        log("Authentication Verify failed!");
                        log("---");
                        labeLoginResult.Content = "Verify failed!";
                        return;
                    }
                    log("---");
                    log("Authentication Verify ok!");
                    log("---");
                }

            } else {
                log("---");
                log("Authentication failed!");
                log("---");
                labeLoginResult.Content = "failed!";
            }

            logResponse(response);
            log("<Login-END>");

        }

        private async void buttonLogin2_Click(object sender, RoutedEventArgs e)
        {
            labeLogin2Result.Content = "";
            log("");
            log("<Login without username>");

            byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

            string pin = textPIN.Text;

            string uv = "discouraged";
            if ((bool)checkUV.IsChecked) {
                uv = "preferred";
            }

            string json =
               "{" +
                    string.Format($"timeout : 60000,") +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                    string.Format($"rpId : 'demo.WebauthnMODOKI.gebogebo.com',") +
                   string.Format($"requireUserPresence : 'true',") +
                   string.Format($"userVerification : '{uv}',") +
                "}";

            var response = await WebAuthnModokiDesktop.credentials.get(devParams, json, pin);

            if (response.isSuccess == true) {
                log("---");
                log("Authentication successful!");
                log("---");
                labeLogin2Result.Content = "successful!";
            } else {
                log("---");
                log("Authentication failed!");
                log("---");
                labeLogin2Result.Content = "failed!";
            }

            logResponse(response);
            log("<Login without username-END>");
        }
    }
}
