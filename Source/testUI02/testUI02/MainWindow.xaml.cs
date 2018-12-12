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

namespace testUI02
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

        private void logResponse(WebAuthnModokiDesktop.commoandstatus res)
        {
            string msg = "<commoandstatus>\r\n" + "isSuccess=" + res.isSuccess + " , " + "msg=" + res.msg + "\r\n";
            log(msg);

            foreach (var cmd in res.commands) {
                logResponse(cmd.cmd, cmd.res);
            }
        }
        private void logResponse(WebAuthnModokiDesktop.CTAPauthenticator ctap, WebAuthnModokiDesktop.CTAPResponse res)
        {
            string msg = "<Command>\r\n" + ctap.payloadJson + "\r\n\r\n";

            msg = msg + "<Response>\r\n";
            msg = msg + string.Format($"Status=0x{res.Status:X2}\r\nMsg={res.StatusMsg}\r\n<ResponseData>\r\n");
            msg = msg + res.ResponseDataJson + "\r\n";
            log(msg);

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
            var response = await WebAuthnModokiDesktop.credentials.info();
            logResponse(response);
            if( response.isSuccess == true) {
                MessageBox.Show("Success!");
            } else {
                MessageBox.Show("Failed!");
            }
            log("<Info-End>");
        }

        byte[] CredentialId = null;
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
                    "}," +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                 "}";
            var response = await WebAuthnModokiDesktop.credentials.create(json, pin);
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
                CredentialId = response.attestation.CredentialId;
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

            byte[] challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

            string pin = textPIN.Text;

            string json =
               "{" +
                    string.Format($"timeout : 60000,") +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                    string.Format($"rpId : 'demo.WebauthnMODOKI.gebogebo.com',") +
                   @"allowCredentials : [{" +
                       string.Format($"id : [{string.Join(",", CredentialId)}],") +
                       string.Format($"type : 'public-key',") +
                   @"}]," +
                   string.Format($"requireUserPresence : 'true',") +
                   string.Format($"userVerification : 'discouraged',") +
                "}";

            var response = await WebAuthnModokiDesktop.credentials.get(json, pin);

            if(response.isSuccess == true) {
                log("---");
                log("Authentication successful!");
                log("---");
                labeLoginResult.Content = "successful!";
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

            string json =
               "{" +
                    string.Format($"timeout : 60000,") +
                    string.Format($"challenge:[{string.Join(",", challenge)}],") +
                    string.Format($"rpId : 'demo.WebauthnMODOKI.gebogebo.com',") +
                   string.Format($"requireUserPresence : 'true',") +
                   string.Format($"userVerification : 'discouraged',") +
                "}";

            var response = await WebAuthnModokiDesktop.credentials.get(json, pin);

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
