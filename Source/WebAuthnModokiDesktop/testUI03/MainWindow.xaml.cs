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

namespace testUI03
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        private WebAuthnModokiDesktop.devparam devParam;

        public MainWindow()
        {
            InitializeComponent();

            devParam = WebAuthnModokiDesktop.devparam.getDefaultParams();
        }

        private async void buttonSetPIN_Click(object sender, RoutedEventArgs e)
        {
            string newpin = textNewPINSet.Text;
            var ret = await WebAuthnModokiDesktop.credentials.setpin(devParam, newpin);
            if (ret.isSuccess == true) {
                textStatusSet.Text = "Success! " + ret.msg;
            } else {
                textStatusSet.Text = "Failed! " + ret.msg;
            }
        }

        private async void buttonChangePIN_Click(object sender, RoutedEventArgs e)
        {
            string newpin = textNewPIN.Text;
            string currentpin = textCurrentPIN.Text;
            var ret = await WebAuthnModokiDesktop.credentials.changepin(devParam, newpin, currentpin);
            if (ret.isSuccess == true) {
                textStatus.Text = "Success! " + ret.msg;
            } else {
                textStatus.Text = "Failed! " + ret.msg;
            }
        }

        private async void buttonInfo_Click(object sender, RoutedEventArgs e)
        {
            var ret = await WebAuthnModokiDesktop.credentials.info(devParam);
            var msg = ""; 
            msg = msg + string.Format($"isSuccess={ret.isSuccess}") + "\r\n";
            msg = msg + string.Format($"msg={ret.msg}") + "\r\n";
            msg = msg + string.Format($"HidInfo={ret.HidInfo}") + "\r\n";
            msg = msg + string.Format($"NFcInfo={ret.NfcInfo}") + "\r\n";
            msg = msg + string.Format($"PIN Retry Count={ret.PinRetryCount}") + "\r\n";

            if( ret.AuthenticatorInfo != null) {
                msg = msg + string.Format($"Platform={ret.AuthenticatorInfo.Option_plat}") + "\r\n";
                msg = msg + string.Format($"Enable Resident Key={ret.AuthenticatorInfo.Option_rk}") + "\r\n";
                msg = msg + string.Format($"PIN Present={ret.AuthenticatorInfo.Option_clientPin}") + "\r\n";
                msg = msg + string.Format($"Enable User Presence={ret.AuthenticatorInfo.Option_up}") + "\r\n";
                msg = msg + string.Format($"Enable User Verification={ret.AuthenticatorInfo.Option_uv}") + "\r\n";
                msg = msg + string.Format($"Versions={string.Join(",", ret.AuthenticatorInfo.Versions)}") + "\r\n";
            }

            textStatusInfo.Text = msg;

        }

    }
}
