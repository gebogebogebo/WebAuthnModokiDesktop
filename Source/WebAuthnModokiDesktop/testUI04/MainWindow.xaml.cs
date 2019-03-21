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

        private void log(string log)
        {
            textLog.Text = textLog.Text + log + "\r\n";
        }

        private string rpid = "CTAP2.gebo";
        private string pin = "1234";
        private async void buttonRegist_Click(object sender, RoutedEventArgs e)
        {
            string ip = "";
            string user = "";
            string pass = "";

            // create 
            string text = $@"Cmdkey /generic:TERMSRV/{ip} /user:{user} /pass:{pass} & Start mstsc /v:{ip} & Timeout 2 & Cmdkey /delete:TERMSRV/{ip}";

            var count = gebo.CTAP2.Util.CmdExecuter.CheckWriteBlockCount(text);
            log($"Block Count = {count}");

            var result = await gebo.CTAP2.Util.CmdExecuter.RegisterCmd(rpid, pin,text);
            log($"result = {result}");
        }

        private async void buttonLoad_Click(object sender, RoutedEventArgs e)
        {
            log($"read-start");

            var result = await gebo.CTAP2.Util.CmdExecuter.Execute(rpid, pin);
            log($"result = {result}");

            log($"read-end");
        }
    }
}
