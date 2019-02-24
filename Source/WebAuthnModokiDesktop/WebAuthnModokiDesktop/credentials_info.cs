using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using gebo.CTAP2;

namespace WebAuthnModokiDesktop
{
    public class infocommandstatus : commandstatus
    {
        public string HidInfo="";
        public string NfcInfo = "";
        public CTAPResponseInfo AuthenticatorInfo=null;
        public int PinRetryCount = 0;
    }

    public partial class credentials
    {
        public static async Task<infocommandstatus> info(DevParam devParam)
        {
            var status = new infocommandstatus();
            try {

                // hid
                if( devParam.hidparams != null) {
                    var ret = credentials.hidcheck(devParam.hidparams);
                    status.HidInfo = ret.msg;
                }
                // nfc
                if( devParam.nfcparams != null) {
                    var ret = credentials.nfccheck(devParam.nfcparams);
                    status.NfcInfo = ret.msg;
                }

                // getinfo
                {
                    var ctap = new CTAPauthenticatorGetInfo();
                    var ret = await ctap.SendAndResponse(devParam);
                    status.commands.Add(new commandstatus.commandinfo(ctap, ret));
                    if (ret.Status != 0x00) {
                        throw (new Exception("GetInfo"));
                    }
                    status.AuthenticatorInfo = ret;
                }

                // retry
                if( status.AuthenticatorInfo.Option_clientPin == CTAPResponseInfo.OptionFlag.present_and_set_to_true) {
                    var ctap = new CTAPauthenticatorClientPIN();
                    var ret = await ctap.GetRetries(devParam);
                    status.commands.Add(new commandstatus.commandinfo(ctap, ret));
                    if (ret.Status != 0x00) {
                        throw (new Exception("GetRetries"));
                    }
                    status.PinRetryCount = ctap.RetryCount;
                }
                status.isSuccess = true;
            } catch (Exception ex) {
                status.setErrorMsg(ex);
            }
            return status;
        }
    }
}
