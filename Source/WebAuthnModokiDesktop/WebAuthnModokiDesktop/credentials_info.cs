using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using gebo.CTAP2;

namespace gebo.CTAP2.WebAuthnModokiDesktop
{
    public class InfoCommandStatus : CommandStatus
    {
        public string HidInfo="";
        public string NfcInfo = "";
        public CTAPResponseInfo AuthenticatorInfo=null;
        public int PinRetryCount = 0;
    }

    public partial class Credentials
    {
        public static async Task<InfoCommandStatus> Info(DevParam devParam)
        {
            var status = new InfoCommandStatus();
            try {

                // hid
                if( devParam.hidparams != null) {
                    var ret = Credentials.HidCheck(devParam.hidparams);
                    status.HidInfo = ret.msg;
                }
                // nfc
                if( devParam.nfcparams != null) {
                    var ret = Credentials.NfcCheck(devParam.nfcparams);
                    status.NfcInfo = ret.msg;
                }

                // getinfo
                {
                    var ctap = new CTAPauthenticatorGetInfo();
                    var ret = await ctap.SendAndResponse(devParam);
                    status.commands.Add(new CommandStatus.CommandInfo(ctap, ret));
                    if (ret.Status != 0) {
                        throw (new Exception("GetInfo"));
                    }
                    status.AuthenticatorInfo = ret;
                }

                // retry
                if( status.AuthenticatorInfo.Option_clientPin == CTAPResponseInfo.OptionFlag.present_and_set_to_true) {
                    var ctap = new CTAPauthenticatorClientPIN();
                    var ret = await ctap.GetRetries(devParam);
                    status.commands.Add(new CommandStatus.CommandInfo(ctap, ret));
                    if (ret.Status != 0) {
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
