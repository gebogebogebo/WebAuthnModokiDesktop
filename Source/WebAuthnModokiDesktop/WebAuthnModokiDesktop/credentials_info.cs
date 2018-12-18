using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebAuthnModokiDesktop
{
    public class infocommandstatus : commandstatus
    {
        public string HidInfo="";
        public CTAPResponseInfo AuthenticatorInfo=null;
        public int PinRetryCount = 0;
    }

    public partial class credentials
    {
        public static async Task<infocommandstatus> info(List<hidparam> hidParams)
        {
            var status = new infocommandstatus();
            try {

                // hid
                {
                    var ret = credentials.hidcheck(hidParams);
                    status.HidInfo = ret.msg;
                }

                // getinfo
                {
                    var ctap = new CTAPauthenticatorGetInfo();
                    var ret = await ctap.SendAndResponse(hidParams);
                    status.commands.Add(new commandstatus.commandinfo(ctap, ret));
                    if (ret.Status != 0x00) {
                        throw (new Exception("GetInfo"));
                    }
                    status.AuthenticatorInfo = ret;
                }

                // retry
                {
                    var ctap = new CTAPauthenticatorClientPIN();
                    var ret = await ctap.GetRetries(hidParams);
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
