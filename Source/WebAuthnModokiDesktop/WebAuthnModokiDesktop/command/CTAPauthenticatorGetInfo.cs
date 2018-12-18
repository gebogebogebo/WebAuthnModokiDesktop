using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebAuthnModokiDesktop
{
    internal class CTAPauthenticatorGetInfo : CTAPauthenticator
    {
        public async Task<CTAPResponseInfo> SendAndResponse(List<hidparam> hidparams)
        {
            var resi = await sendCommandandResponse(hidparams,0x04, null);

            var response = new CTAPResponseInfo(resi);
            response.CommandDataJson = this.payloadJson;
            return response;
        }

    }
}
