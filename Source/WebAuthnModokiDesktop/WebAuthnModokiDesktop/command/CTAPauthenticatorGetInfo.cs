using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WebAuthnModokiDesktop;

namespace gebo.CTAP2
{
    internal class CTAPauthenticatorGetInfo : CTAPauthenticator
    {
        public async Task<CTAPResponseInfo> SendAndResponse(devparam devParam)
        {
            var resi = await sendCommandandResponse(devParam, 0x04, null);

            var response = new CTAPResponseInfo(resi);
            response.CommandDataJson = this.payloadJson;
            return response;
        }

    }
}
