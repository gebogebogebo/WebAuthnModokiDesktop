using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace gebo.CTAP2
{
    internal class CTAPauthenticatorGetInfo : CTAPauthenticator
    {
        public async Task<CTAPResponseInfo> SendAndResponse(DevParam devParam)
        {
            var resi = await sendCommandandResponse(devParam, 0x04, null);

            var response = new CTAPResponseInfo(resi);
            response.CommandDataJson = this.payloadJson;
            return response;
        }

    }
}
