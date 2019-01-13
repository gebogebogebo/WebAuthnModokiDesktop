using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WebAuthnModokiDesktop;

namespace gebo.CTAP2
{
    internal class CTAPauthenticatorGetNextAssertion : CTAPauthenticatorGetAssertion
    {
        new public async Task<CTAPResponseAssertion> SendAndResponse(devparam devParam)
        {
            var resi = await sendCommandandResponse(devParam, 0x08, null);
            var response = new CTAPResponseAssertion(resi);
            response.CommandDataJson = this.payloadJson;

            return (response);
        }
    }
}
