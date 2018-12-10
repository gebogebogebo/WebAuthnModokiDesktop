using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebAuthnModokiDesktop
{
    internal class CTAPauthenticatorGetNextAssertion : CTAPauthenticatorGetAssertion
    {
        new public async Task<CTAPResponseAssertion> SendAndResponse()
        {
            var resi = await sendCommandandResponse(0x08,null);
            var response = new CTAPResponseAssertion(resi);
            response.CommandDataJson = this.payloadJson;

            return (response);
        }
    }
}
