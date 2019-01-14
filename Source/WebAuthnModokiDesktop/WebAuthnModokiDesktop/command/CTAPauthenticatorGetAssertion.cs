using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PeterO.Cbor;
using System.Runtime.Serialization;

namespace gebo.CTAP2
{
    internal class CTAPauthenticatorGetAssertion : CTAPauthenticator
    {
        // input param
        [DataMember()]
        public string RpId { get; set; }
        [DataMember()]
        public byte[] AllowList_CredentialId { get; set; }
        [DataMember()]
        public bool Option_up { get; set; }
        [DataMember()]
        public bool Option_uv { get; set; }
        [DataMember()]
        public byte[] PinAuth { get; set; }

        public byte[] ClientDataHash { get; set; }

        public async Task<CTAPResponseAssertion> SendAndResponse(DevParam devParam)
        {
            // check
            {
                if (RpId == null) RpId = "";
                if (ClientDataHash == null) ClientDataHash = new byte[0];
            }

            var cbor = CBORObject.NewMap();

            // 0x01 : rpid
            cbor.Add(0x01, RpId);

            // 0x02 : clientDataHash
            cbor.Add(0x02, ClientDataHash);

            // 0x03 : allowList
            if (AllowList_CredentialId != null) {
                var pubKeyCredParams = CBORObject.NewMap();
                pubKeyCredParams.Add("type", "public-key");
                pubKeyCredParams.Add("id", AllowList_CredentialId);
                cbor.Add(0x03, CBORObject.NewArray().Add(pubKeyCredParams));
            }

            // 0x05 : options
            {
                var opt = CBORObject.NewMap();
                opt.Add("up", Option_up);
                opt.Add("uv", Option_uv);
                cbor.Add(0x05, opt);
            }

            if (PinAuth != null) {
                // pinAuth(0x06)
                cbor.Add(0x06, PinAuth);
                // 0x07:pinProtocol
                cbor.Add(0x07, 1);
            }

            var resi = await sendCommandandResponse(devParam, 0x02, cbor);

            var response = new CTAPResponseAssertion(resi);
            response.CommandDataJson = this.payloadJson;

            return (response);
        }
    }
}
