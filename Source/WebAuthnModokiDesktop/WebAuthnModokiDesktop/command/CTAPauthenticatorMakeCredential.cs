using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;
using System.Security.Cryptography;
using System.Runtime.Serialization;

namespace WebAuthnModokiDesktop
{
    [DataContract]
    public class CTAPauthenticatorMakeCredential : CTAPauthenticator
    {
        // input param

        [DataMember()]
        public string RpId { get; set; }
        [DataMember()]
        public string RpName { get; set; }
        [DataMember()]
        public string UserId { get; set; }
        [DataMember()]
        public string UserName { get; set; }
        [DataMember()]
        public string UserDisplayName { get; set; }
        [DataMember()]
        public bool Option_rk { get; set; }
        [DataMember()]
        public bool Option_uv { get; set; }
        [DataMember()]
        public byte[] PinAuth { get; set; }

        public byte[] ClientDataHash { get; set; }

        public async Task<CTAPResponseAttestation> SendAndResponse()
        {
            var cbor = CBORObject.NewMap();

            // 0x01 : clientDataHash
            cbor.Add(0x01, ClientDataHash);

            // 0x02 : rp
            cbor.Add(0x02, CBORObject.NewMap().Add("id", RpId).Add("name", RpName));

            // 0x03 : user
            {
                var user = CBORObject.NewMap();
                user.Add("id", Encoding.ASCII.GetBytes(UserId));
                user.Add("name", UserName);
                user.Add("displayName", UserDisplayName);
                cbor.Add(0x03, user);
            }

            // 0x04 : pubKeyCredParams
            {
                var pubKeyCredParams = CBORObject.NewMap();
                pubKeyCredParams.Add("alg", -7);
                pubKeyCredParams.Add("type", "public-key");
                cbor.Add(0x04, CBORObject.NewArray().Add(pubKeyCredParams));
            }

            // 0x07 : options
            {
                var opt = CBORObject.NewMap();
                opt.Add("rk", Option_rk);
                opt.Add("uv", Option_uv);
                cbor.Add(0x07, opt);
            }

            if(PinAuth != null) {
                // pinAuth(0x08)
                cbor.Add(0x08, PinAuth);

                // 0x09:pinProtocol
                cbor.Add(0x09, 1);
            }

            var resi = await sendCommandandResponse(0x01, cbor);

            var response = new CTAPResponseAttestation(resi);
            response.CommandDataJson = this.payloadJson;
            return (response);
        }

    }

}
