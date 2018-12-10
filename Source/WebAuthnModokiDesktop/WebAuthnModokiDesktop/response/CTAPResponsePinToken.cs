using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;
using System.Runtime.InteropServices;       // dll

namespace WebAuthnModokiDesktop
{
    internal class CTAPResponsePinToken : CTAPResponse
    {
        public byte[] PinTokenEnc { get; set; }
        public CTAPResponsePinToken(CTAPauthenticator.CTAPResponseInner resi) : base(resi)
        {
            if (resi.ResponseDataCbor != null) {
                parse(resi.ResponseDataCbor);
            }
        }

        private void parse(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x02) {
                    PinTokenEnc = cbor[key].GetByteString();
                }
            }

        }

    }

}
