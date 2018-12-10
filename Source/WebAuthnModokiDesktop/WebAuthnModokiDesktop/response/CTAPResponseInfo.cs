using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace WebAuthnModokiDesktop
{
    internal class CTAPResponseInfo:CTAPResponse
    {
        public string[] Versions{ get; private set; }
        public string[] Extensions { get; private set; }
        public byte[] Aaguid { get; private set; }
        public bool Option_rk { get; private set; }
        public bool Option_up { get; private set; }
        public bool Option_plat { get; private set; }
        public bool Option_clientPin { get; private set; }
        public int MaxMsgSize { get; private set; }
        public int[] PinProtocols { get; private set; }

        public CTAPResponseInfo(CTAPauthenticator.CTAPResponseInner resi) : base(resi)
        {
            if( resi.ResponseDataCbor != null) {
                parse(resi.ResponseDataCbor);
            }
        }
        private void parse(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x01) {
                    Versions = getKeyValueAsStringArray(cbor[key]);
                } else if (keyVal == 0x02) {
                    Extensions = getKeyValueAsStringArray(cbor[key]);
                } else if (keyVal == 0x03) {
                    Aaguid = cbor[key].GetByteString();
                } else if (keyVal == 0x04) {
                    Option_rk = getKeyValueAsBool(cbor[key], "rk");
                    Option_up = getKeyValueAsBool(cbor[key], "up");
                    Option_plat = getKeyValueAsBool(cbor[key], "plat");
                    Option_clientPin = getKeyValueAsBool(cbor[key], "clientPin");
                } else if (keyVal == 0x05) {
                    MaxMsgSize = cbor[key].AsInt16();
                } else if (keyVal == 0x06) {
                    PinProtocols = getKeyValueAsIntArray(cbor[key]);
                }
            }

        }

    }
}
