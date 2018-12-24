using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace WebAuthnModokiDesktop
{
    public class CTAPResponseAssertion : CTAPResponse
    {
        public byte[] RpIdHash { get; set; }
        public bool Flags_UserPresentResult { get; set; }
        public bool Flags_UserVerifiedResult { get; set; }
        public bool Flags_AttestedCredentialDataIncluded { get; set; }
        public bool Flags_ExtensionDataIncluded { get; set; }

        public int SignCount { get; set; }
        public byte[] Aaguid { get; set; }

        public int NumberOfCredentials { get; set; }

        public byte[] Signature { get; set; }
        public byte[] User_Id { get; set; }
        public string User_Name { get; set; }
        public string User_DisplayName { get; set; }

        public byte[] AuthData { get; set; }

        public CTAPResponseAssertion(CTAPauthenticator.CTAPResponseInner resi) : base(resi)
        {
            SignCount = 0;
            Aaguid = new byte[0];
            NumberOfCredentials = 0;
            Signature = new byte[0];
            User_Id = new byte[0];
            User_Name = "";
            User_DisplayName = "";

            if (resi.ResponseDataCbor != null) {
                parse(resi.ResponseDataCbor);
            }
        }

        private void parse(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x01) {
                    // 0x01:credential
                } else if (keyVal == 0x02) {
                    parseAuthData(cbor[key].GetByteString());
                } else if (keyVal == 0x03) {
                    // 0x03:signature
                    Signature = cbor[key].GetByteString();
                } else if (keyVal == 0x04) {
                    parsePublicKeyCredentialUserEntity(cbor[key]);
                } else if (keyVal == 0x05) {
                    // 0x05:numberOfCredentials
                    NumberOfCredentials = cbor[key].AsUInt16();

                }
            }
        }

        private void parseAuthData(byte[] data)
        {
            int index = 0;

            // rpIdHash	(32)
            RpIdHash = data.Skip(index).Take(32).ToArray();
            index = index + 32;

            // flags(1)
            {
                byte flags = data[index];
                index++;
                Flags_UserPresentResult = Common.GetBit(flags, 0);
                Flags_UserVerifiedResult = Common.GetBit(flags, 2);
                Flags_AttestedCredentialDataIncluded = Common.GetBit(flags, 6);
                Flags_ExtensionDataIncluded = Common.GetBit(flags, 7);
            }

            // signCount(4)
            {
                SignCount = Common.ToInt32(data, index, true);
                index = index + 4;
            }

            // aaguid	16
            Aaguid = data.Skip(index).Take(16).ToArray();
            index = index + 16;

            AuthData = data;
        }

        private void parsePublicKeyCredentialUserEntity(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsString();
                if (keyVal == "id") {
                    User_Id = cbor[key].GetByteString();
                } else if (keyVal == "name") {
                    User_Name = cbor[key].AsString();
                } else if (keyVal == "displayName") {
                    User_DisplayName = cbor[key].AsString();
                }
            }

        }

    }
}
