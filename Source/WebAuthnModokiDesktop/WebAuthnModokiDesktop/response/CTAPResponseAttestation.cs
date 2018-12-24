using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;
using System.Runtime.Serialization;

namespace WebAuthnModokiDesktop
{
    [DataContract]
    public class CTAPResponseAttestation : CTAPResponse
    {
        public string Fmt { get; set; }
        public byte[] RpIdHash { get; set; }

        [DataMember()]
        public bool Flags_UserPresentResult { get; set; }
        [DataMember()]
        public bool Flags_UserVerifiedResult { get; set; }
        [DataMember()]
        public bool Flags_AttestedCredentialDataIncluded { get; set; }
        [DataMember()]
        public bool Flags_ExtensionDataIncluded { get; set; }

        [DataMember()]
        public int SignCount { get; set; }
        [DataMember()]
        public byte[] Aaguid { get; set; }

        [DataMember()]
        public byte[] CredentialId { get; set; }

        [DataMember()]
        public string CredentialPublicKey { get; set; }

        [DataMember()]
        public byte[] CredentialPublicKeyByte { get; set; }

        [DataMember()]
        public byte[] AuthData { get; set; }

        public int AttStmtAlg { get; set; }
        public byte[] AttStmtSig { get; set; }
        public byte[] AttStmtX5c { get; set; }

        public CTAPResponseAttestation(CTAPauthenticator.CTAPResponseInner resi) : base(resi)
        {
            if (resi.ResponseDataCbor != null) {
                parse(resi.ResponseDataCbor);
            }
        }

        private void parse(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x01) {
                    // fmt
                    Fmt = cbor[key].AsString();
                } else if (keyVal == 0x02) {
                    // authData
                    parseAuthData(cbor[key].GetByteString());
                } else if (keyVal == 0x03) {
                    // attstmt
                    parseAttstmt(cbor[key]);
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

            // credentialId
            {
                int credentialIdLength = Common.ToInt16(data, index, true);
                index = index + 2;

                CredentialId = data.Skip(index).Take(credentialIdLength).ToArray();
                index = index + credentialIdLength;
            }

            // credentialPublicKey
            {
                CredentialPublicKeyByte = data.Skip(index).ToArray();
                var credentialPublicKeyCobr = CBORObject.DecodeFromBytes(CredentialPublicKeyByte, CBOREncodeOptions.Default);
                CredentialPublicKey = credentialPublicKeyCobr.ToJSONString();
                Console.WriteLine("credentialPublicKeyCobr:" + CredentialPublicKey);
            }

            AuthData = data;
        }

        private void parseAttstmt(CBORObject attestationStatementCbor)
        {
            var attestationStatement = attestationStatementCbor.ToJSONString();
            Console.WriteLine("attestationStatement:" + attestationStatement);

            foreach (var key in attestationStatementCbor.Keys) {
                var keyVal = key.AsString();
                if (keyVal == "alg") {
                    AttStmtAlg = attestationStatementCbor[key].AsInt16();
                } else if (keyVal == "sig") {
                    AttStmtSig = attestationStatementCbor[key].GetByteString();
                } else if (keyVal == "x5c") {
                    foreach (var sub in attestationStatementCbor[key].Values) {
                        AttStmtX5c = sub.GetByteString();
                        break;
                    }
                }
            }

        }

    }

}
