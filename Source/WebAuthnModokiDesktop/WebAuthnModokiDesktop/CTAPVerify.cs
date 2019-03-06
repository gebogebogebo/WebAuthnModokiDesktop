using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace gebo.CTAP2.WebAuthnModokiDesktop
{
    public class CTAPVerify
    {
        public static bool Verify(CreateCommandStatus status)
        {
            foreach(var command in status.commands) {
                if (command.cmd.GetType() == typeof(CTAPauthenticatorMakeCredential)) {
                    var make = ((CTAPauthenticatorMakeCredential)(command.cmd));
                    return(Verify(make.RpId, make.ClientDataHash, status.attestation));
                }
            }
            return (false);
        }

        public static bool Verify(string rpid,byte[] clientDataHash,CTAPResponseAttestation attestation)
        {
            bool verify = false;
            try {
                // SHA-256(rpid) == attestation.RpIdHash
                {
                    byte[] rpidbyte = Encoding.ASCII.GetBytes(rpid);
                    SHA256 sha = new SHA256CryptoServiceProvider();
                    byte[] rpidbytesha = sha.ComputeHash(rpidbyte);
                    if (rpidbytesha.SequenceEqual(attestation.RpIdHash) == false) {
                        // verify error
                        throw (new Exception("verify failed CTAPResponseAttestation.RpIdHash"));
                    }
                }

                // flags - skip

                // counter - skip

                // SigBase = authData + clientDataHash
                var sigBase = new List<byte>();
                sigBase.AddRange(attestation.AuthData.ToList());
                sigBase.AddRange(clientDataHash.ToList());

                // Verify
                string certPem = CTAPVerify.ConvertCertificateDERtoPEM(attestation.AttStmtX5c);
                var pubKeyPem = BCVerify.GetPublicKeyPEMfromCert(certPem);
                if( BCVerify.VerifySignature(sigBase.ToArray(), pubKeyPem, attestation.AttStmtSig) == false) {
                    // verify error
                    throw (new Exception("verify failed Signature"));
                }

                verify = true;
            } catch (Exception) {
            }
            return (verify);
        }

        public static bool Verify(GetCommandStatus status, byte[] publickey,int assertion_index=0)
        {
            if( status.assertions.Count <= 0 || status.assertions.Count < assertion_index+1) {
                return (false);
            }

            var pubkeypem = ConvertCOSEtoPEM(publickey);

            foreach (var command in status.commands) {
                if (command.cmd.GetType() == typeof(CTAPauthenticatorGetAssertion)) {
                    var get = ((CTAPauthenticatorGetAssertion)(command.cmd));

                    // verify assertion
                    return (Verify(get.RpId, get.ClientDataHash, pubkeypem, status.assertions[assertion_index]));
                }
            }
            return (false);
        }

        public static bool Verify(string rpid, byte[] clientDataHash,string pubkeypem,CTAPResponseAssertion assertion)
        {
            bool verify = false;
            try {
                // SHA-256(rpid) == attestation.RpIdHash
                {
                    byte[] rpidbyte = Encoding.ASCII.GetBytes(rpid);
                    SHA256 sha = new SHA256CryptoServiceProvider();
                    byte[] rpidbytesha = sha.ComputeHash(rpidbyte);
                    if (rpidbytesha.SequenceEqual(assertion.RpIdHash) == false) {
                        // verify error;
                        throw (new Exception("verify failed CTAPResponseAssertion.RpIdHash"));
                    }
                }

                // flags - skip

                // counter - skip

                // SigBase = authData + clientDataHash
                var sigBase = new List<byte>();
                sigBase.AddRange(assertion.AuthData.ToList());
                sigBase.AddRange(clientDataHash.ToList());

                // Verify
                if (BCVerify.VerifySignature(sigBase.ToArray(), pubkeypem, assertion.Signature) == false) {
                    // verify error
                    throw (new Exception("verify failed Signature"));
                }

                verify = true;

            } catch (Exception) {
            }
            return (verify);
        }

        public static string ConvertCertificateDERtoPEM(byte[] certificateDER)
        {
            // DER形式の証明書をPEM形式に変換する
            //     DER -> 鍵や証明書をASN.1というデータ構造で表し、それをシリアライズしたバイナリファイル
            //     PEM -> DERと同じASN.1のバイナリデータをBase64によってテキスト化されたファイル 
            // 1.Base64エンコード
            // 2.64文字ごとに改行コードをいれる
            // 3.ヘッダとフッタを入れる

            var b64cert = Convert.ToBase64String(certificateDER);

            string pemdata = "";
            int roopcount = (int)Math.Ceiling(b64cert.Length / 64.0f);
            for (int intIc = 0; intIc < roopcount; intIc++) {
                int start = 64 * intIc;
                if (intIc == roopcount - 1) {
                    pemdata = pemdata + b64cert.Substring(start) + "\n";
                } else {
                    pemdata = pemdata + b64cert.Substring(start, 64) + "\n";
                }
            }
            pemdata = string.Format("-----BEGIN CERTIFICATE-----\n") + pemdata + string.Format("-----END CERTIFICATE-----\n");

            return pemdata;
        }

        public static string ConvertCOSEtoPEM(byte[] cose)
        {
            // COSE形式の公開鍵をPEM形式に変換する
            // 1-1.26byteのメタデータを追加
            // 1-2.0x04を追加
            // 1-3.COSEデータのxとyを追加
            // 2-1.Base64エンコード
            // 2-2.64文字ごとに改行コードをいれる
            // 2-3.ヘッダとフッタを入れる

            string pemdata = "";
            try {
                // Phase-1
                var pubkey = new List<byte>();
                var metaheader = Common.HexStringToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
                pubkey.AddRange(metaheader);

                pubkey.Add(0x04);
                var cbor = PeterO.Cbor.CBORObject.DecodeFromBytes(cose, PeterO.Cbor.CBOREncodeOptions.Default);
                foreach (var key in cbor.Keys) {
                    if (key.Type == PeterO.Cbor.CBORType.Number) {
                        var keyVal = key.AsInt16();
                        if (keyVal == -2) {
                            var x = cbor[key].GetByteString();
                            pubkey.AddRange(x);
                        } else if (keyVal == -3) {
                            var y = cbor[key].GetByteString();
                            pubkey.AddRange(y);
                        }
                    }
                }

                // Phase-2
                var b64pubkey = Convert.ToBase64String(pubkey.ToArray());

                int roopcount = (int)Math.Ceiling(b64pubkey.Length / 64.0f);
                for (int intIc = 0; intIc < roopcount; intIc++) {
                    int start = 64 * intIc;
                    if (intIc == roopcount - 1) {
                        pemdata = pemdata + b64pubkey.Substring(start) + "\n";
                    } else {
                        pemdata = pemdata + b64pubkey.Substring(start, 64) + "\n";
                    }
                }
                pemdata = string.Format("-----BEGIN PUBLIC KEY-----\n") + pemdata + string.Format("-----END PUBLIC KEY-----\n");

            } catch (Exception) {

            }
            return (pemdata);
        }

    }
}
