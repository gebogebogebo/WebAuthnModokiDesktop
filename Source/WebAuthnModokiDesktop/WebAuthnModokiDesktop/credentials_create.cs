using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using Newtonsoft.Json;
using System.IO;
using gebo.CTAP2;

namespace WebAuthnModokiDesktop
{

    public class createcommandstatus:commandstatus
    {
        public CTAPResponseAttestation attestation;
    }

    public partial class credentials
    {
        public static async Task<createcommandstatus> create(DevParam devParam, string publickeyJson,string pin="")
        {
            try {
                var publickey = JsonConvert.DeserializeObject<PublicKeyforCreate>(publickeyJson);
                publickey.pin = pin;
                return (await create(devParam, publickey));
            } catch (Exception ex) {
                var status = new createcommandstatus();
                status.msg = ex.Message.ToString();
                return (status);
            }
        }
        public static async Task<createcommandstatus> create(DevParam devParam, PublicKeyforCreate publickey)
        {
            var status = new createcommandstatus();

            try {
                if( publickey.rp == null || publickey.user == null || publickey.challenge == null) {
                    throw (new Exception("Param Error"));
                }

                var ctap = new CTAPauthenticatorMakeCredential();

                ctap.RpId = publickey.rp.id;
                ctap.RpName = publickey.rp.name;
                ctap.UserId = publickey.user.id;
                ctap.UserId_bytearray = publickey.user.id_bytearray;
                ctap.UserName = publickey.user.name;
                ctap.UserDisplayName = publickey.user.displayName;
                ctap.ClientDataHash = CTAPauthenticator.CreateClientDataHash(publickey.challenge);

                ctap.Option_rk = publickey.authenticatorSelection.requireResidentKey;
                if( publickey.authenticatorSelection.userVerification == UserVerificationRequirement.discouraged) {
                    ctap.Option_uv = false;
                } else {
                    ctap.Option_uv = true;
                }

                if ( publickey.pin.Length > 0 ) {
                    string pin = publickey.pin;

                    var ctap2 = new CTAPauthenticatorClientPIN();

                    var st1 = await ctap2.GetKeyAgreement(devParam);
                    status.commands.Add(new commandstatus.commandinfo(ctap2, st1));
                    if (st1.Status != 0x00) {
                        throw (new Exception("GetKeyAgreement"));
                    }

                    var sharedSecret = ctap2.createSharedSecret(ctap2.Authenticator_KeyAgreement);

                    var pinHashEnc = ctap2.createPinHashEnc(pin, sharedSecret);

                    var token = await ctap2.GetPINToken(devParam, pinHashEnc);
                    status.commands.Add(new commandstatus.commandinfo(ctap2, token));
                    if (token.Status != 0x00) {
                        throw (new Exception("GetPINToken"));
                    }

                    ctap.PinAuth = ctap2.createPinAuth(sharedSecret, ctap.ClientDataHash, token.PinTokenEnc);
                }

                var att = await ctap.SendAndResponse(devParam);
                status.commands.Add(new commandstatus.commandinfo(ctap, att));
                if (att.Status != 0x00) {
                    throw (new Exception("MakeCredential"));
                }

                status.attestation = att;
                status.isSuccess = true;
            } catch (Exception ex) {
                status.setErrorMsg(ex);
            }
            return status;
        }

        public static bool serializeAttestationToFile(CTAPResponseAttestation att,string pathname)
        {
            try {
                string path = Path.GetDirectoryName(pathname);

                if (Directory.Exists(path) == false) {
                    Directory.CreateDirectory(path);
                }
                JsonUtility.SerializeFile(att, pathname);
            } catch (Exception) {
                return false;
            }
            return true;
        }
        public static CTAPResponseAttestation deSerializeAttestationFromFile(string pathname)
        {
            CTAPResponseAttestation att;
            try {
                att = JsonUtility.DeserializeFile<CTAPResponseAttestation>(pathname);
            } catch (Exception) {
                return null;
            }
            return att;
        }

    }

    [DataContract]
    public enum UserVerificationRequirement
    {
        [EnumMember] required,
        [EnumMember] preferred,
        [EnumMember] discouraged
    };

    [DataContract]
    public class PublicKeyforCreate
    {
        public class Rp
        {
            [DataMember]
            public string id { get; set; }
            [DataMember]
            public string name { get; set; }
        };
        public class User
        {
            [DataMember]
            public string id { get; set; }          // string にしとく
            [DataMember]
            public byte[] id_bytearray { get; set; }
            [DataMember]
            public string name { get; set; }
            [DataMember]
            public string displayName { get; set; }
        };
        public class PubKeyCredParams
        {
            [DataMember]
            public string type { get; set; }
            [DataMember]
            public int alg { get; set; }
        };

        public class AuthenticatorSelection
        {
            public bool requireResidentKey { get; set; }
            public string authenticatorAttachment { get; set; }
            public UserVerificationRequirement userVerification { get; set; }
            public AuthenticatorSelection()
            {
                requireResidentKey = false;
                authenticatorAttachment = "";
                userVerification = UserVerificationRequirement.preferred;
            }
        }

        [DataMember]
        public Rp rp { get; set; }

        [DataMember]
        public User user { get; set; }

        [DataMember]
        public IList<PubKeyCredParams> pubKeyCredParams { get; set; }

        [DataMember]
        public AuthenticatorSelection authenticatorSelection { get; set; }

        [DataMember]
        public string attestation { get; set; }
        [DataMember]
        public int timeout { get; set; }
        [DataMember]
        public byte[] challenge { get; set; }

        public string pin { get; set; }

        public PublicKeyforCreate()
        {
            authenticatorSelection = new AuthenticatorSelection();
            attestation = "";
            timeout = 0;
            challenge = new byte[0];
            pin = "";
        }

    }

}
