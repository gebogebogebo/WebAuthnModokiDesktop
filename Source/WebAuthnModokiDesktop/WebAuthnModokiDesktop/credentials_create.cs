using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using Newtonsoft.Json;

using WebAuthnModokiDesktop;

namespace WebAuthnModokiDesktop
{
    public class createcommoandstatus:commoandstatus
    {
        public CTAPResponseAttestation attestation;
    }

    public partial class credentials
    {
        public static async Task<createcommoandstatus> create(string json,string pin="")
        {
            try {
                var publickey = JsonConvert.DeserializeObject<CreatePublicKey>(json);
                publickey.pin = pin;
                return (await create(publickey));
            } catch (Exception ex) {
                var status = new createcommoandstatus();
                status.msg = ex.Message.ToString();
                return (status);
            }
        }
        public static async Task<createcommoandstatus> create(CreatePublicKey publickey)
        {
            var status = new createcommoandstatus();

            try {
                if( publickey.rp == null || publickey.user == null || publickey.challenge == null) {
                    return status;
                }

                var ctap = new CTAPauthenticatorMakeCredential();

                ctap.RpId = publickey.rp.id;
                ctap.RpName = publickey.rp.name;
                ctap.UserId = publickey.user.id;
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

                    var st1 = await ctap2.GetKeyAgreement();
                    status.commands.Add(new commoandstatus.commandinfo(ctap2, st1));
                    if (st1.Status != 0x00) {
                        return status;
                    }

                    var sharedSecret = ctap2.createSharedSecret(ctap2.Authenticator_KeyAgreement);

                    var pinHashEnc = ctap2.createPinHashEnc(pin, sharedSecret);

                    var token = await ctap2.GetPINToken(pinHashEnc);
                    status.commands.Add(new commoandstatus.commandinfo(ctap2, token));
                    if (token.Status != 0x00) {
                        return status;
                    }

                    ctap.PinAuth = ctap2.createPinAuth(sharedSecret, ctap.ClientDataHash, token.PinTokenEnc);
                }

                var att = await ctap.SendAndResponse();
                status.commands.Add(new commoandstatus.commandinfo(ctap, att));
                if (att.Status != 0x00) {
                    return status;
                }

                status.attestation = att;
                status.isSuccess = true;
            } catch (Exception ex) {
                status.msg = ex.Message.ToString();
                return (status);
            }
            return status;
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
    public class CreatePublicKey
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

        public CreatePublicKey()
        {
            //rp = new Rp();
            //user = new User();
            //pubKeyCredParams = new List<PubKeyCredParams>();
            authenticatorSelection = new AuthenticatorSelection();
            attestation = "";
            timeout = 0;
            challenge = new byte[0];
            pin = "";
        }

    }

}
