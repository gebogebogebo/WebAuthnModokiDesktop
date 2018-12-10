using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using Newtonsoft.Json;

using WebAuthnModokiDesktop;

namespace WebAuthnModokiDesktop
{
    public class getcommoandstatus : commoandstatus
    {
        public List<CTAPResponseAssertion> assertions;
        public getcommoandstatus() : base()
        {
            assertions = new List<CTAPResponseAssertion>();
        }
    }

    public partial class credentials
    {
        public static async Task<getcommoandstatus> get(string json, string pin = "")
        {
            try {
                var publickey = JsonConvert.DeserializeObject<PublicKeyforGet>(json);
                publickey.pin = pin;
                return (await get(publickey));
            } catch (Exception ex) {
                var status = new getcommoandstatus();
                status.msg = ex.Message.ToString();
                return (status);
            }
        }
        public static async Task<getcommoandstatus> get(PublicKeyforGet publickey)
        {
            var status = new getcommoandstatus();

            try {

                string rpid = publickey.rpId;

                var ctap = new CTAPauthenticatorGetAssertion();
                ctap.RpId = rpid;
                ctap.ClientDataHash = CTAPauthenticator.CreateClientDataHash(publickey.challenge);

                // credential-id
                if( publickey.allowCredentials.Count > 0 &&
                    publickey.allowCredentials[0] != null &&
                    publickey.allowCredentials[0].id != null &&
                    publickey.allowCredentials[0].id.Length > 0) {
                    ctap.AllowList_CredentialId = publickey.allowCredentials[0].id;
                }

                ctap.Option_up = publickey.requireUserPresence;

                if (publickey.userVerification == UserVerificationRequirement.discouraged) {
                    ctap.Option_uv = false;
                } else {
                    ctap.Option_uv = true;
                }

                // pin
                if (publickey.pin.Length > 0 ) {
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

                var ret = await ctap.SendAndResponse();
                status.commands.Add(new commoandstatus.commandinfo(ctap, ret));
                if (ret.Status != 0x00) {
                    return status;
                }
                status.assertions.Add(ret);

                if (ret.NumberOfCredentials > 0) {
                    for (int intIc = 0; intIc < ret.NumberOfCredentials - 1; intIc++) {
                        var next = new CTAPauthenticatorGetNextAssertion();
                        var nextret = await next.SendAndResponse();
                        status.commands.Add(new commoandstatus.commandinfo(next, nextret));
                        if (ret.Status != 0x00) {
                            return status;
                        }
                        status.assertions.Add(nextret);
                    }
                }

                status.isSuccess = true;
            } catch (Exception ex) {
                status.msg = ex.Message.ToString();
                return (status);
            }
            return status;
        }
    }

    [DataContract]
    public class PublicKeyforGet
    {
        [DataMember]
        public int timeout { get; set; }
        [DataMember]
        public byte[] challenge { get; set; }
        [DataMember]
        public string rpId { get; set; }

        public class AllowCredentials
        {
            [DataMember]
            public byte[] id { get; set; }
        };

        public class Rp
        {
            [DataMember]
            public string id { get; set; }
        };

        [DataMember]
        public IList<AllowCredentials> allowCredentials { get; set; }
        [DataMember]
        public bool requireUserPresence { get; set; }
        [DataMember]
        public UserVerificationRequirement userVerification { get; set; }

        public string pin { get; set; }

        public PublicKeyforGet()
        {
            pin = "";
        }
    }

}
