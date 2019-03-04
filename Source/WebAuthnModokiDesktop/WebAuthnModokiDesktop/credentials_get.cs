using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Runtime.Serialization;
using Newtonsoft.Json;
using gebo.CTAP2;

namespace gebo.CTAP2.WebAuthnModokiDesktop
{
    public class GetCommandStatus : CommandStatus
    {
        public List<CTAPResponseAssertion> assertions;
        public GetCommandStatus() : base()
        {
            assertions = new List<CTAPResponseAssertion>();
        }
    }

    public partial class Credentials
    {
        public static async Task<GetCommandStatus> Get(DevParam devParam, string publickeyJson, string pin = "")
        {
            try {
                var publickey = JsonConvert.DeserializeObject<PublicKeyforGet>(publickeyJson);
                publickey.pin = pin;
                return (await Get(devParam, publickey));
            } catch (Exception ex) {
                var status = new GetCommandStatus();
                status.msg = ex.Message.ToString();
                return (status);
            }
        }

        public static async Task<GetCommandStatus> Get(DevParam devParam, PublicKeyforGet publickey)
        {
            var status = new GetCommandStatus();

            try {

                string rpid = publickey.rpId;

                var ctap = new CTAPauthenticatorGetAssertion();
                ctap.RpId = rpid;
                ctap.ClientDataHash = CTAPauthenticator.CreateClientDataHash(publickey.challenge);

                // credential-id
                if( publickey.allowCredentials != null &&
                    publickey.allowCredentials.Count > 0 &&
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

                    var st1 = await ctap2.GetKeyAgreement(devParam);
                    status.commands.Add(new CommandStatus.CommandInfo(ctap2, st1));
                    if (st1.Status != 0x00) {
                        throw (new Exception("GetKeyAgreement"));
                    }

                    var sharedSecret = ctap2.createSharedSecret(ctap2.Authenticator_KeyAgreement);

                    var pinHashEnc = ctap2.createPinHashEnc(pin, sharedSecret);

                    var token = await ctap2.GetPINToken(devParam, pinHashEnc);
                    status.commands.Add(new CommandStatus.CommandInfo(ctap2, token));
                    if (token.Status != 0x00) {
                        throw (new Exception("GetPINToken"));
                    }

                    ctap.PinAuth = ctap2.createPinAuth(sharedSecret, ctap.ClientDataHash, token.PinTokenEnc);
                }

                var ret = await ctap.SendAndResponse(devParam);
                status.commands.Add(new CommandStatus.CommandInfo(ctap, ret));
                if (ret.Status != 0x00) {
                    throw (new Exception("GetAssertion"));
                }
                status.assertions.Add(ret);

                if (ret.NumberOfCredentials > 0) {
                    for (int intIc = 0; intIc < ret.NumberOfCredentials - 1; intIc++) {
                        var next = new CTAPauthenticatorGetNextAssertion();
                        var nextret = await next.SendAndResponse(devParam);
                        status.commands.Add(new CommandStatus.CommandInfo(next, nextret));
                        if (ret.Status != 0x00) {
                            throw (new Exception("GetNextAssertion"));
                        }
                        status.assertions.Add(nextret);
                    }
                }

                status.isSuccess = true;
            } catch (Exception ex) {
                status.setErrorMsg(ex);
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
