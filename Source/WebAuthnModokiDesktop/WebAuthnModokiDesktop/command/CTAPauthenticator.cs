using System;
using System.Collections.Generic;
using System.Linq;

using System.Threading.Tasks;
using PeterO.Cbor;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace gebo.CTAP2
{
    [DataContract]
    public class CTAPauthenticator
    {
        [DataMember()]
        public string payloadJson { get; private set; }

        public class CTAPResponseInner
        {
            public CTAPResponseInner()
            {

            }

            public int Status { get; set; }

            // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#error-responses
            // 6.3. Status codes
            public byte StatusCodeCTAP { get; set; }

            public CBORObject ResponseDataCbor { get; set; }
        }

        public CTAPauthenticator()
        {

        }

        private static string getCommandName(byte command)
        {
            string name= "";
            switch (command) {
                case 0x01:
                    name = "authenticatorMakeCredential";
                    break;
                case 0x02:
                    name = "authenticatorGetAssertion";
                    break;
                case 0x04:
                    name = "authenticatorGetInfo ";
                    break;
                case 0x06:
                    name = "authenticatorClientPIN";
                    break;
                case 0x08:
                    name = "authenticatorGetNextAssertion ";
                    break;
            }
            return (name);
        }

        protected async Task<CTAPResponseInner> sendCommandandResponse(DevParam devParam, byte command, CBORObject payload,int timeoutms=0)
        {
            byte[] send = null;

            payloadJson = string.Format($"[0x{command:X2}]({getCommandName(command)})");
            if (payload != null) {
                payloadJson = payloadJson + payload.ToJSONString();
                System.Diagnostics.Debug.WriteLine($"Send: {payloadJson}");

                var payloadb = payload.EncodeToBytes();
                send = new byte[] { command }.Concat(payloadb).ToArray();
            } else {
                send = new byte[] { command };
            }
            return (await sendCommandandResponse(devParam, send, timeoutms));
        }

        protected static async Task<CTAPResponseInner> sendCommandandResponse(DevParam devParam, byte[] send,int timeoutms)
        {
            var response = new CTAPResponseInner();

            byte[] byteresponse = null;

            // HID
            if ( devParam.hidparams != null) {
                var res = await CTAPHID.SendCommandandResponse(devParam.hidparams, send, timeoutms);
                if( res != null) {
                    if (res.isTimeout == true) {
                        response.Status = -2;
                        return response;
                    }
                    byteresponse = res.responseData;
                }
            }

            // NFC
            if (byteresponse == null && devParam.nfcparams != null) {
                byteresponse = CTAPNFC.SendCommandandResponse(devParam.nfcparams, send);
            }

            if (byteresponse == null) {
                response.Status = -1;
                return response;
            }
            response.StatusCodeCTAP = byteresponse[0];

            if (byteresponse.Length > 1) {
                try {
                    var cobrbyte = byteresponse.Skip(1).ToArray();
                    response.ResponseDataCbor = CBORObject.DecodeFromBytes(cobrbyte, CBOREncodeOptions.Default);

                    var json = response.ResponseDataCbor.ToJSONString();
                    System.Diagnostics.Debug.WriteLine($"Recv: {json}");
                } catch (Exception ex) {
                    System.Diagnostics.Debug.WriteLine($"CBOR DecordError:{ex.Message}");
                }
            }

            return (response);
        }

        static public byte[] CreateClientDataHash(string challenge)
        {
            byte[] input = System.Text.Encoding.ASCII.GetBytes(challenge);
            return (CreateClientDataHash(input));
        }
        static public byte[] CreateClientDataHash(byte[] challenge)
        {
            SHA256 sha = new SHA256CryptoServiceProvider();
            var cdh = sha.ComputeHash(challenge);
            return (cdh);
        }

    }
}
