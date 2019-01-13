using System;
using System.Collections.Generic;
using System.Linq;

using System.Threading.Tasks;
using PeterO.Cbor;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using WebAuthnModokiDesktop;

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
            public byte Status { get; set; }
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

        protected async Task<CTAPResponseInner> sendCommandandResponse(devparam devParam, byte command, CBORObject payload)
        {
            byte[] send = null;

            payloadJson = string.Format($"[0x{command:X2}]({getCommandName(command)})");
            if (payload != null) {
                payloadJson = payloadJson + payload.ToJSONString();
                Console.WriteLine($"Send: {payloadJson}");

                var payloadb = payload.EncodeToBytes();
                send = new byte[] { command }.Concat(payloadb).ToArray();
            } else {
                send = new byte[] { command };
            }
            return (await sendCommandandResponse(devParam, send));
        }

        protected static async Task<CTAPResponseInner> sendCommandandResponse(devparam devParam, byte[] send)
        {
            var response = new CTAPResponseInner();

            byte[] byteresponse = null;

            // HID
            if ( devParam.hidparams != null) {
                byteresponse = await CTAPHID.SendCommandandResponse(devParam.hidparams, send);
            }

            // NFC
            if (byteresponse == null && devParam.nfcparams != null) {
                byteresponse = CTAPNFC.SendCommandandResponse(devParam.nfcparams, send);
            }

            if (byteresponse == null) {
                response.Status = 0xff;
                return response;
            }
            response.Status = byteresponse[0];

            if (byteresponse.Length > 1) {
                var cobrbyte = byteresponse.Skip(1).ToArray();
                response.ResponseDataCbor = CBORObject.DecodeFromBytes(cobrbyte, CBOREncodeOptions.Default);

                var json = response.ResponseDataCbor.ToJSONString();
                Console.WriteLine($"Recv: {json}");
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
