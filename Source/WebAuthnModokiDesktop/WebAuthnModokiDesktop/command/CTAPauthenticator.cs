using System;
using System.Collections.Generic;
using System.Linq;

using System.Threading.Tasks;
using u2fhost;
using HidLibrary;
using PeterO.Cbor;
using System.Runtime.Serialization;
using System.Security.Cryptography;

namespace WebAuthnModokiDesktop
{
    [DataContract]
    public class CTAPauthenticator
    {
        public const int VENDOR_ID = 0x1050;
        public const int PRODUCT_ID = 0x0120;
        public List<hidparam> HidParams = null;

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

        protected async Task<CTAPResponseInner> sendCommandandResponse(byte command, CBORObject payload)
        {
            byte[] send = null;

            payloadJson = string.Format($"[0x{command:X2}]({getCommandName(command)})");
            if( payload != null) {
                payloadJson = payloadJson + payload.ToJSONString();
                Console.WriteLine($"Send: {payloadJson}");

                var payloadb = payload.EncodeToBytes();
                send = new byte[] { command }.Concat(payloadb).ToArray();
            }else {
                send = new byte[] { command };
            }
            return (await sendCommandandResponse(send));
        }

        protected static async Task<CTAPResponseInner> sendCommandandResponse(byte[] send)
        {
            var response = new CTAPResponseInner();

            IHidDevice hidDevice = null;
            using (hidDevice = HidDevices.Enumerate(VENDOR_ID, PRODUCT_ID).FirstOrDefault()) {
                if(hidDevice == null) {
                    response.Status = 0xff;
                    return response;
                }
                using (var u2fHidDevice = await CTAPHID.OpenAsync(hidDevice)) {

                    var byteresponse = await u2fHidDevice.CborAsync(send);

                    response.Status = byteresponse[0];

                    if (byteresponse.Length > 1) {
                        var cobrbyte = byteresponse.Skip(1).ToArray();
                        response.ResponseDataCbor = CBORObject.DecodeFromBytes(cobrbyte, CBOREncodeOptions.Default);

                        var json = response.ResponseDataCbor.ToJSONString();
                        Console.WriteLine($"Recv: {json}");

                    }
                }
            }
            return (response);
        }

        IHidDevice HidDevice = null;
        CTAPHID U2fHidDevice = null;

        public static HidDevice open(List<hidparam> hidparams)
        {
            HidDevice device = null;
            foreach (var hidparam in hidparams) {
                if (hidparam.ProductId == 0x00) {
                    device = HidDevices.Enumerate(hidparam.VendorId).FirstOrDefault();
                    if (device != null) {
                        break;
                    }
                } else {
                    device = HidDevices.Enumerate(hidparam.VendorId, hidparam.ProductId).FirstOrDefault();
                    if (device != null) {
                        break;
                    }
                }
            }
            return (device);
        }

        public async Task<bool> open()
        {
            HidDevice = HidDevices.Enumerate(VENDOR_ID, PRODUCT_ID).FirstOrDefault();
            U2fHidDevice = await CTAPHID.OpenAsync(HidDevice);

            return (true);
        }
        public void close()
        {
            U2fHidDevice.Dispose();
            HidDevice.Dispose();
            U2fHidDevice = null;
            HidDevice = null;
        }

        protected async Task<CTAPResponseInner> sendCommandandResponse2(byte command, CBORObject payload)
        {
            byte[] send = null;

            payloadJson = string.Format($"[0x{command:X2}]");
            if (payload != null) {
                payloadJson = payloadJson + payload.ToJSONString();
                Console.WriteLine($"Send: {payloadJson}");

                var payloadb = payload.EncodeToBytes();
                send = new byte[] { command }.Concat(payloadb).ToArray();
            } else {
                send = new byte[] { command };
            }
            return (await sendCommandandResponse2(send));
        }

        protected async Task<CTAPResponseInner> sendCommandandResponse2(byte[] send)
        {
            var response = new CTAPResponseInner();

            var byteresponse = await U2fHidDevice.CborAsync(send);

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
