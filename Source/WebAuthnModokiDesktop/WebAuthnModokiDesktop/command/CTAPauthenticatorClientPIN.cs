using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;
using System.Security.Cryptography;
using System.Runtime.InteropServices;       // dll

namespace gebo.CTAP2
{
    internal class CTAPauthenticatorClientPIN : CTAPauthenticator
    {
        [DllImport("SharedSecret.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        static extern int CreateSharedSecret(string aG_x,string aG_y,StringBuilder bG_x, StringBuilder bG_y, StringBuilder sharedSecret);
        [DllImport("SharedSecret.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        static extern int Aes256cbc_Enc(string key, string inbuf, StringBuilder outbuf);
        [DllImport("SharedSecret.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        static extern int Aes256cbc_Dec(string key, string inbuf, StringBuilder outbuf);

        public int RetryCount { get; private set; }
        public async Task<CTAPResponse> GetRetries(DevParam devParam)
        {
            var response = new CTAPResponse();

            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x01:getRetries
            cbor.Add(0x02, 0x01);

            var resi = await sendCommandandResponse(devParam, 0x06, cbor);
            if (resi.ResponseDataCbor != null) {
                foreach (var key in resi.ResponseDataCbor.Keys) {
                    var keyVal = key.AsByte();
                    if (keyVal == 0x03) {
                        RetryCount = resi.ResponseDataCbor[key].AsUInt16();
                        break;
                    }
                }

                var json = resi.ResponseDataCbor.ToJSONString();
                Console.WriteLine(json);
                response.ResponseDataJson = json;
            }
            response.Status = resi.Status;

            return (response);
        }

        public KeyAgreement Authenticator_KeyAgreement { get; private set; }
        public KeyAgreement My_KeyAgreement { get; private set; }

        public async Task<CTAPResponse> GetKeyAgreement(DevParam devParam)
        {
            var response = new CTAPResponse();

            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x02:getKeyAgreement
            cbor.Add(0x02, 0x02);

            {
                var resi = await sendCommandandResponse(devParam, 0x06, cbor);

                if (resi.ResponseDataCbor != null) {
                    var json = resi.ResponseDataCbor.ToJSONString();
                    Console.WriteLine(json);
                    response.ResponseDataJson = json;

                    Authenticator_KeyAgreement = new KeyAgreement(resi.ResponseDataCbor);
                }
                response.Status = resi.Status;
            }

            return (response);
        }

        public async Task<CTAPResponse> SetPIN(DevParam devParam, byte[] pinAuth,byte[] newPinEnc)
        {
            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x03:setPIN
            cbor.Add(0x02, 0x03);

            // 0x03:keyAgreement : COSE_Key
            // これは、自分が生成したもの
            {
                var user = CBORObject.NewMap();
                user.Add(1, My_KeyAgreement.Kty);
                user.Add(3, My_KeyAgreement.Alg);
                user.Add(-1, My_KeyAgreement.Crv);
                user.Add(-2, My_KeyAgreement.X);
                user.Add(-3, My_KeyAgreement.Y);
                cbor.Add(0x03, user);
            }

            // 0x04:pinAuth
            cbor.Add(0x04, pinAuth);

            // 0x05:newPinEnc
            cbor.Add(0x05, newPinEnc);

            var resi = await sendCommandandResponse(devParam, 0x06, cbor);

            var response = new CTAPResponse(resi);

            return (response);
        }

        public async Task<CTAPResponse> ChangePIN(DevParam devParam, byte[] pinAuth, byte[] newPinEnc,byte[] pinHashEnc)
        {
            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x04:changePIN
            cbor.Add(0x02, 0x04);

            // 0x03:keyAgreement : COSE_Key
            // これは、自分が生成したもの
            {
                var user = CBORObject.NewMap();
                user.Add(1, My_KeyAgreement.Kty);
                user.Add(3, My_KeyAgreement.Alg);
                user.Add(-1, My_KeyAgreement.Crv);
                user.Add(-2, My_KeyAgreement.X);
                user.Add(-3, My_KeyAgreement.Y);
                cbor.Add(0x03, user);
            }

            // 0x04:pinAuth
            cbor.Add(0x04, pinAuth);

            // 0x05:newPinEnc
            cbor.Add(0x05, newPinEnc);

            // 0x06:pinHashEnc
            cbor.Add(0x06, pinHashEnc);

            var resi = await sendCommandandResponse(devParam, 0x06, cbor);

            var response = new CTAPResponse(resi);

            return (response);
        }

        public async Task<CTAPResponsePinToken> GetPINToken(DevParam devParam, byte[] pinHashEnc)
        {
            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x03:setPIN
            cbor.Add(0x02, 0x05);

            // 0x03:keyAgreement : COSE_Key
            // これは、自分が生成したもの
            {
                var user = CBORObject.NewMap();
                user.Add(1, My_KeyAgreement.Kty);
                user.Add(3, My_KeyAgreement.Alg);
                user.Add(-1, My_KeyAgreement.Crv);
                user.Add(-2, My_KeyAgreement.X);
                user.Add(-3, My_KeyAgreement.Y);
                cbor.Add(0x03, user);
            }

            // 0x06:
            cbor.Add(0x06, pinHashEnc);

            var resi = await sendCommandandResponse(devParam, 0x06, cbor);

            var response = new CTAPResponsePinToken(resi);

            return (response);
        }

        public byte[] createSharedSecret(KeyAgreement keyAgreement)
        {
            string aG_x = BitConverter.ToString(keyAgreement.X).Replace("-", string.Empty);
            string aG_y = BitConverter.ToString(keyAgreement.Y).Replace("-", string.Empty);

            var bG_x = new StringBuilder(256);
            var bG_y = new StringBuilder(256);
            var strSharedSecret = new StringBuilder(256);

            // C#版に変更してみる
            //int st = CreateSharedSecret(aG_x, aG_y, bG_x, bG_y, strSharedSecret);
            int st = CreateSharedSecretNew.CreateSharedSecret(aG_x, aG_y, bG_x, bG_y, strSharedSecret);

            // byte配列(32)にする
            var sharedSecret = Common.HexStringToBytes(strSharedSecret.ToString());

            My_KeyAgreement = new KeyAgreement(2, -7, 1, bG_x.ToString(), bG_y.ToString());

            return (sharedSecret);
        }

        public byte[] createPinHashEnc(string pin,byte[] sharedSecret)
        {
            // AES256-CBC(sharedSecret, IV=0, LEFT(SHA-256(PIN), 16))

            // pinsha = SHA-256(PIN) ->32byte
            byte[] pinbyte = Encoding.ASCII.GetBytes(pin);
            SHA256 sha = new SHA256CryptoServiceProvider();
            byte[] pinsha = sha.ComputeHash(pinbyte);

            // pinsha16 = LEFT 16(pinsha)
            byte[] pinsha16 = pinsha.ToList().Skip(0).Take(16).ToArray();

            // pinHashEnc = AES256-CBC(sharedSecret, IV=0, pinsha16)
            string key = Common.BytesToHexString(sharedSecret);
            string data = Common.BytesToHexString(pinsha16);
            var enc = new StringBuilder(256);

            int st = Aes256cbc_Enc(key, data, enc);

            var pinHashEnc = Common.HexStringToBytes(enc.ToString());

            return (pinHashEnc);
        }

        // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
        public byte[] createNewPinEnc(byte[] sharedSecret, byte[] newpin64)
        {
            byte[] newPinEnc;
            {
                string key = Common.BytesToHexString(sharedSecret);
                string data = Common.BytesToHexString(newpin64);
                var enc = new StringBuilder(256);

                int st = Aes256cbc_Enc(key, data, enc);

                newPinEnc = Common.HexStringToBytes(enc.ToString());
            }

            return (newPinEnc);
        }
        public byte[] createNewPinEnc(byte[] sharedSecret, string newpin)
        {
            return (createNewPinEnc(sharedSecret, paddingPin64(newpin)));
        }

        public byte[] createPinAuth(byte[] sharedSecret,byte[] cdh,byte[] pinTokenEnc)
        {
            var strPinTokenEnc = Common.BytesToHexString(pinTokenEnc);
            var strSharedSecret = Common.BytesToHexString(sharedSecret);
            var strPinToken = new StringBuilder(256);
            int ret = Aes256cbc_Dec(strSharedSecret, strPinTokenEnc, strPinToken);
            if( ret < 0) {
                // Error
                return null;
            }
            var pinToken = Common.HexStringToBytes(strPinToken.ToString());

            // HMAC-SHA-256(pinToken, clientDataHash)
            byte[] pinAuth;
            using (var hmacsha256 = new HMACSHA256(pinToken)) {
                var dgst = hmacsha256.ComputeHash(cdh);
                pinAuth = dgst.ToList().Take(16).ToArray();
            }
            return (pinAuth);
        }

        public byte[] createPinAuthforSetPin(byte[] sharedSecret, string newpin)
        {
            var newpin64 = this.paddingPin64(newpin);

            var strSharedSecret = Common.BytesToHexString(sharedSecret);

            var strNewPin64 = Common.BytesToHexString(newpin64);
            var strNewPin64Enc = new StringBuilder(256);
            int ret = Aes256cbc_Enc(strSharedSecret, strNewPin64, strNewPin64Enc);
            if (ret < 0) {
                // Error
                return null;
            }
            var newPinEnc = Common.HexStringToBytes(strNewPin64Enc.ToString());

            // HMAC-SHA-256(sharedSecret, newPinEnc)
            byte[] pinAuth;
            using (var hmacsha256 = new HMACSHA256(sharedSecret)) {
                var dgst = hmacsha256.ComputeHash(newPinEnc);
                pinAuth = dgst.ToList().Take(16).ToArray();
            }
            return (pinAuth);
        }

        public byte[] createPinAuthforChangePin(byte[] sharedSecret, string newpin,string currentpin)
        {
            // new pin
            byte[] newPinEnc = null;
            {
                var newpin64 = this.paddingPin64(newpin);
                var strSharedSecret = Common.BytesToHexString(sharedSecret);

                var strNewPin64 = Common.BytesToHexString(newpin64);
                var strNewPin64Enc = new StringBuilder(256);
                int ret = Aes256cbc_Enc(strSharedSecret, strNewPin64, strNewPin64Enc);
                if (ret < 0) {
                    // Error
                    return null;
                }
                newPinEnc = Common.HexStringToBytes(strNewPin64Enc.ToString());
            }

            // current pin
            var currentPinHashEnc = createPinHashEnc(currentpin, sharedSecret);

            // source data
            var data = new List<byte>();
            data.AddRange(newPinEnc.ToArray());
            data.AddRange(currentPinHashEnc.ToArray());

            // HMAC-SHA-256(sharedSecret, newPinEnc)
            byte[] pinAuth;
            using (var hmacsha256 = new HMACSHA256(sharedSecret)) {
                var dgst = hmacsha256.ComputeHash(data.ToArray());
                pinAuth = dgst.ToList().Take(16).ToArray();
            }
            return (pinAuth);
        }

        public byte[] paddingPin64(string pin)
        {
            // 5.5.5. Setting a New PIN
            // 5.5.6. Changing existing PIN
            // During encryption, 
            // newPin is padded with trailing 0x00 bytes and is of minimum 64 bytes length. 
            // This is to prevent leak of PIN length while communicating to the authenticator. 
            // There is no PKCS #7 padding used in this scheme.
            var bpin64 = new byte[64];
            byte[] pintmp = Encoding.ASCII.GetBytes(pin);
            for (int intIc = 0; intIc < bpin64.Length; intIc++) {
                if (intIc < pintmp.Length) {
                    bpin64[intIc] = pintmp[intIc];
                } else {
                    bpin64[intIc] = 0x00;
                }
            }
            return (bpin64);
        }
    }
}
