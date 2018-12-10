using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using HidLibrary;

using WebAuthnModokiDesktop;

namespace WebAuthnModokiDesktop
{
    public class commoandstatus
    {
        public class commandinfo
        {
            public CTAPauthenticator cmd;
            public CTAPResponse res;

            public commandinfo(CTAPauthenticator cmd, CTAPResponse res)
            {
                this.cmd = cmd;
                this.res = res;
            }
        }
        public List<commandinfo> commands { get; set; }
        public bool isSuccess;
        public string msg;

        public commoandstatus()
        {
            commands = new List<commandinfo>();
            isSuccess = false;
            msg = "";
        }
    }

    public partial class credentials
    {

        public bool get()
        {
            return false;
        }

        public static commoandstatus test()
        {
            var status = new commoandstatus();
            try {
                var yubikey = HidDevices.Enumerate(CTAPauthenticator.VENDOR_ID, CTAPauthenticator.PRODUCT_ID).FirstOrDefault();
                if (yubikey == null) {
                    return (status);
                }
                yubikey.ReadManufacturer(out byte[] manufacturerRaw);
                yubikey.ReadProduct(out byte[] productRaw);

                var manufacturer = Encoding.Unicode.GetString(manufacturerRaw).TrimEnd('\0');
                var product = Encoding.Unicode.GetString(productRaw).TrimEnd('\0');

                string msg = string.Format($"Manufacturer : {manufacturer} , Product : {product}");
                status.msg = msg;
                status.isSuccess = true;

            } catch (Exception ex) {
                status.msg = ex.Message.ToString();
                return (status);
            }
            return status;
        }

        public static async Task<commoandstatus> setpin(string newpin)
        {
            var status = new commoandstatus();

            var ctap = new CTAPauthenticatorClientPIN();
            var st = await ctap.GetKeyAgreement();
            status.commands.Add(new commoandstatus.commandinfo(ctap, st));
            if (st.Status != 0x00) {
                return status;
            }

            var sharedSecret = ctap.createSharedSecret(ctap.Authenticator_KeyAgreement);

            // pinAuth = LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
            var bpin64 = new byte[64];
            {
                byte[] pintmp = Encoding.ASCII.GetBytes(newpin);
                for (int intIc = 0; intIc < bpin64.Length; intIc++) {
                    if (intIc < pintmp.Length) {
                        bpin64[intIc] = pintmp[intIc];
                    } else {
                        bpin64[intIc] = 0x00;
                    }
                }
            }
            var pinAuth = ctap.createPinAuthforSetPin(sharedSecret, bpin64);

            // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
            byte[] newPinEnc = ctap.createNewPinEnc(sharedSecret, bpin64);

            var st2 = await ctap.SetPIN(pinAuth, newPinEnc);
            status.commands.Add(new commoandstatus.commandinfo(ctap, st2));
            if (st2.Status != 0x00) {
                return status;
            }

            status.isSuccess = true;
            return status;
        }

        public static async Task<commoandstatus> info()
        {
            var status = new commoandstatus();

            var ctap = new CTAPauthenticatorGetInfo();
            var ret = await ctap.SendAndResponse();
            status.commands.Add(new commoandstatus.commandinfo(ctap, ret));
            if (ret.Status != 0x00) {
                return status;
            }
            status.isSuccess = true;
            return status;
        }

    }

}

