using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HidLibrary;

namespace WebAuthnModokiDesktop
{
    public class hidparam
    {
        public int VendorId { get; set; }
        public int ProductId { get; set; }
        public hidparam(int vendorId, int productId)
        {
            this.VendorId = vendorId;
            this.ProductId = productId;
        }
        public hidparam(int vendorId)
        {
            this.VendorId = vendorId;
            this.ProductId = 0x00;
        }

        public static List<hidparam> getDefaultParams()
        {
            var ret = new List<hidparam>();
            // Yubikey
            //ret.Add(new hidparam(0x1050, 0x0120));
            ret.Add(new hidparam(0x1050));

            // BioPass FIDO2
            ret.Add(new hidparam(0x096E));

            return (ret);
        }

    }

    public class commandstatus
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

        public commandstatus()
        {
            commands = new List<commandinfo>();
            isSuccess = false;
            msg = "";
        }

        public void setErrorMsg(Exception ex)
        {
            this.isSuccess = false;
            if (string.IsNullOrEmpty(this.msg)) {
                this.msg = ex.Message;
                if (this.commands.Count > 0) {
                    if (this.commands[this.commands.Count - 1].res != null) {
                        this.msg = this.msg + this.commands[this.commands.Count - 1].res.StatusMsg;
                    }
                }
            }
        }
    }

    public partial class credentials
    {

        public bool get()
        {
            return false;
        }

        public static commandstatus hidcheck(List<hidparam> hidparams)
        {
            var status = new commandstatus();
            HidDevice device = null;
            try {
                device = CTAPauthenticator.find(hidparams);
                if (device == null) {
                    return (status);
                }
                device.ReadManufacturer(out byte[] manufacturerRaw);
                device.ReadProduct(out byte[] productRaw);

                var manufacturer = Encoding.Unicode.GetString(manufacturerRaw).TrimEnd('\0');
                var product = Encoding.Unicode.GetString(productRaw).TrimEnd('\0');

                string msg = string.Format($"Manufacturer : {manufacturer} , Product : {product}");
                status.msg = msg;
                status.isSuccess = true;

            } catch (Exception ex) {
                status.msg = ex.Message.ToString();
                return (status);
            } finally {
                if( device != null) {
                    device.Dispose();
                }
            }
            return status;
        }

        public static async Task<commandstatus> setpin(List<hidparam> hidParams,string newpin)
        {
            var status = new commandstatus();
            try {
                var ctap = new CTAPauthenticatorClientPIN();
                var st = await ctap.GetKeyAgreement(hidParams);
                status.commands.Add(new commandstatus.commandinfo(ctap, st));
                if (st.Status != 0x00) {
                    throw (new Exception("GetKeyAgreement"));
                }

                var sharedSecret = ctap.createSharedSecret(ctap.Authenticator_KeyAgreement);

                // pinAuth = LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
                var pinAuth = ctap.createPinAuthforSetPin(sharedSecret, newpin);

                // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
                byte[] newPinEnc = ctap.createNewPinEnc(sharedSecret, newpin);

                var st2 = await ctap.SetPIN(hidParams,pinAuth, newPinEnc);
                status.commands.Add(new commandstatus.commandinfo(ctap, st2));
                if (st2.Status != 0x00) {
                    throw (new Exception("SetPIN"));
                }

                status.isSuccess = true;
            } catch (Exception ex) {
                status.setErrorMsg(ex);
            }
            return status;
        }

        public static async Task<commandstatus> changepin(List<hidparam> hidParams,string newpin, string currentpin)
        {
            var status = new commandstatus();

            try {
                var ctap = new CTAPauthenticatorClientPIN();
                var st = await ctap.GetKeyAgreement(hidParams);
                status.commands.Add(new commandstatus.commandinfo(ctap, st));
                if (st.Status != 0x00) {
                    throw (new Exception("GetKeyAgreement"));
                }

                var sharedSecret = ctap.createSharedSecret(ctap.Authenticator_KeyAgreement);

                // pinAuth:
                //  LEFT(HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc), 16).
                var pinAuth = ctap.createPinAuthforChangePin(sharedSecret, newpin,currentpin);

                // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
                byte[] newPinEnc = ctap.createNewPinEnc(sharedSecret, newpin);

                // pinHashEnc:
                //  Encrypted first 16 bytes of SHA - 256 hash of curPin using sharedSecret: 
                //  AES256-CBC(sharedSecret, IV = 0, LEFT(SHA-256(curPin), 16)).
                var pinHashEnc = ctap.createPinHashEnc(currentpin, sharedSecret);

                var st2 = await ctap.ChangePIN(hidParams,pinAuth, newPinEnc, pinHashEnc);
                status.commands.Add(new commandstatus.commandinfo(ctap, st2));
                if (st2.Status != 0x00) {
                    throw (new Exception("ChangePIN"));
                }

                status.isSuccess = true;
            } catch (Exception ex) {
                status.setErrorMsg(ex);
            }
            return status;
        }

    }

}

