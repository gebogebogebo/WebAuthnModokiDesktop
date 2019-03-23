using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HidLibrary;

namespace gebo.CTAP2.WebAuthnModokiDesktop
{
    public class CommandStatus
    {
        public class CommandInfo
        {
            public CTAPauthenticator cmd;
            public CTAPResponse res;

            public CommandInfo(CTAPauthenticator cmd, CTAPResponse res)
            {
                this.cmd = cmd;
                this.res = res;
            }
        }
        public List<CommandInfo> commands { get; set; }
        public bool isSuccess;
        public string msg;

        public CommandStatus()
        {
            commands = new List<CommandInfo>();
            isSuccess = false;
            msg = "";
        }

        public void setErrorMsg(Exception ex)
        {
            this.isSuccess = false;
            if (string.IsNullOrEmpty(this.msg)) {
                this.msg = ex.Message + " ";
                if (this.commands.Count > 0) {
                    if (this.commands[this.commands.Count - 1].res != null) {
                        this.msg = this.msg + this.commands[this.commands.Count - 1].res.StatusMsg;
                    }
                }
            }
        }
    }

    public partial class Credentials
    {
        public static CommandStatus HidCheck(List<HidParam> hidParams)
        {
            var status = new CommandStatus();
            HidDevice device = null;
            try {
                device = CTAPHID.find(hidParams);
                if (device == null) {
                    throw (new Exception("HID Device Not Found"));
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

        public static CommandStatus NfcCheck(List<NfcParam> nfcParams)
        {
            var status = new CommandStatus();
            try {
                status.msg = "";

                using (var reader = new gebo.NFC.ICReader(CTAPNFC.ToStringList(nfcParams) )) {
                    var readername = reader.GetLinkedReaderName();
                    if (string.IsNullOrEmpty(readername)){
                        throw (new Exception("Reader Not Found"));
                    }
                    status.msg = status.msg + string.Format($"Reader : {readername}");
                }

                var uid = CTAPNFC.GetCardUID(nfcParams);
                if( uid == null) {
                    throw (new Exception("Error-GetCardUID"));
                }
                status.msg = status.msg + string.Format($" , UID : {Common.BytesToHexString(uid)}");

                var version = CTAPNFC.CheckAP(nfcParams);
                if(string.IsNullOrEmpty(version)) {
                    throw (new Exception("Error-CheckAP"));
                }
                status.msg = status.msg + string.Format($" , VERSION : {version}");

                status.isSuccess = true;

            } catch (Exception ex) {
                status.msg = status.msg + ex.Message.ToString();
                return (status);
            } finally {
            }
            return status;
        }


        public static async Task<CommandStatus> SetPin(DevParam devParam, string newpin)
        {
            var status = new CommandStatus();
            try {
                var ctap = new CTAPauthenticatorClientPIN();
                var st = await ctap.GetKeyAgreement(devParam);
                status.commands.Add(new CommandStatus.CommandInfo(ctap, st));
                if (st.Status != 0) {
                    throw (new Exception("GetKeyAgreement"));
                }

                var sharedSecret = ctap.createSharedSecret(ctap.Authenticator_KeyAgreement);

                // pinAuth = LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
                var pinAuth = ctap.createPinAuthforSetPin(sharedSecret, newpin);

                // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
                byte[] newPinEnc = ctap.createNewPinEnc(sharedSecret, newpin);

                var st2 = await ctap.SetPIN(devParam, pinAuth, newPinEnc);
                status.commands.Add(new CommandStatus.CommandInfo(ctap, st2));
                if (st2.Status != 0) {
                    throw (new Exception("SetPIN"));
                }

                status.isSuccess = true;
            } catch (Exception ex) {
                status.setErrorMsg(ex);
            }
            return status;
        }

        public static async Task<CommandStatus> ChangePin(DevParam devParam, string newpin, string currentpin)
        {
            var status = new CommandStatus();

            try {
                var ctap = new CTAPauthenticatorClientPIN();
                var st = await ctap.GetKeyAgreement(devParam);
                status.commands.Add(new CommandStatus.CommandInfo(ctap, st));
                if (st.Status != 0) {
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

                var st2 = await ctap.ChangePIN(devParam, pinAuth, newPinEnc, pinHashEnc);
                status.commands.Add(new CommandStatus.CommandInfo(ctap, st2));
                if (st2.Status != 0) {
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

