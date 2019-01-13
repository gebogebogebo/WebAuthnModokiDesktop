using System;
using System.Collections.Generic;
using gebo.CTAP2;

namespace WebAuthnModokiDesktop
{
    public class devparam
    {
        public List<HidParam> hidparams { get; set; }
        public List<NfcParam> nfcparams { get; set; }

        public static devparam getDefaultParams()
        {
            var ret = new devparam();

            // HID
            {
                ret.hidparams = new List<HidParam>();

                // Yubikey
                //ret.Add(new hidparam(0x1050, 0x0120));
                ret.hidparams.Add(new HidParam(0x1050));

                // BioPass FIDO2
                ret.hidparams.Add(new HidParam(0x096E));
            }

            // NFC
            {
                ret.nfcparams = new List<NfcParam>();
                // empty-all device
                ret.nfcparams.Add(new NfcParam(""));
            }

            return (ret);
        }
    }

}
