using System;
using System.Collections.Generic;

namespace gebo.CTAP2
{
    public class DevParam
    {
        public List<HidParam> hidparams { get; set; }
        public List<NfcParam> nfcparams { get; set; }

        public static DevParam GetDefaultParams()
        {
            var ret = new DevParam();

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
