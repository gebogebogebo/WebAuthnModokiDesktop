using System;
using System.Collections.Generic;
using gebo.NFC;

namespace gebo.CTAP2
{
    public class NfcParam
    {
        public string TargetReaderName { get; set; }
        public NfcParam(string targetReaderName)
        {
            this.TargetReaderName = targetReaderName;
        }
    }

    internal class CTAPNFC
    {
        protected static NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        public static List<string> ToStringList(List<NfcParam> nfcparams)
        {
            var ret = new List<string>();
            foreach (var param in nfcparams) {
                if (!string.IsNullOrEmpty(param.TargetReaderName)) {
                    ret.Add(param.TargetReaderName);
                }
            }
            return (ret);
        }

        public static byte[] GetCardUID(List<NfcParam> nfcParams)
        {
            byte[] uid = null;
            try {

                using (var reader = new ICReader(ToStringList(nfcParams))) {
                    // CONNECT
                    if (reader.Connect() == false) {
                        throw (new Exception("Connect Error"));
                    }

                    // get UID
                    var response = reader.SendandResponse(new byte[] { 0xFF, 0xCA, 0x00, 0x00, 0x00 });
                    if (response.IsSuccess) {
                        uid = response.Data;
                    }
                }
            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (uid);
        }

        public static string CheckAP(List<NfcParam> nfcParams)
        {
            logger.Debug("CheckAP");
            string ret = "";
            var apdures = sendCommandandResponse(nfcParams, null);
            if (apdures != null && apdures.IsSuccess == true) {
                ret = System.Text.Encoding.ASCII.GetString(apdures.Data);
            }
            return (ret);
        }

        public static byte[] SendCommandandResponse(List<NfcParam> nfcParams, byte[] send)
        {
            byte[] res = null;
            var apdures = sendCommandandResponse(nfcParams, send);
            if (apdures != null && apdures.IsSuccess == true) {
                res = apdures.Data;
            }
            return (res);
        }

        private static APDUresponse sendCommandandResponse(List<NfcParam> nfcParams, byte[] send)
        {
            try {
                using (var reader = new ICReader(ToStringList(nfcParams))) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    // SELECT AP
                    {
                        var apdu = new List<byte>();
                        var ap = new byte[] { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01 };

                        apdu.AddRange(new List<byte> { 0x00, 0xA4, 0x04, 0x00 });
                        apdu.Add((byte)ap.Length);
                        apdu.AddRange(ap);
                        apdu.Add(0x00);

                        var res = reader.SendandResponse(apdu.ToArray());
                        if( send == null) {
                            return res;
                        }
                    }

                    // send command
                    {
                        var apdu = new List<byte>();

                        apdu.AddRange(new List<byte> { 0x80, 0x10, 0x00, 0x00 });
                        apdu.Add((byte)send.Length);
                        apdu.AddRange(send);
                        apdu.Add(0x00);

                        var res = reader.SendandResponse(apdu.ToArray());
                        if( res.Sw1 == 0x61) {
                            // next
                            for(; ; ) {
                                var next = reader.SendandResponse(new byte[] { 0x80, 0xC0, 0x00, 0x00 });
                                res.Marge(next);
                                if( res.Sw1 != 0x61) {
                                    break;
                                }
                            }
                        }
                        return (res);
                    }
                }

            } catch (Exception ex) {
                logger.Error(ex);
            }
            return (null);
        }

    }
}
