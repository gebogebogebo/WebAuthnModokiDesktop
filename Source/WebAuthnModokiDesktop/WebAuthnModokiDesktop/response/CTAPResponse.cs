using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;
using System.Runtime.Serialization;

namespace gebo.CTAP2
{
    [DataContract]
    public class CTAPResponse
    {
        private int _status;
        [DataMember()]
        public int Status
        {
            get {
                return this._status;
            }
            set {
                this._status = value;
                this.StatusMsg = CTAPResponseStatusMessage.GetMessage(value);
            }
        }
        [DataMember()]
        public string StatusMsg { get; set; }
        [DataMember()]
        public string ResponseDataJson { get; set; }
        [DataMember()]
        public string CommandDataJson { get; set; }

        public CTAPResponse()
        {
            Status = 0;
            CommandDataJson = "";
            ResponseDataJson = "";
        }

        public CTAPResponse(CTAPauthenticator.CTAPResponseInner resi)
        {
            if( resi.Status < 0) {
                Status = resi.Status;
            } else {
                Status = resi.StatusCodeCTAP;
            }
            if (resi.ResponseDataCbor == null) {
                System.Diagnostics.Debug.WriteLine("ResponseDataCbor is null");        // log
                //throw new Exception("ResponseDataCbor is null");
                return;
            }
            ResponseDataJson = resi.ResponseDataCbor.ToJSONString();
            System.Diagnostics.Debug.WriteLine(ResponseDataJson);        // log
        }

        protected bool getKeyValueAsBool(CBORObject obj, string key)
        {
            if (obj.ContainsKey(key)) {
                return (obj[key].AsBoolean());
            } else {
                return false;
            }
        }

        protected bool? getKeyValueAsBoolorNull(CBORObject obj, string key)
        {
            if (obj.ContainsKey(key)) {
                return (obj[key].AsBoolean());
            } else {
                return null;
            }
        }

        protected string[] getKeyValueAsStringArray(CBORObject obj)
        {
            var tmp = new List<string>();
            obj.Values.ToList().ForEach(x => tmp.Add(x.AsString()));
            return(tmp.ToArray());
        }

        protected int[] getKeyValueAsIntArray(CBORObject obj)
        {
            var tmp = new List<int>();
            obj.Values.ToList().ForEach(x => tmp.Add(x.AsInt32()));
            return (tmp.ToArray());
        }

    }
}
