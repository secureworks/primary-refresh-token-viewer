using System;
using System.Collections;
using System.IO;
using System.Windows.Forms;
using Fiddler;
using Newtonsoft.Json;

namespace Secureworks
{
    public class PRTRequest : Inspector2, IRequestInspector2
    {
        #region Private Properties
        private RequestInspector inspectorView;
        private byte[] binBody;
        #endregion

        HTTPRequestHeaders IRequestInspector2.headers
        {
            get { return null; }
            set { }
        }
        public byte[] body
        {
            get { return binBody; }
            set
            {
                binBody = value;

                this.inspectorView.boxOutput.Text = "";

                // Don't try too long
                if (binBody.Length < 20000)
                {

                    // Check does this response contain session_key_jwe
                    try
                    {

                        string strBody = System.Net.WebUtility.UrlDecode(System.Text.Encoding.UTF8.GetString(binBody));

                        string[] keyValues = strBody.Split('&');
                        Hashtable parameters = new Hashtable();
                        foreach (string keyValue in keyValues)
                        {
                            string[] elements = keyValue.Split('=');
                            parameters[elements[0]] = elements[1];
                        }

                        string strRequest = null;
                        // The "normal" request
                        try
                        {
                            if (parameters["grant_type"].Equals("urn:ietf:params:oauth:grant-type:jwt-bearer") & !String.IsNullOrEmpty((string)parameters["request"]))
                            {
                                strRequest = (string)parameters["request"];
                            }
                        }
                        catch { }

                        try
                        {
                            // getkeydata
                            if (!String.IsNullOrEmpty((string)parameters["signedRequest"]))
                            {
                                strRequest = (string)parameters["signedRequest"];
                            }
                        }
                        catch { }

                        if(!String.IsNullOrEmpty(strRequest))
                        { 
                            string[] parts = strRequest.Split('.');
                            if (parts.Length == 3)
                            {
                                string json = System.Text.Encoding.UTF8.GetString(PRTUtils.ConvertB64ToByteArray(parts[1]));
                                using (var stringReader = new StringReader(json))
                                using (var stringWriter = new StringWriter())
                                {
                                    var jsonReader = new JsonTextReader(stringReader);
                                    var jsonWriter = new JsonTextWriter(stringWriter) { Formatting = Formatting.Indented };
                                    jsonWriter.WriteToken(jsonReader);
                                    this.inspectorView.boxOutput.Text = stringWriter.ToString();
                                }
                            }
                            
                        }
                    }
                    catch (Exception ex)
                    {
                        FiddlerApplication.Log.LogString(ex.Message);
                    }


                }
            }
        }

        public bool bDirty
        {
            get { return false; }
        }

        public bool bReadOnly
        {
            get { return false; }
            set { }
        }

        

        public override void AddToTab(TabPage o)
        {
            o.Text = "PRT";

            inspectorView = new RequestInspector();
            inspectorView.BackColor = CONFIG.colorDisabledEdit;
            inspectorView.Dock = DockStyle.Fill;
            o.Controls.Add(inspectorView);

        }

        public void Clear()
        {
            // Nothing to do
        }

        public override int GetOrder()
        {
            return 1;
        }
    }
}
