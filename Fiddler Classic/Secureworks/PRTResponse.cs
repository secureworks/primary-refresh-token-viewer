using System;
using System.IO;
using System.Windows.Forms;
using Fiddler;
using Newtonsoft.Json;

namespace Secureworks
{
    public class PRTResponse : Inspector2,IResponseInspector2
    {
        #region Private Properties
        private ResponseInspector inspectorView;
        private byte[] binBody;
        #endregion

        public HTTPResponseHeaders headers
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

                this.inspectorView.txtDecryptedSessionKey.Text = "";
                this.inspectorView.boxOutput.Text = "";
                this.inspectorView.btnUpdate.Enabled = false;

                // Don't try too long
                if (binBody.Length < 20000)
                {

                    // Check does this response contain session_key_jwe
                    try
                    {
                        
                        string strBody = System.Text.Encoding.UTF8.GetString(binBody);
                        SessionKeyJWE sessionKeyJWE = JsonConvert.DeserializeObject<SessionKeyJWE>(strBody);
                        JWEData data = PRTUtils.DecryptJWE(sessionKeyJWE.Session_key_jwe, this.inspectorView.txtDeviceTransportKey.Text);
                        string sessionKey = Convert.ToBase64String(data.CEK);
                        this.inspectorView.txtDecryptedSessionKey.Text = sessionKey;
                        this.inspectorView.btnUpdate.Enabled = true;
                        return;
                    }
                    catch(Exception ex)
                    {
                        //FiddlerApplication.Log.LogString(ex.Message);
                    }

                    // Check does this response has decrypted content if we have the session key.
                    try
                    {
                        if (!String.IsNullOrEmpty(this.inspectorView.txtSessionKey.Text))
                        {
                            string strBody = System.Text.Encoding.UTF8.GetString(binBody);
                            JWEData data = PRTUtils.DecryptJWE(strBody, null, this.inspectorView.txtSessionKey.Text);

                            // Let's first try json
                            try
                            {
                                string json = System.Text.Encoding.UTF8.GetString(data.Data);
                                using (var stringReader = new StringReader(json))
                                    using(var stringWriter = new StringWriter())
                                    {
                                        var jsonReader = new JsonTextReader(stringReader);
                                        var jsonWriter = new JsonTextWriter(stringWriter) { Formatting = Formatting.Indented };
                                        jsonWriter.WriteToken(jsonReader);
                                        this.inspectorView.boxOutput.Text = stringWriter.ToString();
                                    }
                            }
                            catch
                            {
                            }

                            this.binBody = data.Data;
                        }
                    }
                    catch (Exception ex)
                    {
                        //FiddlerApplication.Log.LogString(ex.Message);
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

            inspectorView = new ResponseInspector();
            inspectorView.BackColor = CONFIG.colorDisabledEdit;
            inspectorView.Dock = DockStyle.Fill;
            o.Controls.Add(inspectorView);

            inspectorView.txtDeviceTransportKey.Text = FiddlerApplication.Prefs.GetStringPref("ext.Secureworks.TransportKey", null);
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
