
using System.IO;
using System.Windows.Forms;
using Fiddler;
using Newtonsoft.Json;

namespace Secureworks
{
    public class ATRequest : Inspector2, IRequestInspector2
    {
        #region Private Properties
        private RequestInspector inspectorView;
        #endregion

        HTTPRequestHeaders IRequestInspector2.headers
        {
            get { return null; }
            set {
                this.inspectorView.boxOutput.Text = "";

                var authHeaders = value.FindAll("Authorization");
                try
                {
                    string authHeaderValue = authHeaders[0].Value;
                    if (authHeaderValue.StartsWith("Bearer "))
                    {
                        string[] parts = authHeaderValue.Split(' ')[1].Split('.');
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
                catch { }
            }
        }
        public byte[] body
        {
            get { return null; }
            set { }
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
            o.Text = "AT";

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
