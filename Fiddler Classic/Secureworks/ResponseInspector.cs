using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Fiddler;

namespace Secureworks
{
    public partial class ResponseInspector : UserControl
    {
        public ResponseInspector()
        {
            InitializeComponent();
        }

        private void Inspector_Load(object sender, EventArgs e)
        {

        }

        private void selectDeviceCert_Click(object sender, EventArgs e)
        {
            OpenFileDialog openCert = new OpenFileDialog();
            openCert.Title = "Select Device Certificate";
            openCert.Title = "pfx";
            openCert.Filter = "Pfx files (*.pfx)|*.pfx";
            openCert.CheckFileExists = true;

            if (openCert.ShowDialog() == DialogResult.OK)
            {
                FiddlerApplication.Prefs.SetStringPref("ext.Secureworks.DeviceCertificate", openCert.FileName);
            }
        }

        private void selectTransportKey_Click(object sender, EventArgs e)
        {
            OpenFileDialog openKey = new OpenFileDialog();
            openKey.Title = "Select Transport Key";
            openKey.Title = "pem";
            openKey.Filter = "Pem files (*.pem)|*.pem";
            openKey.CheckFileExists = true;

            if (openKey.ShowDialog() == DialogResult.OK)
            {
                FiddlerApplication.Prefs.SetStringPref("ext.Secureworks.TransportKey", openKey.FileName);
                txtDeviceTransportKey.Text = openKey.FileName;
            }
        }

        private void update_Click(object sender, EventArgs e)
        {

            try
            {
                txtSessionKey.Text = txtDecryptedSessionKey.Text;
                txtDecryptedSessionKey.Text = "";
                btnUpdate.Enabled = false;
            }
            catch (Exception ex)
            {
                FiddlerApplication.Log.LogString(ex.Message);
            }
            
        }
    }
}
