
using System.Windows.Forms;

namespace Secureworks
{
    partial class ResponseInspector
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.selectTransportKey = new System.Windows.Forms.Button();
            this.txtDeviceTransportKey = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.txtSessionKey = new System.Windows.Forms.TextBox();
            this.txtDecryptedSessionKey = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.btnUpdate = new System.Windows.Forms.Button();
            this.boxOutput = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // selectTransportKey
            // 
            this.selectTransportKey.Location = new System.Drawing.Point(441, 12);
            this.selectTransportKey.Name = "selectTransportKey";
            this.selectTransportKey.Size = new System.Drawing.Size(68, 23);
            this.selectTransportKey.TabIndex = 0;
            this.selectTransportKey.Text = "Select";
            this.selectTransportKey.UseVisualStyleBackColor = true;
            this.selectTransportKey.Click += new System.EventHandler(this.selectTransportKey_Click);
            // 
            // txtDeviceTransportKey
            // 
            this.txtDeviceTransportKey.Location = new System.Drawing.Point(131, 14);
            this.txtDeviceTransportKey.Name = "txtDeviceTransportKey";
            this.txtDeviceTransportKey.ReadOnly = true;
            this.txtDeviceTransportKey.Size = new System.Drawing.Size(304, 20);
            this.txtDeviceTransportKey.TabIndex = 2;
            this.txtDeviceTransportKey.TabStop = false;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(5, 17);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(76, 13);
            this.label2.TabIndex = 4;
            this.label2.Text = "Transport Key:";
            // 
            // txtSessionKey
            // 
            this.txtSessionKey.Location = new System.Drawing.Point(131, 40);
            this.txtSessionKey.Name = "txtSessionKey";
            this.txtSessionKey.Size = new System.Drawing.Size(304, 20);
            this.txtSessionKey.TabIndex = 5;
            this.txtSessionKey.TabStop = false;
            // 
            // txtDecryptedSessionKey
            // 
            this.txtDecryptedSessionKey.ForeColor = System.Drawing.Color.Red;
            this.txtDecryptedSessionKey.Location = new System.Drawing.Point(131, 66);
            this.txtDecryptedSessionKey.Name = "txtDecryptedSessionKey";
            this.txtDecryptedSessionKey.ReadOnly = true;
            this.txtDecryptedSessionKey.Size = new System.Drawing.Size(304, 20);
            this.txtDecryptedSessionKey.TabIndex = 6;
            this.txtDecryptedSessionKey.TabStop = false;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(5, 43);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(96, 13);
            this.label3.TabIndex = 7;
            this.label3.Text = "Used Session Key:";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(5, 69);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(120, 13);
            this.label4.TabIndex = 8;
            this.label4.Text = "Decrypted Session Key:";
            // 
            // btnUpdate
            // 
            this.btnUpdate.Location = new System.Drawing.Point(441, 64);
            this.btnUpdate.Name = "btnUpdate";
            this.btnUpdate.Size = new System.Drawing.Size(68, 23);
            this.btnUpdate.TabIndex = 9;
            this.btnUpdate.Text = "Use";
            this.btnUpdate.UseVisualStyleBackColor = true;
            this.btnUpdate.Click += new System.EventHandler(this.update_Click);
            // 
            // boxOutput
            // 
            this.boxOutput.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.boxOutput.CausesValidation = false;
            this.boxOutput.Location = new System.Drawing.Point(1, 93);
            this.boxOutput.MaxLength = 65536;
            this.boxOutput.Multiline = true;
            this.boxOutput.Name = "boxOutput";
            this.boxOutput.ReadOnly = true;
            this.boxOutput.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.boxOutput.Size = new System.Drawing.Size(508, 20);
            this.boxOutput.TabIndex = 10;
            this.boxOutput.WordWrap = false;
            // 
            // Inspector
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.Controls.Add(this.boxOutput);
            this.Controls.Add(this.btnUpdate);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.txtSessionKey);
            this.Controls.Add(this.txtDecryptedSessionKey);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.txtDeviceTransportKey);
            this.Controls.Add(this.selectTransportKey);
            this.Name = "Inspector";
            this.Size = new System.Drawing.Size(512, 116);
            this.Load += new System.EventHandler(this.Inspector_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button selectTransportKey;
        public System.Windows.Forms.TextBox txtDeviceTransportKey;
        private System.Windows.Forms.Label label2;
        public System.Windows.Forms.TextBox txtSessionKey;
        public System.Windows.Forms.TextBox txtDecryptedSessionKey;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label4;
        public System.Windows.Forms.Button btnUpdate;
        public System.Windows.Forms.TextBox boxOutput;
    }
}
