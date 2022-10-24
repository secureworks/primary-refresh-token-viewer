
namespace Secureworks
{
    partial class RequestInspector
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
            this.boxOutput = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // boxOutput
            // 
            this.boxOutput.CausesValidation = false;
            this.boxOutput.Dock = System.Windows.Forms.DockStyle.Fill;
            this.boxOutput.Location = new System.Drawing.Point(0, 0);
            this.boxOutput.MaxLength = 65536;
            this.boxOutput.Multiline = true;
            this.boxOutput.Name = "boxOutput";
            this.boxOutput.ReadOnly = true;
            this.boxOutput.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.boxOutput.Size = new System.Drawing.Size(0, 0);
            this.boxOutput.TabIndex = 10;
            this.boxOutput.WordWrap = false;
            // 
            // RequestInspector
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.Controls.Add(this.boxOutput);
            this.Name = "RequestInspector";
            this.Size = new System.Drawing.Size(0, 0);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        public System.Windows.Forms.TextBox boxOutput;
    }
}
