using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;
using System.Xml;
using System.Xml.Linq;

namespace WindowsFormsApp1
{
    public partial class Form1 : Form
    {
        private string _signedXmlFromSource;

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            openFileDialog1.ShowDialog(this);
            richTextBox1.Text = File.ReadAllText(openFileDialog1.FileName);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            openFileDialog1.ShowDialog(this);
            richTextBox3.Text = File.ReadAllText(openFileDialog1.FileName);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(richTextBox1.Text))
            {
                MessageBox.Show("XML vazio");
                return;
            }
            var xml = new XmlDocument();
            try
            {
                xml.LoadXml(richTextBox1.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return;
            }

            var store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            var scollection = X509Certificate2UI.SelectFromCollection(store.Certificates, "Selecione o certificado", "Selecione o certificado", X509SelectionFlag.SingleSelection, Handle);

            XmlRSASHA256Signer.SignXml(xml, scollection[0]);
            var ms = new MemoryStream();
            xml.Save(ms);
            _signedXmlFromSource = Encoding.Default.GetString(ms.ToArray());
            richTextBox2.Text = _signedXmlFromSource;
        }


        private void button4_Click(object sender, EventArgs e)
        {
            var assGerada = GetSignature(richTextBox2.Text);
            var assOriginal = GetSignature(richTextBox3.Text);

            MessageBox.Show(string.Equals(assOriginal, assGerada) ? "Iguais" : "Diferentes");
        }

        private static string GetSignature(string text)
        {
            return XDocument.Parse(text).Root.DescendantsAndSelf().FirstOrDefault(x => x.Name.LocalName.Contains("SignatureValue")).Value;
        }
    }
}
