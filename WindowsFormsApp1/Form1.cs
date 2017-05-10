using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Deployment.Internal.CodeSigning;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Windows.Forms;
using System.Xml;

namespace WindowsFormsApp1
{
    public partial class Form1 : Form
    {
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
        }

        // Sign an XML file. 
        // This document cannot be verified unless the verifying 
        // code has the key with which it was signed.
        public static void SignXml(XmlDocument xmlDoc, RSA Key)
        {
            //X509Certificate2 cert = new X509Certificate2(
            //    @"C:\temp\TESTE XML\CertificadoTestesSerpro\114983_CIA_INDUSTRIAL_DE_OLEOS_DO_NORDESTE_CIONE.pfx", "100417",
            //    X509KeyStorageFlags.Exportable);

            //var exportedKeyMaterial = cert.PrivateKey.ToXmlString(
            //    /* includePrivateParameters = */ true);

            //var key = new RSACryptoServiceProvider(
            //    new CspParameters(24 /* PROV_RSA_AES */));
            //key.PersistKeyInCsp = false;

            //key.FromXmlString(exportedKeyMaterial);


            //// Check arguments.
            //if (xmlDoc == null)
            //    throw new ArgumentException("xmlDoc");
            //if (Key == null)
            //{
            //    MessageBox.Show("Certificado inválido");
            //    return;
            //}

            //var signedXml = new SignedXml(xmlDoc) { SigningKey = key };
            //signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            //Reference reference = new Reference();
            //reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            //reference.AddTransform(new XmlDsigExcC14NTransform());
            //reference.Uri = "";

            //signedXml.AddReference(reference);

            //KeyInfo keyInfo = new KeyInfo();
            //keyInfo.AddClause(new KeyInfoX509Data(cert));
            //signedXml.KeyInfo = keyInfo;

            //signedXml.ComputeSignature();

            //var xmlDigitalSignature = signedXml.GetXml();

            //// Append the element to the XML document.
            //xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

            X509Certificate2 cert = new X509Certificate2(
                @"C:\temp\TESTE XML\CertificadoTestesSerpro\114983_CIA_INDUSTRIAL_DE_OLEOS_DO_NORDESTE_CIONE.pfx", "100417",
                X509KeyStorageFlags.Exportable);

            // Export private key from cert.PrivateKey and import into a PROV_RSA_AES provider:
            var exportedKeyMaterial = cert.PrivateKey.ToXmlString( /* includePrivateParameters = */ true);
            var key = new RSACryptoServiceProvider(new CspParameters(24 /* PROV_RSA_AES */));
            key.PersistKeyInCsp = false;
            key.FromXmlString(exportedKeyMaterial);

            var doc = new XmlDocument();
            doc.LoadXml(xmlDoc.GetElementsByTagName("eSocial")[1].OuterXml);

            SignedXml signedXml = new SignedXml(doc);
            //SignedXml signedXml = new SignedXml((XmlElement)doc);
            signedXml.SigningKey = key;
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            
            // 
            // Add a signing reference, the uri is empty and so the whole document 
            // is signed. 
            Reference reference = new Reference();
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform(){ Algorithm = SignedXml.XmlDsigC14NTransformUrl });
            reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
            reference.Uri = "";
            signedXml.AddReference(reference);

            // 
            // Add the certificate as key info, because of this the certificate 
            // with the public key will be added in the signature part. 
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;
            // Generate the signature. 
            signedXml.ComputeSignature();

            var xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.GetElementsByTagName("eSocial")[1].AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            X509Certificate2 myCert = null;
            var store = new X509Store(StoreLocation.CurrentUser); //StoreLocation.LocalMachine fails too
            store.Open(OpenFlags.ReadOnly);
            var certificates = store.Certificates;
            foreach (var certificate in certificates)
            {
                listBox1.Items.Add(certificate.SubjectName.Name);
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            string assOriginal = "";
            string assGerada = "";
            var doc = new XmlDocument();
            doc.LoadXml(richTextBox2.Text);
            var selectSingleNodes = doc.SelectNodes("//*");

            foreach (XmlNode node in selectSingleNodes)
            {
                if (node.Name.Contains("SignatureValue"))
                    assOriginal = node.InnerText;
            }

            doc.LoadXml(richTextBox3.Text);
            selectSingleNodes = doc.SelectNodes("//*");

            foreach (XmlNode node in selectSingleNodes)
            {
                if (node.Name.Contains("SignatureValue"))
                    assGerada = node.InnerText;
            }

            MessageBox.Show(string.Equals(assOriginal, assGerada) ? "Iguais" : "Diferentes");
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
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

            X509Certificate2 myCert = null;
            var store = new X509Store(StoreLocation.CurrentUser); //StoreLocation.LocalMachine fails too
            store.Open(OpenFlags.ReadOnly);
            var certificate = store.Certificates[listBox1.SelectedIndex];
            SignXml(xml, (RSA)certificate.PrivateKey);
            var ms = new MemoryStream();
            xml.Save(ms);
            richTextBox2.Text = Encoding.Default.GetString(ms.ToArray());
        }
    }
}
