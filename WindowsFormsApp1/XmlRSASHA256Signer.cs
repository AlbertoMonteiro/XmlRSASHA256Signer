using System;
using System.Deployment.Internal.CodeSigning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace WindowsFormsApp1
{
    public static class XmlRSASHA256Signer
    {
        public static void SignXml(XmlDocument xmlDoc, X509Certificate2 cert, Func<XmlDocument, XmlElement> elementToSign = null)
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), SignedXml.XmlDsigRSASHA256Url);

            var element = elementToSign?.Invoke(xmlDoc) ?? (XmlElement)xmlDoc.FirstChild;

            var key = GetRSAKeyFromX509Certificate(cert);
            var signedXml = GetSignedXml(element, key);
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.ComputeSignature();
            var xmlDigitalSignature = signedXml.GetXml();

            element.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }

        private static RSACryptoServiceProvider GetRSAKeyFromX509Certificate(X509Certificate2 cert)
        {
            var key = new RSACryptoServiceProvider(new CspParameters(24)) { PersistKeyInCsp = false };
            key.FromXmlString(cert.PrivateKey.ToXmlString(true));
            return key;
        }

        private static SignedXml GetSignedXml(XmlElement doc, RSACryptoServiceProvider key)
        {
            var signedXml = new SignedXml(doc)
            {
                SigningKey = key,
                SignedInfo = { SignatureMethod = SignedXml.XmlDsigRSASHA256Url },
                KeyInfo = new KeyInfo()
            };
            var reference = GetReference();
            signedXml.AddReference(reference);
            return signedXml;
        }

        private static Reference GetReference()
        {
            var reference = new Reference
            {
                DigestMethod = SignedXml.XmlDsigSHA256Url,
                Uri = ""
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform { Algorithm = SignedXml.XmlDsigC14NTransformUrl });
            return reference;
        }

    }
}
