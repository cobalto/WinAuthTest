using System;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;

namespace TestClient
{
    public class CustomCertificateValidator : X509CertificateValidator
    {
        public override void Validate(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }
        }
    }
}
