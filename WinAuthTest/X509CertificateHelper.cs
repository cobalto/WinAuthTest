using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace WinAuthTest
{
    internal static class X509CertificateHelper
    {
        public static X509Certificate2 GetCertificateFromStore(
            string subjectName,
            StoreName storeName = StoreName.My,
            StoreLocation storeLocation = StoreLocation.LocalMachine)
        {
            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            var certificates = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, true);
            return certificates.FirstOrDefault() ?? throw new Exception("Certificate not found");
        }
    }
}
