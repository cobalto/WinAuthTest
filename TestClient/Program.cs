using Contracts;
using System;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Threading;

namespace TestClient
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Thread.CurrentThread.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            bool exit = false;

            string url = $"net.tcp://{IPAddress.Loopback}:5190";

            NetTcpBinding binding = null;
            ChannelFactory<ITestService> factory = null;
            ITestService service = null;
            EndpointIdentity identity = null;
            string superSafelyImplementedPassword = "Windows_ClientCredential_Password";

            while (!exit)
            {
                Console.WriteLine("Choose the security option:");
                Console.WriteLine("1: Message = Username | Transport = Windows");
                Console.WriteLine("2: Message = None     | Transport = Windows");
                Console.WriteLine("3: Message = Windows  | Transport = Windows");
                Console.WriteLine("4: Message = Windows  | Transport = None");
                Console.WriteLine("");
                var key = Console.ReadKey();
                Console.WriteLine("");

                try
                {

                    switch (key.KeyChar)
                    {
                        case '1':
                            binding = new NetTcpBinding();
                            binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                            binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
                            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                            binding.Security.Transport.ProtectionLevel = ProtectionLevel.EncryptAndSign;

                            //identity = EndpointIdentity.CreateSpnIdentity($"host/{Environment.MachineName}");
                            identity = EndpointIdentity.CreateDnsIdentity("MyIdentityDns");

                            factory = new ChannelFactory<ITestService>(binding, new EndpointAddress(new Uri(url + "/v1"), identity));
                            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = GetCertificateAuthentication();
                            //factory.Credentials.Windows.ClientCredential = new NetworkCredential(Environment.UserName, superSafelyImplementedPassword);
                            factory.Credentials.UserName.UserName = "user";
                            factory.Credentials.UserName.Password = "pwd";
                            
                            factory.Open();
                            service = factory.CreateChannel();
                            break;
                        case '2':
                            binding = new NetTcpBinding();
                            binding.Security.Mode = SecurityMode.Transport;
                            binding.Security.Message.ClientCredentialType = MessageCredentialType.None;
                            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                            binding.Security.Transport.ProtectionLevel = ProtectionLevel.EncryptAndSign;

                            identity = EndpointIdentity.CreateUpnIdentity($"{Environment.UserName}@{Environment.UserDomainName ?? Environment.MachineName}");
                            //identity = EndpointIdentity.CreateSpnIdentity($"host/{Environment.MachineName}");
                            //identity = EndpointIdentity.CreateDnsIdentity("MyIdentityDns");

                            factory = new ChannelFactory<ITestService>(binding, new EndpointAddress(new Uri(url + "/v2"), identity));
                            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = GetCertificateAuthentication();
                            factory.Credentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Identification;
                            factory.Credentials.Windows.ClientCredential = new NetworkCredential(Environment.UserName, superSafelyImplementedPassword);
                            
                            factory.Open();
                            service = factory.CreateChannel();
                            break;
                        case '3':
                            binding = new NetTcpBinding();
                            binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                            binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                            binding.Security.Transport.ProtectionLevel = ProtectionLevel.EncryptAndSign;

                            identity = EndpointIdentity.CreateSpnIdentity($"host/{Environment.MachineName}");
                            //identity = EndpointIdentity.CreateDnsIdentity("MyIdentityDns");

                            factory = new ChannelFactory<ITestService>(binding, new EndpointAddress(new Uri(url + "/v3"), identity));
                            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = GetCertificateAuthentication();
                            factory.Credentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Identification;
                            factory.Credentials.Windows.ClientCredential = new NetworkCredential(Environment.UserName, superSafelyImplementedPassword);
                            
                            factory.Open();
                            service = factory.CreateChannel();
                            break;
                        case '4':
                            binding = new NetTcpBinding();
                            binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                            binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.None;
                            binding.Security.Transport.ProtectionLevel = ProtectionLevel.EncryptAndSign;

                            identity = EndpointIdentity.CreateSpnIdentity($"host/{Environment.MachineName}");
                            //identity = EndpointIdentity.CreateDnsIdentity("MyIdentityDns");

                            factory = new ChannelFactory<ITestService>(binding, new EndpointAddress(new Uri(url + "/v3"), identity));
                            factory.Credentials.ServiceCertificate.SslCertificateAuthentication = GetCertificateAuthentication();
                            factory.Credentials.Windows.AllowedImpersonationLevel = System.Security.Principal.TokenImpersonationLevel.Identification;
                            factory.Credentials.Windows.ClientCredential = new NetworkCredential(Environment.UserName, superSafelyImplementedPassword);
                            
                            factory.Open();
                            service = factory.CreateChannel();
                            break;
                        case 'q':
                            exit = true;
                            break;
                        default:
                            Console.WriteLine("Invalid choice. Please select a valid option.");
                            break;
                    }

                    service.Test();

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
                finally
                {
                    Console.WriteLine("Done!");
                    Console.WriteLine("\n=====\n");
                }
            }
        }

        private static X509ServiceCertificateAuthentication GetCertificateAuthentication()
        {
            return new X509ServiceCertificateAuthentication
            {
                CertificateValidationMode = X509CertificateValidationMode.Custom,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomCertificateValidator = new CustomCertificateValidator(),
            };
        }
    }
}
