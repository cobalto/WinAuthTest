using Contracts;
using CoreWCF;
using CoreWCF.Configuration;
using CoreWCF.Description;
using CoreWCF.IdentityModel.Policy;
using CoreWCF.Security;
using idunno.Authentication.Basic;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace WinAuthTest
{
    public class Program
    {
        private static readonly string CERTIFICATE_SUBJECT_NAME = "MyCertificateSubject";

        private static readonly int LISTEN_PORT_HTTP_DEFAULT = 5180;
        private static readonly int LISTEN_PORT_NETTCP_DEFAULT = 5190;

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddServiceModelServices();
            builder.Services.AddServiceModelMetadata();
            builder.Services.AddSingleton<IServiceBehavior, UseRequestHeadersForMetadataAddressBehavior>();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = BasicAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = BasicAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCertificate(CertificateAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.AllowedCertificateTypes = CertificateTypes.All;
                options.RevocationMode = X509RevocationMode.NoCheck;
                options.ValidateCertificateUse = true;
                options.ChainTrustValidationMode = X509ChainTrustMode.System;
            })
            .AddBasic(BasicAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Realm = "WinAuthTestBasic";
            })
            .AddNegotiate(NegotiateDefaults.AuthenticationScheme, options =>
             {
                 options.ClaimsIssuer = "WinAuthTestNegotiate";
                 options.Events = new NegotiateEvents
                 {
                     OnAuthenticated = context =>
                     {
                         var claims = new[]
                         {
                            new Claim(ClaimTypes.NameIdentifier, context.Principal.Identity.Name, ClaimValueTypes.String, context.Scheme.Name),
                            new Claim(ClaimTypes.Name, context.Principal.Identity.Name, ClaimValueTypes.String, context.Scheme.Name),
                            new Claim(ClaimTypes.Role, "MySpecificWindowsGroup", ClaimValueTypes.String, context.Scheme.Name),
                        };

                         context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
                         context.Success();
                         return Task.CompletedTask;
                     }
                 };
             });

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("WinAuthTestPolicy", policy =>
                    policy.Requirements.Add(new CustomAuthorizationRequirement()));
            });

            builder.Services.AddSingleton<IAuthorizationHandler, CustomAuthorizationHandler>();

            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.Listen(IPAddress.Loopback, LISTEN_PORT_HTTP_DEFAULT, listenOptions =>
                {
                    listenOptions.UseHttps(adapterOptions =>
                    {
                        adapterOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                    });
                });
            });

            builder.WebHost.UseNetTcp(IPAddress.Loopback, LISTEN_PORT_NETTCP_DEFAULT);

            var app = builder.Build();

            app.UseAuthentication();
            app.UseAuthorization();

            ServiceAuthorizationBehavior authBehavior = app.Services.GetRequiredService<ServiceAuthorizationBehavior>();
            var authPolicies = new List<IAuthorizationPolicy>
            {
                new ServiceAuthorizationPolicy()
            };

            var externalAuthPolicies = new ReadOnlyCollection<IAuthorizationPolicy>(authPolicies);
            authBehavior.ExternalAuthorizationPolicies = externalAuthPolicies;
            //authBehavior.PrincipalPermissionMode = PrincipalPermissionMode.Custom;

            app.UseServiceModel(serviceBuilder =>
            {
                serviceBuilder.AddService<TestService>(serviceOptions =>
                {
                    serviceOptions.DebugBehavior.IncludeExceptionDetailInFaults = true;
                });

                serviceBuilder.ConfigureServiceHostBase<TestService>(host =>
                {
                    var serverCertificate = X509CertificateHelper.GetCertificateFromStore(CERTIFICATE_SUBJECT_NAME);

                    var serviceCredentials = host.Credentials;
                    serviceCredentials.ServiceCertificate.Certificate = serverCertificate;

                    serviceCredentials.UserNameAuthentication.UserNamePasswordValidationMode = UserNamePasswordValidationMode.Custom;
                    serviceCredentials.UserNameAuthentication.CustomUserNamePasswordValidator = new ServiceAuthenticator();

                    serviceCredentials.WindowsAuthentication.IncludeWindowsGroups = true;
                });

                var netTcpv1binding = new NetTcpBinding();
                netTcpv1binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                netTcpv1binding.Security.Message.ClientCredentialType = MessageCredentialType.UserName;
                netTcpv1binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                netTcpv1binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

                serviceBuilder.AddService<TestService>().AddServiceEndpoint<TestService, ITestService>(netTcpv1binding, $"net.tcp://{IPAddress.Loopback}:{LISTEN_PORT_NETTCP_DEFAULT}/v1");

                var netTcpv2binding = new NetTcpBinding();
                netTcpv2binding.Security.Mode = SecurityMode.Transport;
                netTcpv2binding.Security.Message.ClientCredentialType = MessageCredentialType.None;
                netTcpv2binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                netTcpv2binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

                serviceBuilder.AddService<TestService>().AddServiceEndpoint<TestService, ITestService>(netTcpv2binding, $"net.tcp://{IPAddress.Loopback}:{LISTEN_PORT_NETTCP_DEFAULT}/v2");

                var netTcpv3binding = new NetTcpBinding();
                netTcpv3binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                netTcpv3binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                netTcpv3binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;
                netTcpv3binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

                serviceBuilder.AddServiceEndpoint<TestService, ITestService>(netTcpv3binding, $"net.tcp://{IPAddress.Loopback}:{LISTEN_PORT_NETTCP_DEFAULT}/v3");

                var netTcpv4binding = new NetTcpBinding();
                netTcpv4binding.Security.Mode = SecurityMode.TransportWithMessageCredential;
                netTcpv4binding.Security.Message.ClientCredentialType = MessageCredentialType.Windows;
                netTcpv4binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.None;
                netTcpv4binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;

                serviceBuilder.AddServiceEndpoint<TestService, ITestService>(netTcpv4binding, $"net.tcp://{IPAddress.Loopback}:{LISTEN_PORT_NETTCP_DEFAULT}/v4");
            });

            var serviceMetadataBehavior = app.Services.GetRequiredService<ServiceMetadataBehavior>();
            serviceMetadataBehavior.HttpGetEnabled = true;

            serviceMetadataBehavior.HttpGetUrl = new Uri($"http://{IPAddress.Loopback}:{LISTEN_PORT_HTTP_DEFAULT}/metadata");


            // Get the current Windows identity
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();

            if (identity != null)
            {
                Console.WriteLine($"Authentication Type: {identity.AuthenticationType}");
                Console.WriteLine($"Is Authenticated: {identity.IsAuthenticated}");
                Console.WriteLine($"Name: {identity.Name}");
            }
            else
            {
                Console.WriteLine("No identity found.");
            }

            app.Run();
        }
    }
}
