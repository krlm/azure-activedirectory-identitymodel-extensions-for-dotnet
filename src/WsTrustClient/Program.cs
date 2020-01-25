//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Federation;
using System.ServiceModel.Security;
using System.Xml;

#pragma warning disable CS3003 // Binding, EndpointAddress not CLS-compliant
namespace WsTrustClient
{
    class Program
    {
        static void Main(string[] args)
        {
            ServicePointManager.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;
            try
            {
                var epi = new DnsEndpointIdentity("https://127.0.0.1:5443/");
                var endpointAddress = new EndpointAddress(new Uri("https://127.0.0.1:5443/WsTrust13/transportIWA"), epi, new AddressHeader[0]);
                var federationBinding = new WsFederationBinding();

                // Create the channel factory for the request-reply message exchange pattern.
                var factory = new ChannelFactory<IRequestChannel>(federationBinding, endpointAddress);
                factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                factory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication();
                factory.Credentials.ServiceCertificate.SslCertificateAuthentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;

                // Create the channel.
                var channel = factory.CreateChannel();
                channel.Open();
                var replyMessage = channel.Request(Message.CreateMessage(MessageVersion.Soap12WSAddressingAugust2004, "get data", new CustomBodyWriter("Hello")));
                replyMessage.Close();
                channel.Close();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }

    public class CustomBodyWriter : BodyWriter
    {
        private string _bodyContent;

        public CustomBodyWriter() : base(true)
        { }

        public CustomBodyWriter(string message) : base(true)
        {
            _bodyContent = message;
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            writer.WriteString(_bodyContent);
        }
    }
}
