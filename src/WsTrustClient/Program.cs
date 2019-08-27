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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

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
                CustomBinding customBinding = null;
                ChannelFactory<IRequestChannel> factory = null;
                EndpointAddress endpointAddress = null;
                IRequestChannel channel = null;
                Message replyMessage = null;
                string replyMessageAction = null;
                string actualResponse = null;

                // *** SETUP *** \\

                customBinding = new CustomBinding(new BindingElement[] {
                  new TextMessageEncodingBindingElement(MessageVersion.Default, Encoding.UTF8),
                  new HttpsTransportBindingElement() });

                var epi = new DnsEndpointIdentity("https://127.0.0.1:5443/");
                endpointAddress = new EndpointAddress(new Uri("https://127.0.0.1:5443/WsTrust13/transportIWA"), epi, new AddressHeader[0]);


                IssuedSecurityTokenParameters issuedSecurityTokenParameters = new IssuedSecurityTokenParameters();
                issuedSecurityTokenParameters.IssuerAddress = endpointAddress;
                issuedSecurityTokenParameters.IssuerBinding = customBinding;
                issuedSecurityTokenParameters.TokenType = Saml2Constants.OasisWssSaml2TokenProfile11;

                var transportBindingElement = SecurityBindingElement.CreateIssuedTokenOverTransportBindingElement(issuedSecurityTokenParameters);


                customBinding = new CustomBinding(new BindingElement[] {
                  new TextMessageEncodingBindingElement(MessageVersion.Default, Encoding.UTF8),
                  transportBindingElement,
                  new HttpsTransportBindingElement() });

                // Create the channel factory for the request-reply message exchange pattern.
                factory = new ChannelFactory<IRequestChannel>(customBinding, endpointAddress);
                factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                factory.Credentials.ServiceCertificate.SslCertificateAuthentication = new X509ServiceCertificateAuthentication();
                factory.Credentials.ServiceCertificate.SslCertificateAuthentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
                factory.Endpoint.EndpointBehaviors.Remove(typeof(ClientCredentials));
                factory.Endpoint.EndpointBehaviors.Add(new WSTrustChannelClientCredentials());
                //factory.Credentials.

                // Create the channel.
                channel = factory.CreateChannel();
                channel.Open();

                // Create the Message object to send to the service.

                var wsTrustRequest = new WsTrustRequest()
                {
                    AppliesTo = new AppliesTo(new EndpointReference("https://127.0.0.1:443/IssuedTokenUsingTls")),
                    //CanonicalizationAlgorithm = SecurityAlgorithms.ExclusiveC14n,
                    Context = Guid.NewGuid().ToString(),
                    //KeySizeInBits = 256,
                    KeyType = WsTrustKeyTypes.Trust13.Bearer,
                    RequestType = WsTrustConstants.Trust13.WsTrustActions.Issue,
                    //SignWith = SecurityAlgorithms.Aes128CbcHmacSha256,
                    TokenType = Saml2Constants.OasisWssSaml2TokenProfile11,
                };

                var memeoryStream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                var serializer = new WsTrustSerializer();
                serializer.WriteRequest(writer, WsTrustVersion.Trust13, wsTrustRequest);
                writer.Flush();
                var bytes = memeoryStream.ToArray();
                var xml = Encoding.UTF8.GetString(bytes);
                var reader = XmlDictionaryReader.CreateTextReader(bytes, XmlDictionaryReaderQuotas.Max);

                var clientMessage = Encoding.UTF8.GetString(bytes);
                var action = WsTrustActions.Trust13.IssueRequest;
                Message requestMessage = Message.CreateMessage(
                    customBinding.MessageVersion,
                    action,
                    reader);

                replyMessage = channel.Request(requestMessage);
                replyMessageAction = replyMessage.Headers.Action;

                var replyReader = replyMessage.GetReaderAtBodyContents();
                var response = serializer.ReadResponse(replyReader);
//                actualResponse = replyReader.ReadElementContentAsString();
                replyMessage.Close();
                channel.Close();
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

    }

    /// <summary>
    /// These client credentials class that will serve up a SecurityTokenManager that will use a TrustChannel to get a token from an STS
    /// </summary>
    public class WSTrustChannelClientCredentials : ClientCredentials
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public WSTrustChannelClientCredentials()
            : base()
        {
            // Set SupportInteractive to false to suppress Cardspace UI
            //SupportInteractive = false;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">The WSTrustChannelClientCredentials to create a copy of</param>
        protected WSTrustChannelClientCredentials(WSTrustChannelClientCredentials other)
            : base(other)
        {
        }

        protected override ClientCredentials CloneCore()
        {
            return new WSTrustChannelClientCredentials(this);
        }

        /// <summary>
        /// Extensibility point for serving up the WSTrustChannelSecurityTokenManager
        /// </summary>
        /// <returns>WSTrustChannelSecurityTokenManager</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            // return custom security token manager
            return new WSTrustChannelSecurityTokenManager(this);
        }
    }

    /// <summary>
    /// Returns a WSTrustChannelSecurityTokenProvider to obtain token Saml
    /// </summary>
    public class WSTrustChannelSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        public WSTrustChannelSecurityTokenManager(WSTrustChannelClientCredentials clientCredentials)
            : base(clientCredentials)
        { }

        /// <summary>
        /// Make use of this extensibility point for returning a custom SecurityTokenProvider when SAML tokens are specified in the tokenRequirement
        /// </summary>
        /// <param name="tokenRequirement">A SecurityTokenRequirement  </param>
        /// <returns>The appropriate SecurityTokenProvider</returns>
        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            // If token requirement matches SAML token return the custom SAML token provider            
            // that performs custom work to serve up the token
            return new WSTrustChannelSecurityTokenProvider(tokenRequirement);
        }
    }

    /// <summary>
    /// Custom WSTrustChannelSecurityTokenProvider that returns a SAML assertion
    /// </summary>
    public class WSTrustChannelSecurityTokenProvider : SecurityTokenProvider
    {
        Microsoft.IdentityModel.Tokens.SecurityToken _st;
        SecurityTokenRequirement _tokenRequirement;
        //WSTrustChannelFactory _trustChannelFactory;

        public WSTrustChannelSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            if (tokenRequirement == null)
                throw new ArgumentNullException("tokenRequirement");

            _tokenRequirement = tokenRequirement;
        }

        /// <summary>
        /// Calls out to the STS, if necessary to get a token
        /// </summary>
        protected override System.IdentityModel.Tokens.SecurityToken GetTokenCore(TimeSpan timeout)
        {
            /*            if (_st != null)
                            return _st;

                        IssuedSecurityTokenParameters istp = _tokenRequirement.GetProperty<IssuedSecurityTokenParameters>(ServiceModelSecurityTokenRequirement.IssuedSecurityTokenParametersProperty);

                        if (_trustChannelFactory == null)
                        {
                            _trustChannelFactory = new WSTrustChannelFactory(istp.IssuerBinding, istp.IssuerAddress);
                            _trustChannelFactory.TrustVersion = TrustVersion.WSTrust13;
                        }

                        WSTrustChannel channel = null;

                        try
                        {
                            RequestSecurityToken rst = new RequestSecurityToken(WSTrust13Constants.RequestTypes.Issue);

                            // need to figure out the trust version. Assuming 1.3
                            if (istp.KeyType == SecurityKeyType.AsymmetricKey)
                                rst.KeyType = WSTrust13Constants.KeyTypes.Asymmetric;
                            else if (istp.KeyType == SecurityKeyType.SymmetricKey)
                                rst.KeyType = WSTrust13Constants.KeyTypes.Symmetric;
                            else
                                rst.KeyType = WSTrust13Constants.KeyTypes.Bearer;

                            rst.AppliesTo = istp.IssuerAddress;
                            rst.TokenType = istp.TokenType;

                            channel = (WSTrustChannel)_trustChannelFactory.CreateChannel();

                            // token is a GenericXmlSecurityToken and can be attached directly to message;
                            _st = channel.Issue(rst);

                            ((IChannel)channel).Close();
                            channel = null;

                            return _st;
                        }
                        finally
                        {
                            if (channel != null)
                            {
                                ((IChannel)channel).Abort();
                            }
                        }
                        */

            return new UP();// System.IdentityModel.Tokens.SecurityToken UsernameSecurityToken(); ;
        }
    }

    public class UP : System.IdentityModel.Tokens.SecurityToken
    {
        public override string Id => throw new NotImplementedException();

        public override DateTime ValidFrom => throw new NotImplementedException();

        public override DateTime ValidTo => throw new NotImplementedException();

        public override ReadOnlyCollection<System.IdentityModel.Tokens.SecurityKey> SecurityKeys => throw new NotImplementedException();
    }

    public class CustomBodyWriter : BodyWriter

    {

        private string _bodyContent;



        public CustomBodyWriter()

            : base(true)

        { }



        public CustomBodyWriter(string message)

            : base(true)

        {

            _bodyContent = message;

        }



        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)

        {

            writer.WriteString(_bodyContent);

        }

    }
}
