// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;

namespace System.ServiceModel.Federation
{
    public class WsFederationBinding : WSHttpBinding
    {
        public WsFederationBinding() : base(SecurityMode.TransportWithMessageCredential)
        {
            Security.Message.ClientCredentialType = MessageCredentialType.IssuedToken;
        }

        // binding is always TransportWithMessageCredentialy
        public WsFederationBinding(IssuedTokenParameters issuedTokenParameters) : base(SecurityMode.TransportWithMessageCredential)
        {
            Security = new WSHttpSecurity
            {
                Mode = SecurityMode.TransportWithMessageCredential
            };

            IssuedTokenParameters = issuedTokenParameters;
        }

        public IssuedTokenParameters IssuedTokenParameters
        {
            get;
        }

        public override BindingElementCollection CreateBindingElements()
        {
            return base.CreateBindingElements();
        }

        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingParameterCollection parameters)
        {
            return base.BuildChannelFactory<TChannel>(parameters);
        }

        public override bool CanBuildChannelFactory<TChannel>(BindingParameterCollection parameters)
        {
            return base.CanBuildChannelFactory<TChannel>(parameters);
        }

        protected override Channels.SecurityBindingElement CreateMessageSecurity()
        {
            return base.CreateMessageSecurity();
        }

        protected override TransportBindingElement GetTransport()
        {
            return base.GetTransport();
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
        //Microsoft.IdentityModel.Tokens.SecurityToken _st;
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
}
