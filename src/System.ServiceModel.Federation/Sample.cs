//-----------------------------------------------------------------------------
//
// Copyright 2010 (c) Microsoft Corporation. All rights reserved.
//
//-----------------------------------------------------------------------------

using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;

namespace System.ServiceModel.Federation
{
    public class SampleCustomSecurityTokenProvider
    {
            // Client
            ChannelFactory<ISimpleRequestReply> cf = new ChannelFactory<ISimpleRequestReply>( serviceBinding, epa );
            cf.Credentials.ClientCertificate.SetCertificate( "CN=client", StoreLocation.CurrentUser, StoreName.My );
            cf.Credentials.ServiceCertificate.SetDefaultCertificate( "CN=localhost", StoreLocation.LocalMachine, StoreName.My );
            cf.Endpoint.Behaviors.Add( new WSTrustChannelClientCredentials( cf.Endpoint.Behaviors.Remove<ClientCredentials>() ) );

            ISimpleRequestReply srr = cf.CreateChannel();

            try
            {
                // contract has sign only.
                Console.WriteLine( srr.Sign( "Hello" ) );
            }
            catch ( Exception e )
            {
                Console.WriteLine( "Caught Exception => '{0}'", e.ToString() );
            }
        }

        static CustomBinding GetBinding( string tokenType, EndpointAddress stsAddress, Binding stsBinding )
        {
            // fill in binding for STS
        }


        /// <summary>
        /// These client credentials class that will serve up a SecurityTokenManager that will use a TrustChannel to get a token from an STS
        /// </summary>
        public class WSTrustChannelClientCredentials : ClientCredentials
        {
            /// <summary>
            /// Default constructor
            /// </summary>
            public WSTrustChannelClientCredentials( ClientCredentials cc )
                : base( cc )
            {
                // Set SupportInteractive to false to suppress Cardspace UI
                SupportInteractive = false;
            }

            /// <summary>
            /// Copy constructor
            /// </summary>
            /// <param name="other">The WSTrustChannelClientCredentials to create a copy of</param>
            protected WSTrustChannelClientCredentials( WSTrustChannelClientCredentials other )
                : base( other )
            {
            }

            protected override ClientCredentials CloneCore()
            {
                return new WSTrustChannelClientCredentials( this );
            }

            /// <summary>
            /// Extensibility point for serving up the WSTrustChannelSecurityTokenManager
            /// </summary>
            /// <returns>WSTrustChannelSecurityTokenManager</returns>
            public override SecurityTokenManager CreateSecurityTokenManager()
            {
                // return custom security token manager
                return new WSTrustChannelSecurityTokenManager( this );
            }
        }

        /// <summary>
        /// Returns a WSTrustChannelSecurityTokenProvider to obtain token Saml
        /// </summary>
        public class WSTrustChannelSecurityTokenManager : ClientCredentialsSecurityTokenManager
        {
            public WSTrustChannelSecurityTokenManager( WSTrustChannelClientCredentials clientCredentials )
                : base( clientCredentials )
            { }

            /// <summary>
            /// Make use of this extensibility point for returning a custom SecurityTokenProvider when SAML tokens are specified in the tokenRequirement
            /// </summary>
            /// <param name="tokenRequirement">A SecurityTokenRequirement  </param>
            /// <returns>The appropriate SecurityTokenProvider</returns>
            public override SecurityTokenProvider CreateSecurityTokenProvider( SecurityTokenRequirement tokenRequirement )
            {
                // If token requirement matches SAML token return the custom SAML token provider            
                // that performs custom work to serve up the token
                if ( tokenRequirement.TokenType == "urn:oasis:names:tc:SAML:2.0:assertion" )
                {
                    return new WSTrustChannelSecurityTokenProvider( tokenRequirement );
                }
                // otherwise use base implementation
                else
                {
                    return base.CreateSecurityTokenProvider( tokenRequirement );
                }
            }

        }

        /// <summary>
        /// Custom WSTrustChannelSecurityTokenProvider that returns a SAML assertion
        /// </summary>
        public class WSTrustChannelSecurityTokenProvider : SecurityTokenProvider
        {
            SecurityToken _st;
            SecurityTokenRequirement _tokenRequirement;
            WSTrustChannelFactory _trustChannelFactory;

            public WSTrustChannelSecurityTokenProvider( SecurityTokenRequirement tokenRequirement )
            {
                if ( tokenRequirement == null )
                    throw new ArgumentNullException( "tokenRequirement" );

                _tokenRequirement = tokenRequirement;
            }

            /// <summary>
            /// Calls out to the STS, if necessary to get a token
            /// </summary>
            protected override SecurityToken GetTokenCore( TimeSpan timeout )
            {
                if ( _st != null )
                    return _st;

                IssuedSecurityTokenParameters istp = _tokenRequirement.GetProperty<IssuedSecurityTokenParameters>( ServiceModelSecurityTokenRequirement.IssuedSecurityTokenParametersProperty );

                if ( _trustChannelFactory == null )
                {
                    _trustChannelFactory = new WSTrustChannelFactory( istp.IssuerBinding, istp.IssuerAddress );
                    _trustChannelFactory.TrustVersion = TrustVersion.WSTrust13;
                }

                WSTrustChannel channel = null;

                try
                {
                    RequestSecurityToken rst = new RequestSecurityToken( WSTrust13Constants.RequestTypes.Issue );

                    // need to figure out the trust version. Assuming 1.3
                    if ( istp.KeyType == SecurityKeyType.AsymmetricKey )
                        rst.KeyType = WSTrust13Constants.KeyTypes.Asymmetric;
                    else if ( istp.KeyType == SecurityKeyType.SymmetricKey )
                        rst.KeyType = WSTrust13Constants.KeyTypes.Symmetric;
                    else
                        rst.KeyType = WSTrust13Constants.KeyTypes.Bearer;

                    rst.AppliesTo = istp.IssuerAddress;
                    rst.TokenType = istp.TokenType;

                    channel = (WSTrustChannel)_trustChannelFactory.CreateChannel();

                    // token is a GenericXmlSecurityToken and can be attached directly to message;
                    _st = channel.Issue( rst );

                    ( (IChannel)channel ).Close();
                    channel = null;

                    return _st;
                }
                finally
                {
                    if ( channel != null )
                    {
                        ( (IChannel)channel ).Abort();
                    }
                }
            }
        }
    }
}
