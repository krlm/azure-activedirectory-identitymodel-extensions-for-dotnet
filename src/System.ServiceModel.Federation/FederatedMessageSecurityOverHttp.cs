// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IdentityModel.Tokens;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Xml;

namespace System.ServiceModel.Federation
{
#pragma warning disable 1591

    public class FederatedSecurity
    {
        EndpointAddress issuerAddress;
         Binding issuerBinding;
        string issuedTokenType;
        //SecurityKeyType issuedKeyType;
        //Collection<XmlElement> tokenRequestParameters;

        public FederatedSecurity(string issuedTokenType, Binding issuerBinding, EndpointAddress issuerAddress)
        {
            IssuerBinding = issuerBinding;
            IssuerAddress = issuerAddress;
            IssuedTokenType = issuedTokenType;
        }

        public EndpointAddress IssuerAddress
        {
            get;
            set;
        }

        public Binding IssuerBinding
        {
            get;
            set;
        }

        public string IssuedTokenType
        {
            get;
            set;
        }

        public SecurityKeyType IssuedKeyType
        {
            get;
            set;
        }

        internal static bool TryCreate(SecurityBindingElement sbe, bool isSecureTransportMode, bool isReliableSession, MessageSecurityVersion version, out FederatedMessageSecurityOverHttp messageSecurity)
        {
            Fx.Assert(null != sbe, string.Empty);

            messageSecurity = null;

            // do not check local settings: sbe.LocalServiceSettings and sbe.LocalClientSettings

            if (!sbe.IncludeTimestamp)
                return false;

            if (sbe.SecurityHeaderLayout != SecurityProtocolFactory.defaultSecurityHeaderLayout)
                return false;

            bool emitBspAttributes = true;

            // Do not check MessageSecurityVersion: it maybe changed by the wrapper element and gets checked later in the SecuritySection.AreBindingsMatching()

            SecurityBindingElement bootstrapSecurity;

            bool establishSecurityContext = SecurityBindingElement.IsSecureConversationBinding(sbe, true, out bootstrapSecurity);
            bootstrapSecurity = establishSecurityContext ? bootstrapSecurity : sbe;

            if (isSecureTransportMode && !(bootstrapSecurity is TransportSecurityBindingElement))
                return false;

            bool negotiateServiceCredential = DefaultNegotiateServiceCredential;
            IssuedSecurityTokenParameters issuedTokenParameters;

            if (isSecureTransportMode)
            {
                if (!SecurityBindingElement.IsIssuedTokenOverTransportBinding(bootstrapSecurity, out issuedTokenParameters))
                    return false;
            }
            else
            {
                // We should have passed 'true' as RequireCancelation to be consistent with other standard bindings.
                // However, to limit the change for Orcas, we scope down to just newer version of WSSecurityPolicy.
                if (SecurityBindingElement.IsIssuedTokenForSslBinding(bootstrapSecurity, version.SecurityPolicyVersion != SecurityPolicyVersion.WSSecurityPolicy11, out issuedTokenParameters))
                    negotiateServiceCredential = true;
                else if (SecurityBindingElement.IsIssuedTokenForCertificateBinding(bootstrapSecurity, out issuedTokenParameters))
                    negotiateServiceCredential = false;
                else
                    return false;
            }

            if ((issuedTokenParameters.KeyType == SecurityKeyType.BearerKey) &&
               (version.TrustVersion == TrustVersion.WSTrustFeb2005))
            {
                return false;
            }

            Collection<XmlElement> nonAlgorithmRequestParameters;
            WSSecurityTokenSerializer versionSpecificSerializer = new WSSecurityTokenSerializer(version.SecurityVersion,
                                                                                                version.TrustVersion,
                                                                                                version.SecureConversationVersion,
                                                                                                emitBspAttributes,
                                                                                                null, null, null);
            SecurityStandardsManager versionSpecificStandardsManager = new SecurityStandardsManager(version, versionSpecificSerializer);

            if (!issuedTokenParameters.DoAlgorithmsMatch(sbe.DefaultAlgorithmSuite,
                                                         versionSpecificStandardsManager,
                                                         out nonAlgorithmRequestParameters))
            {
                return false;
            }
            messageSecurity = new FederatedMessageSecurityOverHttp();

            messageSecurity.AlgorithmSuite = sbe.DefaultAlgorithmSuite;
            messageSecurity.NegotiateServiceCredential = negotiateServiceCredential;
            messageSecurity.EstablishSecurityContext = establishSecurityContext;
            messageSecurity.IssuedTokenType = issuedTokenParameters.TokenType;
            messageSecurity.IssuerAddress = issuedTokenParameters.IssuerAddress;
            messageSecurity.IssuerBinding = issuedTokenParameters.IssuerBinding;
            messageSecurity.IssuerMetadataAddress = issuedTokenParameters.IssuerMetadataAddress;
            messageSecurity.IssuedKeyType = issuedTokenParameters.KeyType;
            foreach (ClaimTypeRequirement c in issuedTokenParameters.ClaimTypeRequirements)
            {
                messageSecurity.ClaimTypeRequirements.Add(c);
            }
            foreach (XmlElement p in nonAlgorithmRequestParameters)
            {
                messageSecurity.TokenRequestParameters.Add(p);
            }
            if (issuedTokenParameters.AlternativeIssuerEndpoints != null && issuedTokenParameters.AlternativeIssuerEndpoints.Count > 0)
            {
                return false;
            }
            return true;
        }

        internal bool InternalShouldSerialize()
        {
            return (this.ShouldSerializeAlgorithmSuite()
                || this.ShouldSerializeClaimTypeRequirements()
                || this.ShouldSerializeNegotiateServiceCredential()
                || this.ShouldSerializeEstablishSecurityContext()
                || this.ShouldSerializeIssuedKeyType()
                || this.ShouldSerializeTokenRequestParameters());
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeAlgorithmSuite()
        {
            return (this.AlgorithmSuite != SecurityAlgorithmSuite.Default);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeClaimTypeRequirements()
        {
            return (this.ClaimTypeRequirements.Count > 0);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeNegotiateServiceCredential()
        {
            return (this.NegotiateServiceCredential != DefaultNegotiateServiceCredential);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeEstablishSecurityContext()
        {
            return (this.EstablishSecurityContext != DefaultEstablishSecurityContext);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeIssuedKeyType()
        {
            return (this.IssuedKeyType != DefaultIssuedKeyType);
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeTokenRequestParameters()
        {
            return (this.TokenRequestParameters.Count > 0);
        }

    }
}
