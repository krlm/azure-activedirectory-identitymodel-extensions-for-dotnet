// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.ServiceModel.Channels;
using System.ServiceModel;

namespace System.ServiceModel.Federation
{

    public class WsFederationBinding : WSHttpBinding
    {
        static readonly MessageSecurityVersion WSMessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10;

        WsFederationHttpSecurity _security = new WsFederationHttpSecurity();

        public WsFederationBinding()
            : base()
        {
        }

        // binding is always TransportWithMessageCredentialy
        public WsFederationBinding(FederatedSecurity federatedSecurity)
        {
            Security = new WSHttpSecurity
            {
                 Mode = SecurityMode.TransportWithMessageCredential
            };
        }

        // if you make changes here, see also c.TryCreate()
        internal static bool TryCreate(SecurityBindingElement sbe, TransportBindingElement transport, out Binding binding)
        {
            binding = null;

            // reverse GetTransport
            HttpTransportSecurity transportSecurity = new HttpTransportSecurity();
            WsFederationHttpSecurityMode mode;
            if (!GetSecurityModeFromTransport(transport, transportSecurity, out mode))
            {
                return false;
            }

            HttpsTransportBindingElement httpsBinding = transport as HttpsTransportBindingElement;
            if (httpsBinding != null && httpsBinding.MessageSecurityVersion != null)
            {
                if (httpsBinding.MessageSecurityVersion.SecurityPolicyVersion != WSMessageSecurityVersion.SecurityPolicyVersion)
                {
                    return false;
                }
            }

            WsFederationHttpSecurity security;
            if (TryCreateSecurity(sbe, mode, transportSecurity, out security))
            {
                binding = new WsFederationHttpBinding(security);
            }

            return binding != null;
        }

        protected override TransportBindingElement GetTransport()
        {
            if (_security.Mode == WsFederationHttpSecurityMode.None)
            {
                return this.HttpTransport;
            }
            else
            {
                return this.HttpsTransport;
            }
        }

        internal static bool GetSecurityModeFromTransport(TransportBindingElement transport, HttpTransportSecurity transportSecurity, out WsFederationHttpSecurityMode mode)
        {
            mode = WsFederationHttpSecurityMode.None | WsFederationHttpSecurityMode.Message | WsFederationHttpSecurityMode.TransportWithMessageCredential;
            if (transport is HttpsTransportBindingElement)
            {
                mode = WsFederationHttpSecurityMode.TransportWithMessageCredential;
            }
            else if (transport is HttpTransportBindingElement)
            {
                mode = WsFederationHttpSecurityMode.None | WsFederationHttpSecurityMode.Message;
            }
            else
            {
                return false;
            }
            return true;
        }

        // if you make changes here, see also WS2007FederationHttpBinding.TryCreateSecurity()
        static bool TryCreateSecurity(SecurityBindingElement sbe, WsFederationHttpSecurityMode mode, HttpTransportSecurity transportSecurity, out WsFederationHttpSecurity security)
        {
            if (!WsFederationHttpSecurity.TryCreate(sbe, mode, transportSecurity, WsMessageSecurityVersion, out security))
                return false;

            // the last check: make sure that security binding element match the incoming security
            return SecurityElement.AreBindingsMatching(security.CreateMessageSecurity(isReliableSession, WSMessageSecurityVersion), sbe);
        }

        public override BindingElementCollection CreateBindingElements()
        {   // return collection of BindingElements

            BindingElementCollection bindingElements = base.CreateBindingElements();
            // order of BindingElements is important

            return bindingElements;
        }

        protected override SecurityBindingElement CreateMessageSecurity()
        {
            throw new NotImplementedException();
        }
    }
}
