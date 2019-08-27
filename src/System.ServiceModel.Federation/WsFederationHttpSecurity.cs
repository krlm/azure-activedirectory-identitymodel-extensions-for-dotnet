// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

namespace System.ServiceModel.Federation
{
    using System.ComponentModel;

    public sealed class WsFederationHttpSecurity
    {
        public WsFederationHttpSecurity()
            : this(DefaultMode, new FederatedMessageSecurityOverHttp())
        {
        }

        WsFederationHttpSecurity(WsFederationHttpSecurityMode mode, FederatedMessageSecurityOverHttp messageSecurity)
        {
            Fx.Assert(WsFederationHttpSecurityModeHelper.IsDefined(mode), string.Format("Invalid WsFederationHttpSecurityMode value: {0}", mode.ToString()));

            this.mode = mode;
            this.messageSecurity = messageSecurity == null ? new FederatedMessageSecurityOverHttp() : messageSecurity;
        }

        public WsFederationHttpSecurityMode Mode
        {
            get { return this.mode; }
            set
            {
                if (!WsFederationHttpSecurityModeHelper.IsDefined(value))
                {
                    throw DiagnosticUtility.ExceptionUtility.ThrowHelperError(new ArgumentOutOfRangeException("value"));
                }
                this.mode = value;
            }
        }

        internal static bool TryCreate(SecurityBindingElement sbe,
                                       WsFederationHttpSecurityMode mode,
                                       HttpTransportSecurity transportSecurity,
                                       out WsFederationHttpSecurity security)
        {
            security = null;
            FederatedMessageSecurityOverHttp messageSecurity = null;
            if (sbe == null)
            {
                mode = WsFederationHttpSecurityMode.None;
            }
            else
            {
                mode &= WsFederationHttpSecurityMode.Message | WsFederationHttpSecurityMode.TransportWithMessageCredential;
                Fx.Assert(WsFederationHttpSecurityModeHelper.IsDefined(mode), string.Format("Invalid WsFederationHttpSecurityMode value: {0}", mode.ToString()));

                if (!FederatedMessageSecurityOverHttp.TryCreate(sbe, mode == WsFederationHttpSecurityMode.TransportWithMessageCredential, isReliableSessionEnabled, version, out messageSecurity))
                    return false;
            }
            security = new WsFederationHttpSecurity(mode, messageSecurity);
            return true;
        }

        internal bool InternalShouldSerialize()
        {
            return this.ShouldSerializeMode()
                || this.ShouldSerializeMessage();
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeMode()
        {
            return this.Mode != DefaultMode;
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeMessage()
        {
            return this.Message.InternalShouldSerialize();
        }
    }
}
