// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsTrust;

namespace System.ServiceModel.Federation
{
    public class IssuedTokenParameters
    {
        public IssuedTokenParameters()
        {
            AdditionalRequestParameters = new List<XmlElement>();
            ClaimTypes = new List<ClaimType>();
        }

        public IList<XmlElement> AdditionalRequestParameters
        {
            get;
        }

        public IList<ClaimType> ClaimTypes
        {
            get;
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

        public string IssuedKeyType
        {
            get;
            set;
        }

        public string IssuedTokenType
        {
            get;
            set;
        }

        public int? KeySize
        {
            get;
            set;
        }

        public WsTrustVersion WsTrustVersion
        {
            get;
            set;
        }
    }
}
