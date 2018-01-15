/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2017-2018 Jon Griffeth
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 -----------------------------------------------------------------------------
 */


import Foundation


// Names
public let x520IDAT                   = ASN1OID(components: [ 2, 5, 4 ])
public let x520CommonName             = ASN1OID(prefix: x520IDAT, components: [  3 ])
public let x520CountryName            = ASN1OID(prefix: x520IDAT, components: [  6 ])
public let x520LocalityName           = ASN1OID(prefix: x520IDAT, components: [  7 ])
public let x520StateOrProvinceName    = ASN1OID(prefix: x520IDAT, components: [  8 ])
public let x520OrganizationName       = ASN1OID(prefix: x520IDAT, components: [ 10 ])
public let x520OrganizationalUnitName = ASN1OID(prefix: x520IDAT, components: [ 11 ])

// Extensions
public let x509IDCE                       = ASN1OID(components: [ 2, 5, 29 ])
public let x509ExtnSubjectkeyIdentifier   = ASN1OID(prefix: x509IDCE, components: [ 14 ])
public let x509ExtnKeyUsage               = ASN1OID(prefix: x509IDCE, components: [ 15 ])
public let x509ExtnBasicConstraints       = ASN1OID(prefix: x509IDCE, components: [ 19 ])
public let x509ExtnAuthoritykeyIdentifier = ASN1OID(prefix: x509IDCE, components: [ 35 ])
public let x509ExtnExtendedKeyUsage       = ASN1OID(prefix: x509IDCE, components: [ 37 ])


// End of File
