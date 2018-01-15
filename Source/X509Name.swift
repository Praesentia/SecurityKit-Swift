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


/**
 X509 Name structure.
 
 - Requirement: RFC-5280
 */
public struct X509Name: Equatable, ASN1Codable {
    
    // MARK: - Properties
    public var commonName             : ASN1String?
    public var localityName           : ASN1String?
    public var stateOrProvinceName    : ASN1String?
    public var countryName            : ASN1String?
    public var organizationName       : ASN1String?
    public var organizationalUnitName : ASN1String?
    public var emailAddress           : ASN1String?
    
    public var string : String { return formatString() }
    
    public var cache: [UInt8]?
    
    // MARK: - Initializers
    
    public init()
    {
    }
    
    /**
     Initialize from identity.
     */
    public init(from identity: Identity)
    {
        commonName = ASN1String(string: identity.string, encoding: .utf8)
    }

    // MARK: - ASN1Codable
    
    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let sequence  = try container.sequence()
        
        commonName             = nil
        countryName            = nil
        localityName           = nil
        stateOrProvinceName    = nil
        organizationName       = nil
        organizationalUnitName = nil
        emailAddress           = nil
        
        repeat {
            let set = try sequence.set()
            
            repeat {
                let attributeTypeValue = try set.decode(X509AttributeValueType.self)
                
                switch attributeTypeValue.oid {
                case x520CommonName :
                    commonName = attributeTypeValue.value
                    
                case x520CountryName :
                    countryName = attributeTypeValue.value
                    
                case x520LocalityName :
                    localityName = attributeTypeValue.value
                    
                case x520StateOrProvinceName :
                    stateOrProvinceName = attributeTypeValue.value
                    
                case x520OrganizationName :
                    organizationName = attributeTypeValue.value
                    
                case x520OrganizationalUnitName :
                    organizationalUnitName = attributeTypeValue.value
                    
                case pkcs9EmailAddress :
                    emailAddress = attributeTypeValue.value
                    
                default :
                    throw SecurityKitError.decodingError
                }
                
            } while !set.isAtEnd
        } while !sequence.isAtEnd
        
        cache = sequence.bytes
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()

        if let cache = self.cache {
            try container.encode(cache)
            return
        }

        let sequence = try container.sequence()

        if let commonName = commonName {
            let set = try sequence.set()
            try set.encode(X509AttributeValueType(oid: x520CommonName, value: commonName))
        }

        if let countryName = countryName {
            let set = try sequence.set()
            try set.encode(X509AttributeValueType(oid: x520CountryName, value: countryName))
        }

        if let localityName = localityName {
            let set = try sequence.set()
            try set.encode(X509AttributeValueType(oid: x520LocalityName, value: localityName))
        }

        if let stateOrProvinceName = stateOrProvinceName {
            let set = try sequence.set()
            try set.encode(X509AttributeValueType(oid: x520StateOrProvinceName, value: stateOrProvinceName))
        }

        if let organizationName = organizationName {
            let set = try sequence.set()
            try set.encode(X509AttributeValueType(oid: x520OrganizationName, value: organizationName))
        }

        if let organizationalUnitName = organizationalUnitName {
            let set = try sequence.set()
            try set.encode(X509AttributeValueType(oid: x520OrganizationalUnitName, value: organizationalUnitName))
        }

        if let emailAddress = emailAddress {
            let set = try sequence.set()
            try set.encode(X509AttributeValueType(oid: pkcs9EmailAddress, value: emailAddress))
        }
    }

    // MARK: - Private
    
    private func formatString() -> String
    {
        var string = String()
        
        if let commonName = self.commonName {
            string = commonName.string
        }
        
        return string
    }
    
    // MARK: - Equatable
    
    /**
     TODO
     */
    public static func ==(lhs: X509Name, rhs: X509Name) -> Bool
    {
        return lhs.commonName          == rhs.commonName             &&
            lhs.localityName           == rhs.localityName           &&
            lhs.stateOrProvinceName    == rhs.stateOrProvinceName    &&
            lhs.countryName            == rhs.countryName            &&
            lhs.organizationName       == rhs.organizationName       &&
            lhs.organizationalUnitName == rhs.organizationalUnitName &&
            lhs.emailAddress           == rhs.emailAddress
    }
    
}



// End of File
