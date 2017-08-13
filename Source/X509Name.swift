/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2017 Jon Griffeth
 
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
public struct X509Name: Equatable, DERCodable {
    
    // MARK: - Properties
    public var commonName             : X509String?
    public var localityName           : X509String?
    public var stateOrProvinceName    : X509String?
    public var countryName            : X509String?
    public var organizationName       : X509String?
    public var organizationalUnitName : X509String?
    public var emailAddress           : X509String?
    
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
        commonName = X509String(string: identity.string, encoding: .utf8)
    }
    
    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        commonName             = nil
        countryName            = nil
        localityName           = nil
        stateOrProvinceName    = nil
        organizationName       = nil
        organizationalUnitName = nil
        emailAddress           = nil
        
        repeat {
            let set = try sequence.decoderFromSet()
            
            repeat {
                let attributeTypeValue = try X509AttributeValueType(decoder: set)
                
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
                
            } while set.more
        } while sequence.more
        
        cache = sequence.bytes
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

    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        if let cache = self.cache {
            encoder.encode(bytes: cache)
            return
        }
        
        let encoder1 = DEREncoder()
        
        if let commonName = commonName {
            let set = DEREncoder()
            set.encode(X509AttributeValueType(oid: x520CommonName, value: commonName))
            encoder1.encodeSet(bytes: set.bytes)
        }
        
        if let countryName = countryName {
            let set = DEREncoder()
            set.encode(X509AttributeValueType(oid: x520CountryName, value: countryName))
            encoder1.encodeSet(bytes: set.bytes)
        }
        
        if let localityName = localityName {
            let set = DEREncoder()
            set.encode(X509AttributeValueType(oid: x520LocalityName, value: localityName))
            encoder1.encodeSet(bytes: set.bytes)
        }
        
        if let stateOrProvinceName = stateOrProvinceName {
            let set = DEREncoder()
            set.encode(X509AttributeValueType(oid: x520StateOrProvinceName, value: stateOrProvinceName))
            encoder1.encodeSet(bytes: set.bytes)
        }
        
        if let organizationName = organizationName {
            let set = DEREncoder()
            set.encode(X509AttributeValueType(oid: x520OrganizationName, value: organizationName))
            encoder1.encodeSet(bytes: set.bytes)
        }
        
        if let organizationalUnitName = organizationalUnitName {
            let set = DEREncoder()
            set.encode(X509AttributeValueType(oid: x520OrganizationalUnitName, value: organizationalUnitName))
            encoder1.encodeSet(bytes: set.bytes)
        }
        
        if let emailAddress = emailAddress {
            let set = DEREncoder()
            set.encode(X509AttributeValueType(oid: pkcs9EmailAddress, value: emailAddress))
            encoder1.encodeSet(bytes: set.bytes)
        }
        
        encoder.encodeSequence(bytes: encoder1.bytes)
    }
    
}



// End of File
