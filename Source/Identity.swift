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
 Identity

 In terms of X509 Names, the identity name usually conforms to a Common Name.

 - Remark:
    Identity instances are immutable to prevent unintended side-effects.
    Changes to an identity requires the creation of a new instance.
 */
public class Identity: Equatable, Codable {
    
    /**
     Identity type.
     
     Different types of identities may use different naming conventions.  The
     identity type separates namespaces to prevent conflicts.
     */
    public enum IdentityType: String, Codable {
        case device       = "device"       //: Devices.
        case organization = "organization" //: An organization, such as a certificate authority.
        case other        = "other"        //: Catch all for any other type of identity.
        case person       = "person"       //: A person.
    }
    
    // MARK: - Properties
    public let name    : String
    public let type    : IdentityType
    public var string  : String { return "\(type.prefix)\(name)" }

    // MARK: - Private

    private enum CodingKeys: CodingKey {
        case name
        case type
    }

    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    public init(named name: String, type: IdentityType)
    {
        self.name = name
        self.type = type
    }
    
    /**
     Initialize instance from string.
     */
    public convenience init?(from string: String) // TODO
    {
        var identityType : IdentityType!
        var name         : String!
        
        if string.hasPrefix(Identity.IdentityType.PrefixDevice) {
            name = String(string.suffix(string.count - Identity.IdentityType.PrefixDevice.count))
            identityType = .device
        }
    
        if string.hasPrefix(Identity.IdentityType.PrefixPerson) {
            name = String(string.suffix(string.count - Identity.IdentityType.PrefixPerson.count))
            identityType = .person
        }
    
        if string.hasPrefix(Identity.IdentityType.PrefixOrganization) {
            name = String(string.suffix(string.count - Identity.IdentityType.PrefixOrganization.count))
            identityType = .organization
        }
        
        if identityType != nil {
            self.init(named: name, type: identityType)
        }
        else {
            self.init(named: string, type: .other)
        }
    }

    // MARK: - Codable

    required public init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        type = try container.decode(IdentityType.self, forKey: .type)
        name = try container.decode(String.self, forKey: .name)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(type, forKey: .type)
        try container.encode(name, forKey: .name)
    }

}

// MARK: - Equatable

/**
 Identity equatable operator.
 */
public func ==(lhs: Identity, rhs: Identity) -> Bool
{
    return lhs.name == rhs.name && lhs.type == rhs.type
}

// MARK: - Extensions

public extension Identity.IdentityType {

    // TODO: no longer specific to medkit
    static let PrefixDevice       = "org.medkit.device."
    static let PrefixOrganization = "org.medkit.organization."
    static let PrefixOther        = ""
    static let PrefixPerson       = "org.medkit.person."
    
    public init?(string: String)
    {
        switch string {
        case "Device" :
            self = .device
            
        case "Organization" :
            self = .organization
            
        case "Other" :
            self = .other
            
        case "Person" :
            self = .person

        default :
            return nil
        }
    }
    
    public var prefix: String {
        switch self {
        case .device :
            return Identity.IdentityType.PrefixDevice
            
        case .organization :
            return Identity.IdentityType.PrefixOrganization
            
        case .other :
            return Identity.IdentityType.PrefixOther
            
        case .person :
            return Identity.IdentityType.PrefixPerson
        }
    }
    
    public var string: String {
        switch self {
        case .device :
            return "Device"
        
        case .organization :
            return "Organization"
            
        case .other :
            return "Other"
        
        case .person :
            return "Person"
        }
    }
    
}


// End of File
