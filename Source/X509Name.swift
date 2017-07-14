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
public struct X509Name: Equatable {
    
    // MARK: - Properties
    public var commonName             : X509String?
    public var localityName           : X509String?
    public var stateOrProvinceName    : X509String?
    public var countryName            : X509String?
    public var organizationName       : X509String?
    public var organizationalUnitName : X509String?
    public var emailAddress           : X509String?
    
    public var string : String { return formatString() }
    
    // MARK: - Private Properties
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
        commonName = X509String(string: identity.string)
    }
    
    // MARK: - Private
    
    private func formatString() -> String
    {
        var string = String()
        
        if let commonName = self.commonName {
            string = string + String(format: "CN=%s", commonName.string)
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
