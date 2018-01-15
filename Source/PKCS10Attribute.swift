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
 PKCS10 Attribute
 
 - Requirement: RFC-2986
 */
public struct PKCS10Attribute: ASN1Codable {
    
    // MARK: - Properties
    public var type   : ASN1OID
    public var values : Data
    
    // MARK: - Initializers

    public init(type: ASN1OID, values: Data)
    {
        self.type   = type
        self.values = values
    }
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let sequence  = try container.sequence()
        
        type   = try sequence.decode(ASN1OID.self)
        values = Data(try sequence.decode([UInt8].self, forTag: .set))
        
        try sequence.assertAtEnd()
    }
    
    // MARK: - ASN1Encodable
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        let sequence  = try container.sequence()
        
        try sequence.encode(type)
        try sequence.encode([UInt8](values), forTag: .set)
    }
    
    
}


// End of File

