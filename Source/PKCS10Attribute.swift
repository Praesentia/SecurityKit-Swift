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
 PKCS10 Attribute
 
 - Requirement: RFC-2986
 */
public struct PKCS10Attribute: DERCodable {
    
    // MARK: - Properties
    public var type   : OID
    public var values : [UInt8]
    
    // MARK: - Initializers

    public init(type: OID, values: [UInt8])
    {
        self.type   = type
        self.values = values
    }
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        type   = try OID(decoder: sequence)
        values = try sequence.decodeSet()
        
        try sequence.assertAtEnd()
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        sequence.encode(type)
        sequence.encodeSet(bytes: values)
        
        encoder.encodeSequence(bytes: sequence.bytes)
    }
    
    
}


// End of File

