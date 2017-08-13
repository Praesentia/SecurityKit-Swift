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
 X509 Extension
 
 - Requirement: RFC-5280, 4.1
 */
public struct X509Extension: DERCodable {
    
    // MARK: - Properties
    public var extnID    : OID
    public var critical  : Bool = false
    public var extnValue : [UInt8]
    
    // MARK: - Initializers
    
    public init()
    {
        extnID    = OID(components: [])
        extnValue = []
    }
    
    public init(extnID: OID, extnValue: [UInt8], critical: Bool = false)
    {
        self.extnID    = extnID
        self.critical  = critical
        self.extnValue = extnValue
    }
    
    public init(extnID: OID, codable: DERCodable, critical: Bool = false)
    {
        let encoder = DEREncoder()
        
        encoder.encode(codable)
        self.init(extnID: extnID, extnValue: encoder.bytes, critical: critical)
    }
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        extnID = try OID(decoder: sequence)
        
        if sequence.peekTag() == DERCoder.TagBoolean {
            critical = try sequence.decodeBoolean()
        }
        else {
            critical = false
        }
        
        extnValue = try sequence.decodeOctetString()
        try sequence.assertAtEnd()
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        sequence.encode(extnID)
        sequence.encodeBoolean(critical)
        sequence.encodeOctetString(bytes: extnValue)
        
        encoder.encodeSequence(bytes: sequence.bytes)
    }
    
    
}


// End of File
