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
 X509 Extended Key Usage
 
 - Requirement: RFC-5280
 */
public struct X509ExtendedKeyUsage: DERCodable {
    
    // MARK: - Properties
    public var purposeIdentifiers = [OID]()
    
    /**
     Initialize instance from extension.
     */
    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        purposeIdentifiers = []
        
        repeat {
            let purposeIdentifier = try OID(decoder: sequence)
            purposeIdentifiers.append(purposeIdentifier)
        } while sequence.more
        
        try sequence.assertAtEnd()
    }
    
    /**
     Initialize instance from extension.
     */
    public init(from extn: X509Extension) throws
    {
        let decoder = DERDecoder(bytes: extn.extnValue)
        try self.init(decoder: decoder)
        try decoder.assertAtEnd()
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        for purposeIdentifier in purposeIdentifiers {
            sequence.encode(purposeIdentifier)
        }
        
        encoder.encodeSequence(bytes: sequence.bytes)
    }
    
}


// End of File
