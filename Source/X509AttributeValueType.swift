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


public struct X509AttributeValueType: DERCodable {
    
    // MARK: - Properties
    public var oid   : OID
    public var value : X509String
    
    // MARK: - Initializers
    
    public init(oid: OID, value: X509String)
    {
        self.oid   = oid
        self.value = value
    }
    
    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        oid   = try OID(decoder: sequence)
        value = try X509String(decoder: sequence)
        
        try sequence.assertAtEnd()
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        sequence.encode(oid)
        sequence.encode(value)
        
        return encoder.encodeSequence(bytes: sequence.bytes)
    }
    
}


// End of File
