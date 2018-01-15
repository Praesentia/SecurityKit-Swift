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


public struct X509AttributeValueType: ASN1Codable {
    
    // MARK: - Properties
    public var oid   : ASN1OID
    public var value : ASN1String
    
    // MARK: - Initializers
    
    public init(oid: ASN1OID, value: ASN1String)
    {
        self.oid   = oid
        self.value = value
    }

    // MARK: - ASN1Codable
    
    public init(from decoder: ASN1Decoder)  throws
    {
        let sequence = try decoder.sequence()
        
        oid   = try sequence.decode(ASN1OID.self)
        value = try sequence.decode(ASN1String.self)
        try sequence.assertAtEnd()
    }

    /**
     Encode

     - Parameters:
         - encoder: ASN1Encoder to which the instance will be encoded.
     */
    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()
        
        try sequence.encode(oid)
        try sequence.encode(value)
    }
    
}


// End of File
