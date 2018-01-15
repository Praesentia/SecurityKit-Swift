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
 X509 Extension
 
 - Requirement: RFC-5280, 4.1
 */
public struct X509Extension: ASN1Codable {
    
    // MARK: - Properties
    public var extnID    : ASN1OID
    public var critical  : Bool?
    public var extnValue : Data
    
    // MARK: - Initializers

    public init(extnID: ASN1OID, extnValue: Data, critical: Bool? = nil)
    {
        self.extnID    = extnID
        self.critical  = critical
        self.extnValue = extnValue
    }
    
    public init<T: ASN1Encodable>(extnID: ASN1OID, extnValue: T, critical: Bool? = nil) throws
    {
        let data = try DEREncoder().encode(extnValue)

        self.init(extnID: extnID, extnValue: data, critical: critical)
    }

    // MARK: - ASN1Codable
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let sequence = try decoder.sequence()
        
        extnID    = try sequence.decode(ASN1OID.self)
        critical  = try sequence.decodeIfPresent(Bool.self)
        extnValue = try Data(sequence.decode(ASN1OctetString.self).bytes)

        try sequence.assertAtEnd()
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()
        
        try sequence.encode(extnID)
        try sequence.encode(critical)
        try sequence.encode(ASN1OctetString(bytes: [UInt8](extnValue)))
    }
    
    
}


// End of File
