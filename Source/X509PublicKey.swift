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
 X509 PublicKey
 */
public struct X509PublicKey: ASN1Codable {
    
    // MARK: - Properties
    public var bytes : [UInt8]
    public var data  : Data { return Data(bytes) }
    
    // MARK: - Initializers
    
    public init(bytes: [UInt8])
    {
        self.bytes = bytes
    }
    
    public init(data: Data)
    {
        self.init(bytes: [UInt8](data))
    }

    // MARK: - ASN1Codable

    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let bytes     = try container.decode(ASN1BitString.self).bytes
        
        self.init(bytes: bytes)
    }
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        try container.encode(ASN1BitString(bytes: [UInt8](data)))
    }
    
}


// End of File

