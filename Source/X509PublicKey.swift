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
 X509 PublicKey
 */
public struct X509PublicKey: DERCodable {
    
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
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280
     */
    public init(decoder: DERDecoder) throws
    {
        let bytes = try decoder.decodeBitString()
        
        self.init(bytes: bytes)
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        encoder.encodeBitString(bytes: [UInt8](data))
    }
    
}


// End of File

