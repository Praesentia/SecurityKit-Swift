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
 X509 Key Usage
 
 - Requirement: RFC 5280
 */
public struct X509KeyUsage: ASN1Codable {
    
    // MARK: - Properties
    public var digitalSignature : Bool
    public var nonRepudiation   : Bool
    public var keyEncipherment  : Bool
    public var dataEncipherment : Bool
    public var keyAgreement     : Bool
    public var keyCertSign      : Bool
    public var cRLSign          : Bool
    public var encipherOnly     : Bool
    public var decipherOnly     : Bool
    
    // MARK: - Initializers
    
    public init()
    {
        digitalSignature = true
        nonRepudiation   = true
        keyEncipherment  = true
        dataEncipherment = true
        keyAgreement     = true
        keyCertSign      = true
        cRLSign          = true
        encipherOnly     = true
        decipherOnly     = true
    }

    /**
     Initialize instance from extension.
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let bits      = try container.decode(ASN1BitString.self).bytes
        try container.assertAtEnd()

        // TODO: check unused bits
        digitalSignature = (bits[0] & 0x01) == 0x01
        nonRepudiation   = (bits[0] & 0x02) == 0x02
        keyEncipherment  = (bits[0] & 0x04) == 0x04
        dataEncipherment = (bits[0] & 0x08) == 0x08
        keyAgreement     = (bits[0] & 0x10) == 0x10
        keyCertSign      = (bits[0] & 0x20) == 0x20
        cRLSign          = (bits[0] & 0x40) == 0x40
        encipherOnly     = (bits[0] & 0x80) == 0x80

        if bits.count > 1 {
            decipherOnly = (bits[1] & 0x01) == 0x01
        }
        else {
            decipherOnly = false
        }
    }
    
    // MARK: - ASN1Encodable
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        var bits      = [UInt8](repeating: 0, count: 2)
        
        if digitalSignature {
            bits[0] |= 0x01
        }
        
        if nonRepudiation {
            bits[0] |= 0x02
        }
        
        if keyEncipherment {
            bits[0] |= 0x04
        }
        
        if dataEncipherment {
            bits[0] |= 0x08
        }
        
        if keyAgreement {
            bits[0] |= 0x10
        }
        
        if keyCertSign {
            bits[0] |= 0x20
        }
        
        if cRLSign {
            bits[0] |= 0x40
        }
        
        if encipherOnly {
            bits[0] |= 0x80
        }
        
        if decipherOnly {
            bits[1] |= 0x01
        }
        
        try container.encode(ASN1BitString(bytes: bits))
    }
    
}


// End of File
