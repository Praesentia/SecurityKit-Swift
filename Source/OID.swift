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
 ASN.1 Object Identifier
 */
public struct OID: Equatable, Hashable, DERCodable {
    
    // MARK: - Properties
    
    /**
     OID components.
     */
    public var components: [UInt]
    
    /**
     Hash value.
     */
    public var hashValue: Int
    {
        var value = 0
        
        for component in components {
            value += Int(component)
        }
        
        return value
    }
    
    /**
     String representation.
     */
    public var string: String { return components.map { String($0) }.joined(separator: ".") }
    
    // MARK: - Initializers
    
    public init(components: [UInt])
    {
        self.components = components
    }
    
    public init(prefix: [UInt], components: [UInt])
    {
        self.components = prefix + components
    }
    
    public init(prefix: OID, components: [UInt])
    {
        self.components = prefix.components + components
    }
    
    public init(decoder: DERDecoder) throws
    {
        let bytes = try decoder.decode(with: DERCoder.TagObjectIdentifier)
        try decoder.assert(bytes.count > 0)
        
        var oid      = [UInt]()
        let oid0     = bytes[0] / 40
        let oid1     = bytes[0] - (oid0 * 40)
        var index    : Int  = 1
        var component: UInt = 0
        
        oid.append(UInt(oid0))
        oid.append(UInt(oid1))
        
        while index < bytes.count { // TODO: error check
            let byte = bytes[index]
            
            if byte < 0x80 {
                component = (component << 7) | UInt(byte)
                oid.append(component)
                component = 0
            }
            else {
                component = (component << 7) | UInt(byte & 0x7f)
            }
            
            index += 1
        }
        
        self.init(components: oid)
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        var value = [UInt8]()
        
        value += [UInt8(40 * components[0] + components[1])]
        
        for i in 2..<components.count {
            var component = components[i]
            var fragment  = [UInt8]()
            
            fragment.append(UInt8(component & 0x7f))
            
            while component >= 0x80 {
                component = component >> 7
                fragment.append(UInt8(component & 0x7f | 0x80))
            }
            
            value += fragment.reversed()
        }
        
        encoder.encodeTag(tag: DERCoder.TagObjectIdentifier, bytes: value)
    }
    
    // MARK: - Equatable
    
    public static func ==(_ lhs: OID, _ rhs: OID) -> Bool
    {
        return lhs.components == rhs.components
    }
    
}


// End of File
