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
public struct OID: Equatable, Hashable {
    
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
    
    // MARK: - Equatable
    
    public static func ==(_ lhs: OID, _ rhs: OID) -> Bool
    {
        return lhs.components == rhs.components
    }
    
}


// End of File
