/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2016-2018 Jon Griffeth
 
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
 Digest
 
 A protocol for cryptographic hash functions that generate a message digest.
 */
public protocol Digest: class {
    
    /**
     Finializes the digest.
     
     Finalizes the algorithm state, generating a byte array representing the
     digest.  The size of byte array is algorithm dependent.
     
     - Returns:
        Retuns a byte array representing the digest.
     */
    func final() -> Data
    
    /**
     Reset state.
     */
    func reset()
    
    /**
     Update digest.
     
     - Parameters:
        - bytes: A byte array to be appended to the digest.
     */
    func update(bytes: [UInt8])
    
}

public extension Digest {
    
    public func hash(bytes: [UInt8]) -> Data
    {
        update(bytes: bytes)
        return final()
    }

    public func hash(data: Data) -> Data
    {
        update(data: data)
        return final()
    }

    /**
     Update digest.
     
     A convenience method for updating the digest for a single byte.
     
     - Parameters:
         - bytes: A byte to be apended to the digest.
     */
    public func update(byte: UInt8)
    {
        update(bytes: [UInt8](repeating: byte, count: 1))
    }
    
    /**
     Update digest.
     
     A convenience method for updating the digest from an optional byte array.
     */
    public func update(bytes: [UInt8]?)
    {
        if let bytes = bytes {
            update(bytes: bytes)
        }
    }

    /**
     Update digest from data.

     A convenience method for updating the digest from optional data.
     */
    public func update(data: Data)
    {
        update(bytes: [UInt8](data))
    }

    /**
     Update digest from data.
     
     A convenience method for updating the digest from optional data.
     */
    public func update(data: Data?)
    {
        if let data = data {
            update(bytes: [UInt8](data))
        }
    }
    
    /**
     Update digest from string.
     
     A convenience method for updating the digest from an optional string.
     */
    public func update(string: String?)
    {
        if let string = string {
            update(bytes: [UInt8](string.utf8))
        }
    }
    
    /**
     Update digest from string.
     
     A convenience method for updating the digest from an optional string.
     */
    public func update(prefixedString string: String?)
    {
        if let string = string {
            update(byte:  UInt8(string.count))
            update(bytes: [UInt8](string.utf8))
        }
    }
    
    /**
     Update digest from string.
     
     A convenience method for updating the digest from an optional UUID.
     */
    public func update(uuid: UUID?)
    {
        if let uuid = uuid {
            var bytes = [UInt8](repeating: 0, count: 16)
            
            (uuid as NSUUID).getBytes(&bytes)
            update(bytes: bytes)
        }
    }
    
}


// End of File
