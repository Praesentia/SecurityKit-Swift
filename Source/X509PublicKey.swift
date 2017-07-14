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
public struct X509PublicKey {
    
    // MARK: - Properties
    public var data    : Data
    public var modulus : [UInt8]?
    public var exponent: [UInt8]?
    
    // MARK: - Initializers
    
    public init(data: Data)
    {
        self.data = data
    }
    
    public init(data: Data, modulus: [UInt8], exponent: [UInt8])
    {
        self.data     = data
        self.modulus  = modulus
        self.exponent = exponent
    }
    
}


// End of File

