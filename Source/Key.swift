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
 */
public protocol Key: class {
    
    // MARK: - Properties
    var keySize: UInt { get }
    
    // MARK: - Signing
    
    /**
     Sign bytes for identity.
     
     Generate a signature for the specified bytes using the private credentials
     associated with identity.
     
     - Parameters:
         - bytes:      The byte sequence to be signed.
         - digestType:
     
     - Returns:
         Returns the signature as a sequence a bytes, or nil.
     */
    func sign(data: Data, using digestType: DigestType) -> Data
    
    /**
     Verify signature for identity.
     
     - Parameters:
        - signature: The signature to be verified.
        - bytes:     The byte sequence to be verified.
     */
    func verify(signature: Data, for data: Data, using digestType: DigestType) -> Bool
}


// End of File
