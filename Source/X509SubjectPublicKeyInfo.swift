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


public struct X509SubjectPublicKeyInfo: DERCodable {
    
    // MARK: - Properties
    public var algorithm        : X509Algorithm
    public var subjectPublicKey : X509PublicKey
    
    // MARK: - Initializers
    
    public init(algorithm: X509Algorithm, subjectPublicKey: X509PublicKey)
    {
        self.algorithm        = algorithm
        self.subjectPublicKey = subjectPublicKey
    }

    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        algorithm        = try X509Algorithm(decoder: sequence)
        subjectPublicKey = try X509PublicKey(decoder: sequence)
        
        try sequence.assertAtEnd()
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()

        sequence.encode(algorithm)
        sequence.encode(subjectPublicKey)
        
        encoder.encodeSequence(bytes: sequence.bytes)
    }
    
}


// End of File
