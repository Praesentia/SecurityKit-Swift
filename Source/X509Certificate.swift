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


public struct X509Certificate: DERCodable {
    
    // MARK: - Protected
    public var tbsCertificate : X509TBSCertificate
    public var algorithm      : X509Algorithm
    public var signature      : [UInt8]
    public var bytes          : [UInt8] { return encode() }
    public var data           : Data    { return Data(bytes) }
    public var fingerprint    : [UInt8] { return fingerprint(using: .sha1) }
    
    // MARK: - Initializers
    
    public init(tbsCertificate: X509TBSCertificate, algorithm: X509Algorithm, signature: [UInt8])
    {
        self.tbsCertificate = tbsCertificate
        self.algorithm      = algorithm
        self.signature      = signature
    }

    public init?(from data: Data)
    {
        do {
            let decoder = DERDecoder(data: data)
            
            try self.init(decoder: decoder)
            try decoder.assertAtEnd()
        }
        catch {
            return nil
        }
    }
    
    public init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        tbsCertificate = try X509TBSCertificate(decoder: sequence)
        algorithm      = try X509Algorithm(decoder: sequence)
        signature      = try sequence.decodeBitString()
        try sequence.assertAtEnd()
    }
    
    // MARK: - Fingerprint
    
    public func fingerprint(using digestType: DigestType) -> [UInt8]
    {
        let digest = SecurityManagerShared.main.digest(ofType: digestType)
        return digest.hash(bytes: bytes)
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        sequence.encode(tbsCertificate)
        sequence.encode(algorithm)
        sequence.encodeBitString(bytes: signature)
        
        encoder.encodeSequence(bytes: sequence.bytes)
    }
    
    private func encode() -> [UInt8]
    {
        let encoder = DEREncoder()
        
        encoder.encode(self)
        
        return encoder.bytes
    }
    
}


// End of File
