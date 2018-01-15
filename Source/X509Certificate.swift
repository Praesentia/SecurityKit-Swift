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


public struct X509Certificate: ASN1Codable {
    
    // MARK: - Protected
    public var tbsCertificate : X509TBSCertificate
    public var algorithm      : X509Algorithm
    public var signature      : Data
    public var fingerprint    : Data  { return fingerprint(using: .sha1) }
    public var data           : Data? { return try? DEREncoder().encode(self) }
    
    // MARK: - Initializers
    
    public init(tbsCertificate: X509TBSCertificate, algorithm: X509Algorithm, signature: Data)
    {
        self.tbsCertificate = tbsCertificate
        self.algorithm      = algorithm
        self.signature      = signature
    }

    // MARK: - ASN1Codable

    public init(from decoder: ASN1Decoder) throws
    {
        let sequence = try decoder.sequence()

        tbsCertificate = try sequence.decode(X509TBSCertificate.self)
        algorithm      = try sequence.decode(X509Algorithm.self)
        signature      = try Data(sequence.decode(ASN1BitString.self).bytes)
        
        try sequence.assertAtEnd()
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()

        try sequence.encode(tbsCertificate)
        try sequence.encode(algorithm)
        try sequence.encode(ASN1BitString(bytes: [UInt8](signature)))
    }

    // MARK: - Fingerprint
    
    public func fingerprint(using digestType: DigestType) -> Data
    {
        var fingerprint: Data!

        do {
            let data    = try DEREncoder().encode(self)
            let digest  = SecurityManagerShared.main.digest(ofType: digestType)

            fingerprint = digest.hash(data: data)
        }
        catch {

        }

        return fingerprint
    }
    
}


// End of File
