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
 PKCS10 Certification request.
 
 - Requirements:
     RFC 2986, PKCS #10: Certification Request Syntax Specification Version 1.7
 */
public struct PCKS10CertificationRequest: ASN1Codable {
    
    // MARK: - Properties
    public var certificationRequestInfo: PCKS10CertificationRequestInfo
    public var signatureAlgorithm      : X509Algorithm
    public var signature               : Data
    
    // MARK: - Initializers
    
    public init(certificationRequestInfo: PCKS10CertificationRequestInfo, signatureAlgorithm: X509Algorithm, signature: Data)
    {
        self.certificationRequestInfo = certificationRequestInfo
        self.signatureAlgorithm       = signatureAlgorithm
        self.signature                = signature
    }
    
    /**
     Decode certifcation request.
     
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let sequence                 = try decoder.sequence()
        let certificationRequestInfo = try sequence.decode(PCKS10CertificationRequestInfo.self)
        let signatureAlgorithm       = try sequence.decode(X509Algorithm.self)
        let signature                = try Data(sequence.decode(ASN1BitString.self).bytes)
        try sequence.assertAtEnd()
        
        self.init(certificationRequestInfo: certificationRequestInfo, signatureAlgorithm: signatureAlgorithm, signature: signature)
    }
    
    // MARK: - ASN1Encodable
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()

        try sequence.encode(certificationRequestInfo)
        try sequence.encode(signatureAlgorithm)
        try sequence.encode(ASN1BitString(bytes: [UInt8](signature)))
    }
    
}


// End of File
