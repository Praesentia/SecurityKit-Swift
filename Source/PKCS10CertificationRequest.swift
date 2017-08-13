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
 PKCS10 Certification request.
 
 - Requirements:
     RFC 2986, PKCS #10: Certification Request Syntax Specification Version 1.7
 */
public struct PCKS10CertificationRequest: DERCodable {
    
    // MARK: - Properties
    public var certificationRequestInfo: PCKS10CertificationRequestInfo
    public var signatureAlgorithm      : X509Algorithm
    public var signature               : [UInt8]
    public var bytes                   : [UInt8] { return encode() }
    
    // MARK: - Initializers
    
    public init(certificationRequestInfo: PCKS10CertificationRequestInfo, signatureAlgorithm: X509Algorithm, signature: [UInt8])
    {
        self.certificationRequestInfo = certificationRequestInfo
        self.signatureAlgorithm       = signatureAlgorithm
        self.signature                = signature
    }
    
    /**
     Initialize from data.
     
     - Parameters:
         - data: PKCS #10 formatted certification request.
     */
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
    
    /**
     Decode certifcation request.
     
     */
    public init(decoder: DERDecoder) throws
    {
        let sequence                 = try decoder.decoderFromSequence()
        let certificationRequestInfo = try PCKS10CertificationRequestInfo(decoder: sequence)
        let signatureAlgorithm       = try X509Algorithm(decoder: sequence)
        let signature                = try sequence.decodeBitString()
        try sequence.assertAtEnd()
        
        self.init(certificationRequestInfo: certificationRequestInfo, signatureAlgorithm: signatureAlgorithm, signature: signature)
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        sequence.encode(certificationRequestInfo)
        sequence.encode(signatureAlgorithm)
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
