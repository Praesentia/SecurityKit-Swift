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


/*
  PKCS10 Certificate request information structure.
 
 - Requirements:
     RFC 2986, PKCS #10: Certification Request Syntax Specification Version 1.7
 */
public struct PCKS10CertificationRequestInfo: DERCodable {
    
    // MARK: - Properties
    public let version              : UInt = 0
    public var subject              : X509Name
    public var subjectPublicKeyInfo : X509SubjectPublicKeyInfo
    public var attributes           : [PKCS10Attribute]?
    
    // requested extensions
    public var basicConstraints : X509BasicConstraints?
    public var keyUsage         : X509KeyUsage?

    // encoded form
    public var bytes : [UInt8] { return encode() }
    public var data  : Data    { return Data(bytes) }
    
    // MARK: - Initializers
    
    public init(subject: X509Name, subjectPublicKeyInfo: X509SubjectPublicKeyInfo)
    {
        self.subject              = subject
        self.subjectPublicKeyInfo = subjectPublicKeyInfo
    }

    /**
     Decode certification request infomrmation.
     
     - Parameters:
         - decoder: 
     */
    public init(decoder: DERDecoder) throws
    {
        let sequence             = try decoder.decoderFromSequence()
        let version              = try PCKS10CertificationRequestInfo.decodeVersion(decoder: sequence)
        let subject              = try X509Name(decoder: sequence)
        let subjectPublicKeyInfo = try X509SubjectPublicKeyInfo(decoder: sequence)
        let attributes           = try PCKS10CertificationRequestInfo.decodeAttributes(decoder: sequence)
        try sequence.assertAtEnd()
        try sequence.assert(version == 0)

        self.init(subject: subject, subjectPublicKeyInfo: subjectPublicKeyInfo)
        self.attributes = attributes
        
        if let attributes = attributes {
            for attribute in attributes {
                switch attribute.type {
                case pkcs9ExtensionRequest :
                    //try decodeExtensionRequest(decoder: DERDecoder(bytes: attribute.values))
                    let decoder = DERDecoder(bytes: attribute.values)
                    repeat {
                        let extn = try X509Extension(decoder: decoder)
                        
                        switch extn.extnID {
                        case x509ExtnBasicConstraints :
                            basicConstraints = try X509BasicConstraints(from: extn)
                            break
                            
                        case x509ExtnKeyUsage :
                            keyUsage = try X509KeyUsage(from: extn)
                            break
                            
                        default :
                            break
                        }
                        
                    } while decoder.more
                    
                default :
                    break
                }
            }
        }
    }
    
    // MARK: - DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        sequence.encode(version)
        sequence.encode(subject)
        sequence.encode(subjectPublicKeyInfo)
        encodeAttributes(encoder: sequence)
        
        return encoder.encodeSequence(bytes: sequence.bytes)
    }
    
    private func encode() -> [UInt8]
    {
        let encoder = DEREncoder()
        
        encoder.encode(self)
        
        return encoder.bytes
    }
    
    // MARK: - Version
    
    private static func decodeVersion(decoder: DERDecoder) throws -> UInt
    {
        var version: UInt = 0
        
        if decoder.peekTag(with: DERCoder.TagInteger) {
            let bytes = try decoder.decodeUnsignedInteger()
            version = UInt(bytes[0])
        }
        
        return version
    }
    
    // MARK: - Attributes
    
    private func encodeAttributes(encoder: DEREncoder)
    {
        let content          = DEREncoder()
        let extensionRequest = DEREncoder()
        
        encodeExtensionRequest(encoder: extensionRequest)
        if !extensionRequest.isEmpty {
            let attribute = PKCS10Attribute(type: pkcs9ExtensionRequest, values: extensionRequest.bytes)
            content.encode(attribute)
        }
        
        if let attributes = self.attributes {
            for attribute in attributes {
                content.encode(attribute)
            }
        }
        
        if !content.isEmpty {
            encoder.encodeContextDefinedTag(id: 0, bytes: content.bytes)
        }
    }
    
    private static func decodeAttributes(decoder: DERDecoder) throws -> [PKCS10Attribute]?
    {
        var attributes: [PKCS10Attribute]!

        if decoder.peekContextDefinedTag(id: 0) {
            let content = try decoder.decoderFromContextDefinedTag(id: 0)
    
            if content.more {
                attributes = [PKCS10Attribute]()
                repeat {
                    let attribute = try PKCS10Attribute(decoder: content)
                    attributes.append(attribute)
                } while content.more
            }
        }
        
        return attributes
    }
    
    // MARK: - Extension Request

    /*
    private func decodeExtensionRequest(decoder: DERDecoder) throws
    {
        repeat {
            let extn = try X509Extension(decoder: decoder)
            
            switch extn.extnID {
            case x509ExtnBasicConstraints :
                basicConstraints = try X509BasicConstraints(from: extn)
                break
                
            case x509ExtnKeyUsage :
                keyUsage = try X509KeyUsage(from: extn)
                break
                
            default :
                break
            }
            
        } while decoder.more
    }
    */
    
    private func encodeExtensionRequest(encoder: DEREncoder)
    {
        if let basicConstraints = self.basicConstraints {
            let extn = X509Extension(extnID: x509ExtnBasicConstraints, codable: basicConstraints, critical: true)
            encoder.encode(extn)
        }
        
        if let keyUsage = self.keyUsage {
            let extn = X509Extension(extnID: x509ExtnKeyUsage, codable: keyUsage, critical: true)
            encoder.encode(extn)
        }
    }

    
}


// End of File
