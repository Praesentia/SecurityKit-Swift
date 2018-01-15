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


/*
  PKCS10 Certificate request information structure.
 
 - Requirements:
     RFC 2986, PKCS #10: Certification Request Syntax Specification Version 1.7
 */
public struct PCKS10CertificationRequestInfo: ASN1Codable {
    
    // MARK: - Properties
    public let version              : UInt?
    public var subject              : X509Name
    public var subjectPublicKeyInfo : X509SubjectPublicKeyInfo
    public var attributes           : [PKCS10Attribute]?
    public var data                 : Data? { return try? DEREncoder().encode(self) }
    
    // requested extensions
    public var basicConstraints : X509BasicConstraints?
    public var keyUsage         : X509KeyUsage?
    
    // MARK: - Initializers
    
    public init(version: UInt?, subject: X509Name, subjectPublicKeyInfo: X509SubjectPublicKeyInfo, attributes: [PKCS10Attribute]? = nil)
    {
        self.version              = version
        self.subject              = subject
        self.subjectPublicKeyInfo = subjectPublicKeyInfo
        self.attributes           = attributes
    }

    /**
     Decode certification request infomrmation.
     
     - Parameters:
         - decoder: 
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let sequence             = try decoder.sequence()
        let version              = try sequence.decodeIfPresent(UInt.self)
        let subject              = try sequence.decode(X509Name.self)
        let subjectPublicKeyInfo = try sequence.decode(X509SubjectPublicKeyInfo.self)
        var attributes           : [PKCS10Attribute]?

        if let content = try sequence.contextDefinedContainerIfPresent(id: 0) {
            attributes = try content.decode([PKCS10Attribute].self)
        }

        try sequence.assertAtEnd()
        try sequence.assert(version == 0)

        self.init(version: version, subject: subject, subjectPublicKeyInfo: subjectPublicKeyInfo, attributes: attributes)

        if let attributes = self.attributes {
            for attribute in attributes {
                switch attribute.type {
                case pkcs9ExtensionRequest :
                    let extensions = try DERDecoder().decode([X509Extension].self, from: attribute.values)
                    for extn in extensions {
                        switch extn.extnID {
                        case x509ExtnBasicConstraints :
                            basicConstraints = try DERDecoder().decode(X509BasicConstraints.self, from: extn.extnValue)
                            break
                            
                        case x509ExtnKeyUsage :
                            keyUsage = try DERDecoder().decode(X509KeyUsage.self, from: extn.extnValue)
                            break
                            
                        default :
                            break
                        }
                    }
                    
                default :
                    break
                }
            }
        }
    }
    
    // MARK: - ASN1Encodable
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()

        try sequence.encode(version)
        try sequence.encode(subject)
        try sequence.encode(subjectPublicKeyInfo)

        if let attributes = try encodeAttributes() {
            let content = try sequence.contextDefinedContainer(id: 0)
            try content.encode(attributes)
        }
    }
    
    // MARK: - Version
    
    private static func decodeVersion(from container: DERDecodingContainer) throws -> UInt
    {
        return try container.decodeIfPresent(UInt.self) ?? 0
    }
    
    // MARK: - Attributes
    
    private func encodeAttributes() throws -> [PKCS10Attribute]?
    {
        var attributes: [PKCS10Attribute]! = self.attributes

        if attributes == nil, let extensions = try encodeExtensions() {
            attributes = [PKCS10Attribute]()
            for extn in extensions {
                let values    = try DEREncoder().encode(extn)
                let attribute = PKCS10Attribute(type: pkcs9ExtensionRequest, values: values)
                attributes.append(attribute)
            }
        }

        return attributes
    }

    // MARK: - Extension Request

    private func encodeExtensions() throws -> [X509Extension]?
    {
        var extensions = [X509Extension]()

        if let basicConstraints = self.basicConstraints {
            let extn = try X509Extension(extnID: x509ExtnBasicConstraints, extnValue: basicConstraints, critical: true)
            extensions.append(extn)
        }
        
        if let keyUsage = self.keyUsage {
            let extn = try X509Extension(extnID: x509ExtnKeyUsage, extnValue: keyUsage, critical: true)
            extensions.append(extn)
        }

        return extensions.isEmpty ? nil : extensions
    }

    
}


// End of File
