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
 X509 TBS Certicate
 
 - Requirement: RFC-5280, 4.1
 */
public struct X509TBSCertificate: ASN1Codable {
    
    // MARK: - Properties
    public var version         : Int?
    public var serialNumber    : ASN1UnsignedInteger
    public var algorithm       : X509Algorithm
    public var issuer          : X509Name
    public var validity        : X509Validity
    public var subject         : X509Name
    public var publicKey       : X509SubjectPublicKeyInfo
    public var issuerUniqueID  : ASN1BitString?
    public var subjectUniqueID : ASN1BitString?
    public var extensions      : [X509Extension]?
    public var data            : Data { return cache != nil ? Data(cache!) : try! DEREncoder().encode(self) }
    
    // extensions
    public var basicConstraints : X509BasicConstraints?
    public var keyUsage         : X509KeyUsage?
    public var extendedKeyUsage : X509ExtendedKeyUsage?
    
    // encoded form
    public var cache            : [UInt8]?

    // MARK: - Private Class Constants
    private static let idVersion          = UInt8(0)
    private static let idIssuerUniqueID   = UInt8(1)
    private static let idSubjectUniqueID  = UInt8(2)
    private static let idExtensions       = UInt8(3)
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     Various extensions may be added once the instance has been initialized.
     */
    public init(serialNumber: ASN1UnsignedInteger, algorithm: X509Algorithm, issuer: X509Name, validity: X509Validity, subject: X509Name, publicKey: X509SubjectPublicKeyInfo)
    {
        self.version      = 2
        self.serialNumber = serialNumber
        self.algorithm    = algorithm
        self.issuer       = issuer
        self.validity     = validity
        self.subject      = subject
        self.publicKey    = publicKey
    }

    // MARK: - ASN1Codable
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    public init(from decoder: ASN1Decoder) throws
    {
        let sequence = try decoder.sequence()
        
        version         = try X509TBSCertificate.decodeVersion(from: sequence)
        serialNumber    = try sequence.decode(ASN1UnsignedInteger.self)
        algorithm       = try sequence.decode(X509Algorithm.self)
        issuer          = try sequence.decode(X509Name.self)
        validity        = try sequence.decode(X509Validity.self)
        subject         = try sequence.decode(X509Name.self)
        publicKey       = try sequence.decode(X509SubjectPublicKeyInfo.self)
        issuerUniqueID  = try X509TBSCertificate.decodeUniqueIdentifier(from: sequence, with: X509TBSCertificate.idIssuerUniqueID)
        subjectUniqueID = try X509TBSCertificate.decodeUniqueIdentifier(from: sequence, with: X509TBSCertificate.idSubjectUniqueID)
        extensions      = try X509TBSCertificate.decodeExtensions(from: sequence)
        try sequence.assertAtEnd()
        
        if let extensions = extensions {
            for extn in extensions {
                switch extn.extnID {
                case x509ExtnBasicConstraints :
                    basicConstraints = try DERDecoder().decode(X509BasicConstraints.self, from: extn.extnValue)
                    
                case x509ExtnKeyUsage :
                    keyUsage = try DERDecoder().decode(X509KeyUsage.self, from: extn.extnValue)
                    
                case x509ExtnExtendedKeyUsage :
                    extendedKeyUsage = try DERDecoder().decode(X509ExtendedKeyUsage.self, from: extn.extnValue)
                    
                default :
                    if extn.critical ?? false {
                        throw SecurityKitError.failed
                    }
                    break
                }
            }
        }
        
        try sequence.assertAtEnd()
        try verify()

        cache = sequence.bytes
    }
    
    public func encode(to encoder: ASN1Encoder) throws
    {
        let sequence = try encoder.sequence()

        if let version = self.version {
            let container = try sequence.contextDefinedContainer(id: X509TBSCertificate.idVersion)
            try container.encode(version)
        }

        try sequence.encode(serialNumber)
        try sequence.encode(algorithm)
        try sequence.encode(issuer)
        try sequence.encode(validity)
        try sequence.encode(subject)
        try sequence.encode(publicKey)
        try encodeUniqueIdentifier(container: sequence, with: X509TBSCertificate.idIssuerUniqueID,  uniqueIdentifier: issuerUniqueID)
        try encodeUniqueIdentifier(container: sequence, with: X509TBSCertificate.idSubjectUniqueID, uniqueIdentifier: subjectUniqueID)
        try encodeExtensions(container: sequence)
    }
    
    // MARK: - Version
    
    /**
     Decode optional version number.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeVersion(from container: ASN1DecodingContainer) throws -> Int?
    {
        var version: Int?

        if let container = try container.contextDefinedContainerIfPresent(id: idVersion) {
            version = try container.decode(Int.self)
        }
        return version
    }
    
    // MARK - Unique Identifiers
    
    /**
     Decode unique identifier.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeUniqueIdentifier(from container: ASN1DecodingContainer, with id: UInt8) throws -> ASN1BitString?
    {
        var uniqueIdentifier: ASN1BitString?

        if let container = try container.contextDefinedContainerIfPresent(id: id) {
            uniqueIdentifier = try container.decode(ASN1BitString.self)
        }
        return uniqueIdentifier
    }
    
    /**
     Encode unique identifier.
     
     - Requirement: RFC 5280, 4.1
     */
    private func encodeUniqueIdentifier(container: ASN1EncodingContainer, with id: UInt8, uniqueIdentifier: ASN1BitString?) throws
    {
        if let uniqueIdentifier = uniqueIdentifier {
            let context = try container.contextDefinedContainer(id: id)
            try context.encode(uniqueIdentifier)
        }
    }
    
    // MARK: - Extensions
    
    /**
     Decode extensions.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeExtensions(from container: ASN1DecodingContainer) throws -> [X509Extension]?
    {
        var extensions: [X509Extension]?

        if let container = try container.contextDefinedContainerIfPresent(id: idExtensions) {
            let sequence = try container.sequence()
            extensions   = try sequence.decode([X509Extension].self)
        }
        
        return extensions
    }
    
    private func encodeExtensions(container: ASN1EncodingContainer) throws
    {
        var extensions: [X509Extension]! = self.extensions

        if extensions == nil {
            extensions = [X509Extension]()

            if let basicConstraints = self.basicConstraints {
                let extn = try X509Extension(extnID: x509ExtnBasicConstraints, extnValue: basicConstraints, critical: true)
                extensions.append(extn)
            }

            if let keyUsage = self.keyUsage {
                let extn = try X509Extension(extnID: x509ExtnKeyUsage, extnValue: keyUsage, critical: true)
                extensions.append(extn)
            }
        }

        if !extensions.isEmpty {
            let container = try container.contextDefinedContainer(id: X509TBSCertificate.idExtensions)
            let sequence  = try container.sequence()
            try sequence.encode(extensions)
        }
    }
    
    // MARK: - Verify
    
    /**
     Verify certificate.
     */
    private func verify() throws
    {
    }
    
}


// End of File
