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
 X509 TBS Certicate
 
 - Requirement: RFC-5280, 4.1
 */
public struct X509TBSCertificate: DERCodable {
    
    // MARK: - Properties
    public var version         : Int
    public var serialNumber    : [UInt8]
    public var algorithm       : X509Algorithm
    public var issuer          : X509Name
    public var validity        : X509Validity
    public var subject         : X509Name
    public var publicKey       : X509SubjectPublicKeyInfo
    public var issuerUniqueID  : [UInt8]?
    public var subjectUniqueID : [UInt8]?
    public var extensions      : [X509Extension]?
    
    // extensions
    public var basicConstraints : X509BasicConstraints?
    public var keyUsage         : X509KeyUsage?
    public var extendedKeyUsage : X509ExtendedKeyUsage?
    
    // encoded form
    public var bytes            : [UInt8] { return encode() }
    public var cache            : [UInt8]?

    // MARK: - Private Class Constants
    private static let defaultVersion     = 0
    private static let idVersion          = UInt8(0)
    private static let idIssuerUniqueID   = UInt8(1)
    private static let idSubjectUniqueID  = UInt8(2)
    private static let idExtensions       = UInt8(3)
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     
     Various extensions may be added once the instance has been initialized.
     */
    public init(serialNumber: [UInt8], algorithm: X509Algorithm, issuer: X509Name, validity: X509Validity, subject: X509Name, publicKey: X509SubjectPublicKeyInfo)
    {
        self.version      = 2
        self.serialNumber = serialNumber
        self.algorithm    = algorithm
        self.issuer       = issuer
        self.validity     = validity
        self.subject      = subject
        self.publicKey    = publicKey
    }
    
    /**
     Initialize instance from decoder.
     
     - Requirement: RFC 5280, 4.1
     */
    init(decoder: DERDecoder) throws
    {
        let sequence = try decoder.decoderFromSequence()
        
        version         = try X509TBSCertificate.decodeVersion(decoder: sequence)
        serialNumber    = try sequence.decodeUnsignedInteger()
        algorithm       = try X509Algorithm(decoder: sequence)
        issuer          = try X509Name(decoder: sequence)
        validity        = try X509Validity(decoder: sequence)
        subject         = try X509Name(decoder: sequence)
        publicKey       = try X509SubjectPublicKeyInfo(decoder: sequence)
        issuerUniqueID  = try X509TBSCertificate.decodeUniqueIdentifier(decoder: sequence, with: X509TBSCertificate.idIssuerUniqueID)
        subjectUniqueID = try X509TBSCertificate.decodeUniqueIdentifier(decoder: sequence, with: X509TBSCertificate.idSubjectUniqueID)
        extensions      = try X509TBSCertificate.decodeExtensions(decoder: sequence)
        
        cache = sequence.bytes
        
        if let extensions = extensions {
            for extn in extensions {
                switch extn.extnID {
                case x509ExtnBasicConstraints :
                    basicConstraints = try X509BasicConstraints(from: extn)
                    
                case x509ExtnKeyUsage :
                    keyUsage = try X509KeyUsage(from: extn)
                    
                case x509ExtnExtendedKeyUsage :
                    extendedKeyUsage = try X509ExtendedKeyUsage(from: extn)
                    
                default :
                    if extn.critical {
                        throw SecurityKitError.failed
                    }
                    break
                }
            }
        }
        
        try sequence.assertAtEnd()
        try verify()
    }
    
    // MARK: DERCodable
    
    public func encode(encoder: DEREncoder)
    {
        let version  = DEREncoder()
        let sequence = DEREncoder()
        
        version.encodeInteger(self.version)
        
        sequence.encodeContextDefinedTag(id: X509TBSCertificate.idVersion, bytes: version.bytes)
        sequence.encodeUnsignedInteger(bytes: serialNumber)
        sequence.encode(algorithm)
        sequence.encode(issuer)
        sequence.encode(validity)
        sequence.encode(subject)
        sequence.encode(publicKey)
        encodeUniqueIdentifier(encoder: encoder, with: X509TBSCertificate.idIssuerUniqueID,  uniqueIdentifier: issuerUniqueID)
        encodeUniqueIdentifier(encoder: encoder, with: X509TBSCertificate.idSubjectUniqueID, uniqueIdentifier: subjectUniqueID)
        encodeExtensions(encoder: sequence)
        
        encoder.encodeSequence(bytes: sequence.bytes)
    }
    
    private func encode() -> [UInt8]
    {
        if let bytes = cache {
            return bytes
        }
        
        let encoder = DEREncoder()
        
        encoder.encode(self)
        
        return encoder.bytes
    }
    
    // MARK: - Version
    
    /**
     Decode optional version number.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeVersion(decoder: DERDecoder) throws -> Int
    {
        var version = defaultVersion
        
        if decoder.peekContextDefinedTag(id: idVersion) {
            let content = try decoder.decoderFromContextDefinedTag(id: idVersion)
            version = try content.decodeIntegerAsValue()
        }
        
        return version
    }
    
    // MARK - Unique Identifiers
    
    /**
     Decode unique identifier.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeUniqueIdentifier(decoder: DERDecoder, with id: UInt8) throws -> [UInt8]?
    {
        var uniqueIdentifier: [UInt8]?
        
        if decoder.peekContextDefinedTag(id: id) {
            let decoder = try decoder.decoderFromContextDefinedTag(id: id)
            uniqueIdentifier = try decoder.decodeBitString()
        }
        
        return uniqueIdentifier
    }
    
    /**
     Encode unique identifier.
     
     - Requirement: RFC 5280, 4.1
     */
    private func encodeUniqueIdentifier(encoder: DEREncoder, with id: UInt8, uniqueIdentifier: [UInt8]?)
    {
        if let uniqueIdentifier = uniqueIdentifier {
            let content = DEREncoder()
            content.encodeBitString(bytes: uniqueIdentifier)
            encoder.encodeContextDefinedTag(id: id, bytes: content.bytes)
        }
    }
    
    // MARK: - Extensions
    
    /**
     Decode extensions.
     
     - Requirement: RFC 5280, 4.1
     */
    private static func decodeExtensions(decoder: DERDecoder) throws -> [X509Extension]?
    {
        if decoder.peekContextDefinedTag(id: idExtensions) {
            let content    = try decoder.decoderFromContextDefinedTag(id: idExtensions)
            let sequence   = try content.decoderFromSequence()
            var extensions = [X509Extension]()
            
            repeat {
                let extn = try X509Extension(decoder: sequence)
                extensions.append(extn)
            } while sequence.more
            
            try decoder.assertAtEnd()
            return extensions
        }
        
        return nil
    }
    
    private func encodeExtensions(encoder: DEREncoder)
    {
        let sequence = DEREncoder()
        
        if let basicConstraints = self.basicConstraints {
            let extn = X509Extension(extnID: x509ExtnBasicConstraints, codable: basicConstraints, critical: true)
            sequence.encode(extn)
        }
        
        if let keyUsage = self.keyUsage {
            let extn = X509Extension(extnID: x509ExtnKeyUsage, codable: keyUsage, critical: true)
            sequence.encode(extn)
        }
        
        if !sequence.isEmpty {
            let content = DEREncoder()
            content.encodeSequence(bytes: sequence.bytes)
            encoder.encodeContextDefinedTag(id: X509TBSCertificate.idExtensions, bytes: content.bytes)
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
