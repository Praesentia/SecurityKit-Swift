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
public struct X509TBSCertificate {
    
    // MARK: - Properties
    public var data            : Data
    public var version         : [UInt8]?
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
    
    // MARK: - Initializers
    
    public init(serialNumber: [UInt8], algorithm: X509Algorithm, issuer: X509Name, validity: X509Validity, subject: X509Name, publicKey: X509SubjectPublicKeyInfo)
    {
        self.data         = Data()
        self.serialNumber = serialNumber
        self.algorithm    = algorithm
        self.issuer       = issuer
        self.validity     = validity
        self.subject      = subject
        self.publicKey    = publicKey
    }
    
}


// End of File
