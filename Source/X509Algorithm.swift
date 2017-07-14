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


public struct X509Algorithm {
    
    // MARK: - Class Properties
    public static let rsaEncryption           = X509Algorithm(oid: pkcs1RSAEncryption)
    public static let md5WithRSAEncryption    = X509Algorithm(oid: pkcs1MD5WithRSAEncryption)
    public static let sha1WithRSAEncryption   = X509Algorithm(oid: pkcs1SHA1WithRSAEncryption)
    public static let sha256WithRSAEncryption = X509Algorithm(oid: pkcs1SHA256WithRSAEncryption)
    public static let sha384WithRSAEncryption = X509Algorithm(oid: pkcs1SHA384WithRSAEncryption)
    public static let sha512WithRSAEncryption = X509Algorithm(oid: pkcs1SHA512WithRSAEncryption)
    
    // MARK - Private Class Properties
    private static let mapAlgorithmToDigest : [ OID : DigestType ] = [
        pkcs1MD5WithRSAEncryption    : .md5,
        pkcs1SHA1WithRSAEncryption   : .sha1,
        pkcs1SHA256WithRSAEncryption : .sha256,
        pkcs1SHA384WithRSAEncryption : .sha384,
        pkcs1SHA512WithRSAEncryption : .sha512
    ]
    
    private static let localizedDescriptions : [ OID : String ] = [
        pkcs1RSAEncryption           : NSLocalizedString("RSA Encryption",              comment: "X509 algorithm."),
        pkcs1MD5WithRSAEncryption    : NSLocalizedString("MD5 with RSA Encryption",     comment: "X509 algorithm."),
        pkcs1SHA1WithRSAEncryption   : NSLocalizedString("SHA-1 with RSA Encryption",   comment: "X509 algorithm."),
        pkcs1SHA256WithRSAEncryption : NSLocalizedString("SHA-256 with RSA Encryption", comment: "X509 algorithm."),
        pkcs1SHA384WithRSAEncryption : NSLocalizedString("SHA-384 with RSA Encryption", comment: "X509 algorithm."),
        pkcs1SHA512WithRSAEncryption : NSLocalizedString("SHA-512 with RSA Encryption", comment: "X509 algorithm.")
    ]
    
    // MARK: - Properties
    public var oid                 : OID
    public var parameters          : [UInt8]?
    public var digest              : DigestType? { return X509Algorithm.mapAlgorithmToDigest[oid] }
    public var localizedDescription: String?     { return X509Algorithm.localizedDescriptions[oid] }

    // MARK: - Initializers
    
    public init(oid: OID, parameters: [UInt8]? = nil)
    {
        self.oid        = oid
        self.parameters = parameters
    }
    
}


// End of File
