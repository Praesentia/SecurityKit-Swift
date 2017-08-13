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
 SecurityManager protocol.
 
 Functionally, the protocol follows a security enclave model such that private
 keys are never passed out of the interface.   All cryptographic operations
 involving these keys must be performed within the enclave.
 
 only one type of credentials can be associated for each identity...
 
 - Remark:
    The interface is somewhat primitive at the moment.
    Only one of each type of credential can be associated with an identity.
 */
public protocol SecurityManager: class {
    
    // MARK: - Digest
    
    func digest(ofType type: DigestType) -> Digest
    
    // MARK: - Random Data
    
    /**
     Generate random bytes.
     
     Generates an array of random bytes.
     
     - Parameters:
        - count: Size of the returned array.
     
     - Returns: Returns the array of random bytes.
     */
    func randomBytes(count: Int) -> [UInt8]
    
    // MARK: - General Credentials
    
    /**
     Instantiate credentials from profile.
     
     Instantiate credentials from profile data.
     
     Credentials instantiated in this manner are ephemeral.
     
     - Parameters
        - identity: The identity of the principal.
     */
    func instantiateCredentials(for identity: Identity, from profile: Any, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    
    // MARK: - Public Key Certificates
    
    func instantiateCertificate(from certificate: X509Certificate) -> Certificate?
    
    func findCertificates(for identity: Identity, completionHandler completion: @escaping ([Certificate]?, Error?) -> Void)
    
    func loadChain(for certificate: Certificate, completionHandler completion: @escaping ([Certificate]?, Error?) -> Void)
    
    func createPublicKeyCertificate(for identity: Identity, keySize: UInt, completionHandler completion: @escaping (Certificate?, Error?) -> Void)
    func createPublicKeyCertificate(for identity: Identity, keySize: UInt, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (Certificate?, Error?) -> Void)

    // MARK: - Public Key Credentials
    
    func findRootCredentials(completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)
    func findPublicKeyCredentials(for identity: Identity, completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)
    
    /**
     Create public key credentials.
     
     Create self-signed public key credentials for identity.
     
     - Parameters:
        - identity:
        - completion:
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func createPublicKeyCredentials(for identity: Identity, keySize: UInt, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    
    /**
     Create public key credentials.
     
     Create certified public key credentials for identity.
     
     - Parameters:
        - identity:
        - issuer:
        - completion:
     */
    func createPublicKeyCredentials(for identity: Identity, keySize: UInt, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    
    /**
     Create public key credentials.
     
     Create certified public key credentials from existing credentials.
     
     - Parameters:
         - credentials:
         - completion:
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func createPublicKeyCredentials(from credentials: Credentials, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    
    /**
     Import credentials from X509 data.
     
     Import credentials from X509 data and add them to the security enclave
     persistent store.
     
     - Parameters:
        - data:       DER encoded X509 data representing the credentials to be imported.
        - completion:
     
     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func importPublicKeyCredentials(from data: Data, completionHandler completion: @escaping (Certificate?, Error?) -> Void)
    
    func importPublicKeyCredentials(from certificate: Certificate, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    
    /**
     Import credentials from pkcs12 data.
     
     Import credentials from pkcs12 data and add them to the security enclave
     persistent store.
     
     - Parameters:
        - data:       DER encoded pkcs12 data representing the credentials to be imported.
        - password:   A password used to unlock the pkcs12 data prior to being imported.
        - completion:
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func importPublicKeyCredentials(from data: Data, with password: String, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    
    /**
     Import public key credentials.
     
     Any private key associated with the credentials will be ignored.
     
     - Parameters:
         - credentials: Public key credentials to be imported.
         - completion:
     */
    func importPublicKeyCredentials(_ credentials: PublicKeyCredentials, completionHandler completion: @escaping (Error?) -> Void)
    
    /**
     Instantiate public key credentials.
     
     Instantiate public key credentials from data.
     
     Credentials instantiated in this manner are ephemeral.
     
     - Parameters
        - identity: The identity of the principal.
        - data:     A DER encoded X509 leaf certificate.
        - chain:    A chain of intermediate signing authorities, consisting of DER encoded X509 certificates.
     
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func instantiatePublicKeyCredentials(for identity: Identity, from data: Data, chain: [Data], completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)
    
    func instantiatePublicKeyCredentials(using certificate: Certificate, chain: [Certificate]) -> PublicKeyCredentials?

    // MARK: - Shared Secret Credentials
    
    /**
     Import shared secret credentials.
     
     Imports a shared secret within the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     lost.
     
     - Parameters:
        - identity:  The identity to which the shared secret will be associated.
        - secret:    The secret to be interned within the security enclave.
        - completion A completion handler that will be invoked will the result
                     of the operation.
      
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     
     - Remark:
         Password strings may be converted to a byte array by encoding the
         string as a UTF-8 byte sequence.
     */
    func importSharedSecretCredentials(for identity: Identity, with secret: [UInt8], completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    
    func loadSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (Credentials?, Error?) -> Void)
    
    func removeSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (Error?) -> Void)

    
}


// End of File
