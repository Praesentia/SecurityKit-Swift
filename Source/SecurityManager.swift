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
 SecurityManager protocol.
 
 Functionally, the protocol follows a security enclave model such that private
 keys are never expossed by the interface.   All cryptographic operations
 involving these keys are performed within the enclave.
 */
public protocol SecurityManager: class {
    
    // MARK: - Digest

    /**
     Instantiate digest of type.

     Instantiate digest of type.

     - Parameters:
        - type: The type of digest to be instantiated.

     - Returns:
         A new digest of the specified type.
     */
    func digest(ofType type: DigestType) -> Digest
    
    // MARK: - Random Data

    /**
     Generate random value.
     */
    func random(_ type: Int.Type) -> Int

    /**
     Generate random value.
     */
    func random(_ type: UInt.Type) -> UInt

    /**
     Generate random value.
     */
    func random(_ type: UInt8.Type) -> UInt8

    /**
     Generate random value.
     */
    func random(_ type: UInt16.Type) -> UInt16

    /**
     Generate random value.
     */
    func random(_ type: UInt32.Type) -> UInt32

    /**
     Generate random value.
     */
    func random(_ type: UInt64.Type) -> UInt64

    /**
     Generate random bytes.
     
     Generates an array of random bytes.
     
     - Parameters:
        - count: Size of the returned array.
     
     - Returns:
         Returns the array of random bytes.
     */
    func randomBytes(count: Int) -> [UInt8]
    
    // MARK: - Credentials
    
    /**
     Instantiate credentials from decoder.
     
     Instantiate credentials from decoder.
     
     Credentials instantiated in this manner are ephemeral.
     
     - Parameters
         - identity: The identity of the principal.

        - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func decodeCredentials(from decoder: Decoder) throws -> Credentials
    
    // MARK: - Public Key Certificates
    
    /**
     Instantiate certificate from X509 certificate.

     Instantiate certificate from X509 certificate.

     - Parameters
         - certificate: An X509 certificate.
     */
    func instantiateCertificate(from certificate: X509Certificate) -> Certificate?
    
    /**
     Find certificates for identity.

     Find certificates for identity.

     - Parameters
         - identity: Identity.

       - Invariant:
         (error == nil) ⇒ (certificates != nil)
     */
    func findCertificates(for identity: Identity, completionHandler completion: @escaping ([Certificate]?, Error?) -> Void)
    
    /**
     Load certificate chain.

     Load certificate chain.

     - Parameters
         - certificate: A certificate.

      - Invariant:
         (error == nil) ⇒ (certificates != nil)
     */
    func loadChain(for certificate: Certificate, completionHandler completion: @escaping (_ certificates: [Certificate]?, _ error: Error?) -> Void)
    
    /**
     Create public key certificate for identity.

     Create public key certificate for identity.

     - Parameters
         - identity: Identity
         - keySize : Key size on bits.

      - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func createPublicKeyCertificate(for identity: Identity, keySize: UInt, completionHandler completion: @escaping (_ certificate: Certificate?, _ error: Error?) -> Void)

    /**
     Create certified public key certificate for identity.

     Create certified public key certificate for identity.

     - Parameters
         - identity: Identity
         - keySize : Key size on bits.
         - issuer  : Issuer crredentials.

      - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func createPublicKeyCertificate(for identity: Identity, keySize: UInt, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (Certificate?, Error?) -> Void)

    // MARK: - Public Key Credentials
    
    func findRootCredentials(completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)

    /**
     Find public key credentials for identity.

     Find public key credentials for identity.

     - Parameters:
         - identity:
         - completion:

     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func findPublicKeyCredentials(for identity: Identity, completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)

    /**
     Find public key credentials with fingerprint.

     Find public key credentials with fingerprint.

     - Parameters:
         - fingerprint:
         - completion:

     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func findPublicKeyCredentials(withFingerprint fingerprint: Data, completionHandler completion: @escaping (PublicKeyCredentials?, Error?) -> Void)

    /**
     Find list public key credentials with fingerprints.

     Find public key credentials with fingerprints.

     - Parameters:
         - fingerprints:
         - completion:

     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func findPublicKeyCredentials(withFingerprints fingerprints: [Data], completionHandler completion: @escaping ([PublicKeyCredentials]?, Error?) -> Void)

    /**
     Create public key credentials.
     
     Create self-signed public key credentials for identity.
     
     - Parameters:
         - identity:
         - completion:
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func createPublicKeyCredentials(for identity: Identity, keySize: UInt, completionHandler completion: @escaping (_ credentials: PublicKeyCredentials?, _ error: Error?) -> Void)
    
    /**
     Create public key credentials.
     
     Create certified public key credentials for identity.
     
     - Parameters:
         - identity:   Subject identity.
         - keySize:    Key size.
         - issuer:     Issuer credentials.
         - completion: Completion handler.

     - Parameters:
         - certificate: Credentials
         - error:       Error

     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func createPublicKeyCredentials(for identity: Identity, keySize: UInt, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (_ credentials: PublicKeyCredentials?, _ error: Error?) -> Void)
    
    /**
     Create public key credentials.
     
     Create certified public key credentials from existing credentials.
     
     - Parameters:
         - credentials:
         - completion:  Completion handler.

     - Parameters:
         - certificate: Certificate
         - error:       Error
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func createPublicKeyCredentials(from credentials: Credentials, certifiedBy issuer: PublicKeyCredentials, completionHandler completion: @escaping (_ credentials: PublicKeyCredentials?, _ error: Error?) -> Void)
    
    /**
     Import credentials from X509 data.
     
     Import credentials from X509 data and add them to the security enclave
     persistent store.
     
     - Parameters:
        - data:       DER encoded X509 data representing the credentials to be imported.
        - completion: Completion handler.

     - Parameters:
         - certificate: Certificate
         - error:       Error
     
     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func importPublicKeyCredentials(from data: Data, completionHandler completion: @escaping (_ certificate: Certificate?, _ error: Error?) -> Void)

    /**
     Import credentials from X509 data.

     Import credentials from X509 data and add them to the security enclave
     persistent store.

     - Parameters:
         - data:       DER encoded X509 data representing the credentials to be imported.
         - completion: Completion handler.

     - Parameters:
         - certificate: Certificate
         - error:       Error

     - Invariant:
         (error == nil) ⇒ (certificate != nil)
     */
    func importPublicKeyCredentials(from certificate: Certificate, completionHandler completion: @escaping (_ credentials: PublicKeyCredentials?, _ error: Error?) -> Void)
    
    /**
     Import credentials from PKCS12 data.
     
     Import credentials from PKCS12 data and add them to the security enclave
     persistent store.
     
     - Parameters:
        - data:       DER encoded PKCS12 data representing the credentials to be imported.
        - password:   A password used to unlock the pkcs12 data prior to being imported.
        - completion: Completion handler.=

     - Parameters:
         - credentials: Credentials
         - error:       Error
     
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func importPublicKeyCredentials(from data: Data, with password: String, completionHandler completion: @escaping (_ credentials: PublicKeyCredentials?, _ error: Error?) -> Void)
    
    /**
     Import public key credentials.
     
     Any private key associated with the credentials will be ignored.
     
     - Parameters:
         - credentials: Public key credentials to be imported.
         - completion:  Completion handler.
     */
    func importPublicKeyCredentials(_ credentials: PublicKeyCredentials, completionHandler completion: @escaping (Error?) -> Void)
    
    /**
     Instantiate public key credentials.
     
     Instantiate public key credentials from data.
     
     Credentials instantiated in this manner are ephemeral.
     
     - Parameters:
         - identity:   The identity of the principal.
         - data:       A DER encoded X509 leaf certificate.
         - chain:      A chain of intermediate signing authorities, consisting of DER encoded X509 certificates.
         - completion: Completion handler.

     - Parameters:
         - credentials: Credentials
         - error:       Error

     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func instantiatePublicKeyCredentials(from data: Data, chain: [Data], completionHandler completion: @escaping (_ credentials: PublicKeyCredentials?, _ error: Error?) -> Void)

    /**
     Instantiate public key credentials.

     Instantiate public key credentials from an existing certificate and
     certificate chain.

     - Parameters:
         - certificate: The identity of the principal.
         - chain:       A chain of intermediate signing authorities.
         - completion:  Completion handler.

     - Parameters:
         - credentials: Credentials
     */
    func instantiatePublicKeyCredentials(using certificate: Certificate, chain: [Certificate]) -> PublicKeyCredentials?

    // MARK: - Shared Secret Credentials
    
    /**
     Import shared secret credentials.
     
     Imports a shared secret within the security enclave for the specified
     identity.  Any existing shared secret associated with identity will be
     lost.
     
     - Parameters:
         - identity:   The identity to which the shared secret will be associated.
         - secret:     The secret to be interned within the security enclave.
         - completion: Completion handler.

     - Parameters:
         - credentials: Credentials
         - error:       Error
      
     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     
     - Remark:
         Password strings may be converted to a byte array by encoding the
         string as a UTF-8 byte sequence.
     */
    func importSharedSecretCredentials(for identity: Identity, with secret: Data, using encryptionAlgorithm: SymmetricEncryptionAlgorithm, completionHandler completion: @escaping (_ credentials: Credentials?, _ error: Error?) -> Void)
    
    /**
     Load shared secret credentials for identity.

     Loads shared secret credentials from the security enclave for the specified
     identity.

     - Parameters:
         - identity:   The identity associated with the shared secret.
         - completion: Completion handler.

     - Parameters:
         - credentials: Credentials.
         - identity   : Identity

     - Invariant:
         (error == nil) ⇒ (credentials != nil)
     */
    func loadSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (_ credentials: Credentials?, _ error: Error?) -> Void)
    
    /**
     Remove shared secret credentials for identity.

     Remove shared secret credentials from the security enclave for the specified
     identity.

     - Parameters:
         - identity:   The identity associated with the shared secret.
         - completion: Completion handler.

     - Parameters:
         - error: Error
     */
    func removeSharedSecretCredentials(for identity: Identity, completionHandler completion: @escaping (_ error: Error?) -> Void)

    
}


// End of File
