/*
 -----------------------------------------------------------------------------
 This source file is part of MedSim.
 
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
 Credentials manager base class.
 */
public class CredentialsManagerBase: CredentialsManager {
    
    // MARK: - Properties
    public var      credentials : PublicKeyCredentials? { return signingCredentials }
    public weak var delegate    : CredentialsManagerDelegate?
    public let      identity    : Identity
    public var      initialized : Bool { return baseCredentials != nil }
    public var      paired      : Bool { return rootCredentials !== baseCredentials }
    
    public internal(set) var baseCredentials    : PublicKeyCredentials?
    public internal(set) var rootCredentials    : PublicKeyCredentials?
    public internal(set) var signingCredentials : PublicKeyCredentials?
    
    // MARK: - Protected Constants
    let keySizeBase    : UInt = 4096
    let keySizeSigning : UInt = 2048
    
    // MARK: - Protected Properties
    var authorization: Authorization = NullAuthorization.shared
    
    // MARK: - Initializers
    
    public init(for identity: Identity)
    {
        self.identity = identity
    }
    
    /**
     */
    public func update(completionHandler completion: @escaping (Error?) -> Void)
    {
        SecurityManagerShared.main.findPublicKeyCredentials(for: identity) { credentials, error in
            
            if error == nil, let credentials = credentials {
                self.findBase(credentials)
                self.findRoot(credentials)
                self.findSigning(credentials)
            }
            
            self.delegate?.credentialsManagerDidUpdate(self)
            completion(error)
        }
    }
    
    public func initialize(completionHandler completion: @escaping (Error?) -> Void)
    {
        let keySize = delegate?.credentialsManagerBaseKeySize(self) ?? keySizeBase
        
        generateBaseCertificate(keySize: keySize) { error in
            
            if error == nil {
                DispatchQueue.main.async {
                    self.delegate?.credentialsManagerDidInitialize(self)
                }
            }

            completion(error)
        }
    }
    
    // MARK: - Base Credentials
    
    /**
     Generate base certificate.
     */
    public func generateBaseCertificate(keySize: UInt, completionHandler completion: @escaping (Error?) -> Void)
    {
        SecurityManagerShared.main.createPublicKeyCredentials(for: identity, keySize: keySize) { credentials, error in
            if error == nil {
                self.baseCredentials    = credentials
                self.rootCredentials    = credentials
                self.signingCredentials = nil
            }
            completion(error)
        }
    }
    
    // MARK: - Root Credentials
    
    
    // MARK: - Pairing
    
    /**
     Create root certification request from base credentials.
     
     - Parameters:
         - completion:
     */
    public func createCertificationRequest(completionHandle completion: @escaping (PCKS10CertificationRequest?, Error?) -> Void)
    {
        var certificationRequest: PCKS10CertificationRequest?
        let sync                = Sync(SecurityKitError.failed)
        
        if let credentials = baseCredentials {
            
            sync.incr()
            credentials.certificate.createCertificationRequest() { request, error in
                if error == nil {
                    certificationRequest = request
                    sync.clear()
                }
                sync.decr(error)
            }
            
        }
        
        sync.close { error in
            completion(certificationRequest, error)
        }
    }
    
    /** Import credentials.
     
     - Parameters:
         - completion:
     */
    public func importCertificate(_ certificate: X509Certificate, completionHandle completion: @escaping (Error?) -> Void)
    {
        let certificate = SecurityManagerShared.main.instantiateCertificate(from: certificate)!
        let sync        = Sync()
        
        sync.incr()
        verifyRootCertificate(certificate) { error in
            if error == nil {
                sync.incr();
                self.importRootCertificate(certificate) { error in
                    sync.decr(error)
                }
            }
            sync.decr(error)
        }
        
        sync.close(completionHandler: completion)
    }
    
    /**
     Verify root certificate.
     
     */
    func verifyRootCertificate(_ certificate: Certificate, completionHandler completion: @escaping (Error?) -> Void)
    {
        var error: Error? = SecurityKitError.failed
        
        if let baseCertificate = self.baseCredentials?.certificate {
            if certificate.twin(of: baseCertificate) {
                error = nil
            }
        }
        
        completion(error)
    }
    
    /**
     Import certified root credentials.
     
     Imports new, certified, root credentials.
     */
    func importRootCertificate(_ certificate: Certificate, completionHandler completion: @escaping (Error?) -> Void)
    {
        SecurityManagerShared.main.importPublicKeyCredentials(from: certificate) { credentials, error in
            if error == nil {
                self.rootCredentials    = credentials
                self.signingCredentials = nil
                self.checkSigningCredentials()
            }
            completion(error)
        }
    }
    
    // MARK: Signing Credentials
    
    /**
     Check signing credentials.
     */
    public func checkSigningCredentials()
    {
        if signingCredentials == nil {
            updateSigningCredentials() { error in }
        }
    }
    
    /**
     Update signing credentials.
     */
    public func updateSigningCredentials(completionHandler completion: @escaping (Error?) -> Void)
    {
        let sync    = Sync(SecurityKitError.failed)
        let keySize = delegate?.credentialsManagerSigningKeySize(self) ?? keySizeSigning
        
        if let rootCredentials = rootCredentials {
            
            sync.incr()
            SecurityManagerShared.main.createPublicKeyCredentials(for: identity, keySize: keySize, certifiedBy: rootCredentials) { credentials, error in
                if error == nil, let credentials = credentials {
                    self.signingCredentials = credentials
                    sync.clear();
                }
                sync.decr(error)
            }
            
        }
        
        sync.close { error in
            
            if error == nil {
                DispatchQueue.main.async {
                    self.delegate?.credentialsManagerDidUpdateCredentials(self)
                }
            }
            
            DispatchQueue.main.async { completion(error) }
        }
    }
    
    // MARK: - Temporary

    func findBase(_ list: [PublicKeyCredentials])
    {
        let result = findAll(in: list, where: { $0.certificate.selfSigned() })
        
        switch result.count {
        case 0 :
            baseCredentials = nil
            
        case 1 :
            baseCredentials = result.first
            
        default :
            baseCredentials = result.first /// TODO: for now
        }
    }
    
    func findRoot(_ list: [PublicKeyCredentials])
    {
        let result = findSignedCredentials(in: list)
        
        switch result.count {
        case 0 :
            rootCredentials = baseCredentials
            
        case 1 :
            rootCredentials = result.first

        default :
            rootCredentials = result.first // TODO: for now
        }
    }
    
    func findSigning(_ list: [PublicKeyCredentials])
    {
        let result = findSigningCredentials(in: list)
        
        switch result.count {
        case 0 :
            signingCredentials = nil
            
        case 1 :
            signingCredentials = result.first
            
        default :
            signingCredentials = result.first // TODO: for now
        }
    }
    
    private func findSignedCredentials(in list: [PublicKeyCredentials]) -> [PublicKeyCredentials]
    {
        var result = [PublicKeyCredentials]()
        
        if let baseCredentials = self.baseCredentials {
            result = findAll(in: list, where: { !$0.certificate.selfSigned() && $0.certificate.twin(of: baseCredentials.certificate) })
        }
        
        return result
    }
    
    private func findSigningCredentials(in list: [PublicKeyCredentials]) -> [PublicKeyCredentials]
    {
        var result = [PublicKeyCredentials]()
        
        if let rootCredentials = self.rootCredentials {
            result = findAll(in: list, where: { !$0.certificate.selfSigned() && $0.certificate.certifiedBy(rootCredentials.certificate) })
        }
        
        return result
    }
    
    private func findAll(in list: [PublicKeyCredentials], where selector: (PublicKeyCredentials) -> Bool) -> [PublicKeyCredentials]
    {
        var result = [PublicKeyCredentials]()
        
        for element in list {
            if selector(element) {
                result.append(element)
            }
        }
        
        return result
    }
    
}


// End of File




