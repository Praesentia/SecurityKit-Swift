/*
 -----------------------------------------------------------------------------
 This source file is part of MedSim.
 
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
 Credentials manager.
 */
public protocol CredentialsManager {
    
    // MARK: - Properties
    
    weak var delegate: CredentialsManagerDelegate? { get set }
    
    /**
     Identity.
     */
    var identity: Identity { get }
    
    /**
     Are credentials initialized?
     
     Indicates whether or not the identity's credentials have been initialized.
     Until the credentials have been initialized, the credential manager
     remains a blank slate.
     */
    var initialized: Bool { get }
    
    /**
     Is the identity paired?
     */
    var paired: Bool { get }
    
    /**
     */
    var credentials: PublicKeyCredentials? { get }
    
    // MARK: - Initialization
    
    /**
     Initialize the identity's credentials.
     
     This operation will erase any existing credentials.
     */
    func initialize(completionHandler completion: @escaping (Error?) -> Void)
    
    /**
     */
    func update(completionHandler completion: @escaping (Error?) -> Void)
    
    // MARK: - Pairing
    
    func createCertificationRequest(completionHandle completion: @escaping (PCKS10CertificationRequest?, Error?) -> Void)
    func importCertificate(_ certificate: X509Certificate, completionHandle completion: @escaping (Error?) -> Void)
    
}


// End of File

