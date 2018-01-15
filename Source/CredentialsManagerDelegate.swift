/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityManager.
 
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
 CredentialsManager observer.
 */
public protocol CredentialsManagerDelegate: class {
    
    /**
     Did initialize.
     */
    func credentialsManagerBaseKeySize(_ manager: CredentialsManager) -> UInt
    
    /**
     Did initialize.
     */
    func credentialsManagerSigningKeySize(_ manager: CredentialsManager) -> UInt
    
    /**
     Did initialize.
     */
    func credentialsManagerDidInitialize(_ manager: CredentialsManager)
    
    /**
     Did update signing credentials.
     */
    func credentialsManagerDidUpdate(_ manager: CredentialsManager)
    
    /**
     Did update signing credentials.
     */
    func credentialsManagerDidUpdateCredentials(_ manager: CredentialsManager)
    
}

public extension CredentialsManagerDelegate {
  
    func credentialsManagerDidInitialize(_ manager: CredentialsManager) {}
    func credentialsManagerDidUpdate(_ manager: CredentialsManager) {}
    func credentialsManagerDidUpdateCredentials(_ manager: CredentialsManager) {}
    
}


// End of File

