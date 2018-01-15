/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKitAOS.
 
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
 Public Key Credentials protocol.
 */
public protocol PublicKeyCredentials: class, Credentials {
    
    // MARK: - Properties
    var certificate : Certificate   { get }
    var chain       : [Certificate] { get }
    
    func certifyRequest(_ certificationRequest: PCKS10CertificationRequest, completionHandler completion: @escaping (X509Certificate?, Error?) -> Void)
    
}

public extension PublicKeyCredentials {

    public var identity   : Identity?          { return certificate.identity   }
    public var publicKey  : PublicKey          { return certificate.publicKey  }
    public var privateKey : PrivateKey?        { return certificate.privateKey }
    public var validity   : ClosedRange<Date>? { return certificate.validity   }
    
}


// End of File

