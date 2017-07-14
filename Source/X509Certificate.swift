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


public struct X509Certificate {
    
    public var data           : Data
    public var tbsCertificate : X509TBSCertificate
    public var algorithm      : X509Algorithm
    public var signature      : [UInt8]
    
    public init(tbsCertificate: X509TBSCertificate, algorithm: X509Algorithm, signature: [UInt8])
    {
        self.data           = Data()
        self.tbsCertificate = tbsCertificate
        self.algorithm      = algorithm
        self.signature      = signature
    }
    
    public func fingerprint(using digestType: DigestType) -> [UInt8]
    {
        let digest = SecurityManagerShared.main.digest(using: digestType)
        
        digest.update(data: data)
        return digest.final()
    }
    
}


// End of File
