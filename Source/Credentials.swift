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
 Credentials protocol.
 
 A protocol to be implemented by various the forms of credentials.  The
 protocol presumes some type of signing and verification algorithm.
 
 The protocol provides access to a JSON profile representing the public
 component of the credentials.  This is the profile that is exchanged
 between entities during authentication.
 */
public protocol Credentials: class  {
    
    // MARK: - Properties
    
    /**
     Identity
     
     The identity associated with the certificate.
     */
    var identity: Identity? { get }
    
    /**
     A JSON profile representing the public credentials.
     */
    var profile: Any { get }
    
    /**
     The credentials type
     */
    var type: CredentialsType { get }
    
    /**
     Validity period.
     
     Specifies a closed time period for which the credentials are valid.
     */
    var validity: ClosedRange<Date>? { get }
    
    // MARK: - Signing
    
    func sign(bytes: [UInt8], using digestType: DigestType) -> [UInt8]?
    
    func verify(signature: [UInt8], for bytes: [UInt8], using digestType: DigestType) -> Bool
    
    // MARK: - Authentication
    
    func verifyTrust(completionHandler completion: @escaping (Error?) -> Void)
    
}

public extension Credentials {
    
    /**
     Are credentials valid for date.
     
     - Parameters:
        - date: The time to be checked.
     */
    public func valid(for date: Date) -> Bool
    {
        return validity?.contains(date) ?? false
    }
    
}


// End of File
