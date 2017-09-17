/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2016-2017 Jon Griffeth
 
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
 Principal
 
 Represents a user account, device etc., consisting of an identity, credentials,
 and authorization.
 
 - Remark:
    Principal instances are immutable to prevent unintended side-effects.
    Changes to a principal requires the creation of a new instance.
 */
public class Principal {
    
    // MARK: - Properties
    public let authorization : Authorization
    public let credentials   : Credentials
    public let identity      : Identity
    public var profile       : Any { return getProfile() }
    
    // MARK: - Class Initializers

    /** Instantiate from profile.
     */
    public static func instantiate(from profile: Any, completionHandler completion: @escaping (Principal?, Error?) -> Void)
    {
        let profile       = profile as! [String : Any]
        let identity      = Identity(from: profile[KeyIdentity]!)
        let authorization = AuthorizationFactoryDB.main.instantiate(from: profile[KeyAuthorization]!)
        var principal     : Principal?
        let sync          = Sync()
        
        sync.incr()
        SecurityManagerShared.main.instantiateCredentials(for: identity, from: profile[KeyCredentials]!) { credentials, error in

            if error == nil, let credentials = credentials {
                sync.incr()
                credentials.verifyTrust() { error in
                    if error == nil {
                        principal = Principal(identity: identity, credentials: credentials, authorization: authorization)
                    }
                    else {
                        NSLog("Credentials for \"\(identity.string)\" are not trusted.")
                    }
                    sync.decr(error)
                }
            }
            else {
                NSLog("Credentials for \"%s\" are not valid.", identity.string)
            }
            
            sync.decr(error)
        }
        
        sync.close() { error in
            completion(principal, error)
        }
    }
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    public init(identity: Identity, credentials: Credentials, authorization: Authorization)
    {
        self.identity      = identity
        self.credentials   = credentials
        self.authorization = authorization
    }
    
    // MARK: - Experimental
    
    public func isaSubject(_ identity: UUID) -> Bool
    {
        return true // TODO
    }
    
    // MARK: - Profile
    
    /**
     Get profile.
     */
    private func getProfile() -> Any
    {
        var profile = [String : Any]()
        
        profile[KeyIdentity]      = identity.profile
        profile[KeyCredentials]   = credentials.profile
        profile[KeyAuthorization] = authorization.profile
        
        return profile
    }
    
}


// End of File
