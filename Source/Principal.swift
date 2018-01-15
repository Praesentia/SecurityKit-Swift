/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2016-2018 Jon Griffeth
 
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
public class Principal: Codable {
    
    // MARK: - Properties
    public let authorization : Authorization
    public let credentials   : Credentials
    public let identity      : Identity

    // MARK: - Private

    private enum CodingKeys: CodingKey {
        case authorization
        case credentials
        case identity
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

    // MARK: - Codable

    required public init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        authorization = try container.decode(AuthorizationCoder.self, forKey: .authorization).authorization
        credentials   = try container.decode(CredentialsCoder.self,   forKey: .credentials).credentials
        identity      = try container.decode(Identity.self,           forKey: .identity)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(AuthorizationCoder(authorization), forKey: .authorization)
        try container.encode(CredentialsCoder(credentials),     forKey: .credentials)
        try container.encode(identity,                          forKey: .identity)
    }
    
}


// End of File
