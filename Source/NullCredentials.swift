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
 Null credentials.
 */
public class NullCredentials: Credentials {
    
    // MARK: - Class Properties
    public static let shared = NullCredentials()

    // MARK: - Properties
    public let identity : Identity?          = nil
    public var type     : CredentialsType    { return .null }
    public let validity : ClosedRange<Date>? = nil
    
    // MARK: - Private
    
    private enum CodingKeys: CodingKey {
        case type
    }
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    private init()
    {
    }
    
    // MAKR: - Codable
    
    required public init(from decoder: Decoder) throws
    {
    }
    
    public func encode(to encoder: Encoder) throws
    {
    }
    
    // MARK: - Authentication
    
    public func verifyTrust(completionHandler completion: @escaping (Error?) -> Void)
    {
        completion(SecurityKitError.badCredentials)
    }
    
    // MARK: - Signing
    
    /**
     Sign bytes.
     
     Always fails.
     
     - Parameters:
        - bytes: The bytes being signed.  This will typically be a hash value
                 of the actual data.
     */
    public func sign(data: Data, using digestType: DigestType) -> Data?
    {
        return nil
    }
    
    /**
     Verify signature.
     
     Always fails.
     
     - Parameters:
        - bytes: The bytes that were originally signed.  This will typically be
                a hash value of the actual data.
     */
    public func verify(signature: Data, for data: Data, using digestType: DigestType) -> Bool
    {
        return false
    }
    
}


// End of File
