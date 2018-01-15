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
 */
public struct CredentialsCoder: Codable {

    // MARK: - Public
    public let credentials: Credentials

    // MARK: - Private
    private enum CodingKeys: CodingKey {
        case type
        case credentials
    }

    // MARK - Initializers

    public init(_ credentials: Credentials)
    {
        self.credentials = credentials
    }

    public init?(_ credentials: Credentials?)
    {
        if let credentials = credentials {
            self.credentials = credentials
        }
        else {
            return nil
        }
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws
    {
        credentials = try SecurityManagerShared.main.decodeCredentials(from: decoder)
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(credentials.type,               forKey: .type)
        try container.encode(ConcreteEncodable(credentials), forKey: .credentials)
    }

}


// End of File

