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
public struct AuthorizationCoder: Codable {

    // MARK: - Public
    public let authorization: Authorization

    // MARK: - Private

    private enum CodingKeys: CodingKey {
        case type
        case authorization
    }

    // MARK - Initializers

    public init(_ authorization: Authorization)
    {
        self.authorization = authorization
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws
    {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type      = try container.decode(AuthorizationType.self, forKey: .type)

        switch type {
        case .null :
            authorization = try container.decode(NullAuthorization.self, forKey: .authorization)
        }
    }

    public func encode(to encoder: Encoder) throws
    {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(authorization.type, forKey: .type)
        try container.encode(ConcreteEncodable(authorization), forKey: .authorization)
    }

}


// End of File


