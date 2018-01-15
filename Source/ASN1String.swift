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
public struct ASN1String: ASN1Codable, Equatable {

    public enum Encoding {
        case ia5
        case printable
        case utf8
    }

    // MARK: - Properties
    public let string   : String
    public let encoding : Encoding

    // MARK: - Initializers

    public init(string: String, encoding: Encoding = .utf8)
    {
        self.string   = string
        self.encoding = encoding
    }

    // MARK: - ASN1Codable

    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let tag       = try container.decode(ASN1Tag.self)

        switch tag {
        case .ia5String :
            encoding = .ia5

        case .printableString :
            encoding = .printable

        case .utf8String :
            encoding = .utf8

        default :
            throw SecurityKitError.decodingError
        }

        let bytes = try container.decode([UInt8].self)
        string    = ASN1String.transcode(bytes: bytes, encoding: encoding)
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        let bytes     = ASN1String.transcode(string: string, encoding: encoding)

        switch encoding {
        case .ia5 :
            try container.encode(bytes, forTag: .ia5String)

        case .printable :
            try container.encode(bytes, forTag: .printableString)

        case .utf8 :
            try container.encode(bytes, forTag: .utf8String)
        }
    }

    // MARK: - Equatable

    public static func ==(lhs: ASN1String, rhs: ASN1String) -> Bool
    {
        return lhs.string == rhs.string
    }

    // MARK: - Transcoders

    private static func transcode(bytes: [UInt8], encoding: ASN1String.Encoding) -> String
    {
        switch encoding {
        case .ia5 :
            return String(bytes: bytes, encoding: .ascii)!

        case .printable :
            return String(bytes: bytes, encoding: .ascii)!

        case .utf8 :
            return String(bytes: bytes, encoding: .utf8)!
        }
    }

    private static func transcode(string: String, encoding: ASN1String.Encoding) -> [UInt8]
    {
        switch encoding {
        case .ia5 :
            return string.unicodeScalars.map { UInt8($0.value) }

        case .printable :
            return string.unicodeScalars.map { UInt8($0.value) }

        case .utf8 :
            return [UInt8](string.utf8)
        }
    }

}


// End of File


