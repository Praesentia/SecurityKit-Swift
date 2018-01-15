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
public struct ASN1Time: ASN1Codable {

    public enum Encoding {
        case univerisal
        case utc
    }

    // MARK: - Properties

    public let time     : Date
    public let encoding : Encoding

    // MARK: - Date/Time Formatter
    private static let dateFormatterUTC       = DateFormatter(dateFormat: "yyMMddHHmmss'Z'",   timeZone: TimeZone(abbreviation: "UTC")!)
    private static let dateFormatterUniversal = DateFormatter(dateFormat: "yyyyMMddHHmmss'Z'", timeZone: TimeZone(abbreviation: "UTC")!)

    // MARK: - Initializers

    public init(time: Date, encoding: Encoding = .utc)
    {
        self.time     = time
        self.encoding = encoding
    }

    // MARK: - ASN1Codable

    public init(from decoder: ASN1Decoder) throws
    {
        let container = try decoder.container()
        let tag       = try container.decode(ASN1Tag.self)

        switch tag {
        case .utcTime :
            encoding = .utc

        default :
            throw SecurityKitError.decodingError
        }

        let bytes  = try container.decode([UInt8].self)
        let string = String(bytes: bytes, encoding: .ascii)!

        time = ASN1Time.dateFormatterUTC.date(from: string)!
    }

    public func encode(to encoder: ASN1Encoder) throws
    {
        let container = try encoder.container()
        let string    = ASN1Time.dateFormatterUTC.string(from: time)
        let bytes     = string.unicodeScalars.map { UInt8($0.value) }

        try container.encode(bytes, forTag: .utcTime)
    }

}


// End of File



