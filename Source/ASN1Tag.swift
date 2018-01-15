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


public enum ASN1Tag: UInt8, ASN1CodingTag {
    case boolean          = 0x01
    case integer          = 0x02
    case bitString        = 0x03
    case octetString      = 0x04
    case null             = 0x05
    case objectIdentifier = 0x06
    case objectDescriptor = 0x07
    case objectReal       = 0x09
    case enumerated       = 0x0a
    case utf8String       = 0x0c
    case printableString  = 0x13
    case teletexString    = 0x14
    case videotexString   = 0x15
    case ia5String        = 0x16
    case utcTime          = 0x17
    case sequence         = 0x30
    case set              = 0x31

    public var value: UInt8 { return rawValue }

    public init(value: UInt8) throws
    {
        if let tag = ASN1Tag(rawValue: value) {
            self = tag
        }
        else {
            throw SecurityKitError.failed
        }
    }
}

public extension ASN1Tag {

    public static func ==(_ lhs: ASN1Tag, _ rhs: ASN1Tag) -> Bool
    {
        return lhs.value == rhs.value
    }

}


// End of File

