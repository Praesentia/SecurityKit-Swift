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


public class ASN1ContextDefinedTag: ASN1CodingTag {

    public private(set) var value: UInt8

    private static let contextDefined : UInt8 = 0x80
    private static let constructed    : UInt8 = 0x20

    public class func isContextDefined(value: UInt8) -> Bool
    {
        return (value & ASN1ContextDefinedTag.contextDefined) != 0
    }

    public init(value: UInt8) throws
    {
        if !ASN1ContextDefinedTag.isContextDefined(value: value) {
            throw SecurityKitError.failed
        }
        self.value = value
    }

    public init(id: UInt8, primitive: Bool = false)
    {
        if primitive {
            value = ASN1ContextDefinedTag.contextDefined | id
        }
        else {
            value = ASN1ContextDefinedTag.contextDefined | ASN1ContextDefinedTag.constructed | id
        }
    }

    public static func ==(_ lhs: ASN1ContextDefinedTag, _ rhs: ASN1ContextDefinedTag) -> Bool
    {
        return lhs.value == rhs.value
    }

}


// End of File

