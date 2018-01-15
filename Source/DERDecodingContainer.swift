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
 Encoder for ASN.1 Distinguished Encoding Rules (DER).
 */
public class DERDecodingContainer {

    // MARK: - Properties
    public var bytes   : [UInt8]       { return Array(slice) }
    public var isAtEnd : Bool          { return index == slice.endIndex }
    public var nextTag : ASN1CodingTag? { return peek() }

    // MARK: - Private Properties
    private var slice: ArraySlice<UInt8>
    private var index: Int

    // MARK: - Initializers

    public init(from bytes: ArraySlice<UInt8>, index: Int = 0)
    {
        self.slice = bytes
        self.index = slice.startIndex + index
    }

    public convenience init(from bytes: [UInt8], index: Int = 0)
    {
        self.init(from: ArraySlice(bytes), index: index)
    }

    public convenience init(from data: Data)
    {
        self.init(from: [UInt8](data))
    }

    // MARK: - Assertions

    public func assert(_ value: Bool) throws
    {
        if !value {
            throw SecurityKitError.decodingError
        }
    }

    // MARK: - Generic

    public func decode<T: ASN1Decodable>(_ type: T.Type) throws -> T
    {
        let decoder = DERContainerDecoder(container: self)
        return try T(from: decoder)
    }

    public func decode<T: ASN1Decodable>(_ type: [T].Type) throws -> [T]
    {
        let decoder = DERContainerDecoder(container: self)
        var array   = [T]()

        while !isAtEnd {
            let element = try T(from: decoder)
            array.append(element)
        }

        return array
    }

    // MARK: - Decoding Tags

    public func peek() -> ASN1CodingTag?
    {
        if index < slice.endIndex {
            let value = slice[index]

            if (ASN1ContextDefinedTag.isContextDefined(value: value)) {
                return try? ASN1ContextDefinedTag(value: value)
            }

            return try? ASN1Tag(value: value)
        }
        return nil
    }

    public func peek(_ type: ASN1Tag.Type) -> ASN1Tag?
    {
        return nextTag as? ASN1Tag
    }

    public func peek(_ type: ASN1ContextDefinedTag.Type) -> ASN1ContextDefinedTag?
    {
        return nextTag as? ASN1ContextDefinedTag
    }

    public func peek(with tag: ASN1Tag) -> Bool
    {
        if let value = peek(ASN1Tag.self) {
            return value == tag
        }
        return false
    }

    public func peek(with tag: ASN1ContextDefinedTag) -> Bool
    {
        if let value = peek(ASN1ContextDefinedTag.self) {
            return value == tag
        }
        return false
    }

    public func decode(_ type: ASN1Tag.Type) throws -> ASN1Tag
    {
        let value = try ASN1Tag(value: try getByte())
        return value
    }

    public func decode(_ type: ASN1ContextDefinedTag.Type) throws -> ASN1ContextDefinedTag
    {
        let value = try ASN1ContextDefinedTag(value: try getByte())
        return value
    }

    public func decode(tag: ASN1Tag) throws
    {
        let value = try decode(ASN1Tag.self)
        try self.assert(value == tag)
    }

    public func decode(tag: ASN1ContextDefinedTag) throws
    {
        let value = try decode(ASN1ContextDefinedTag.self)
        try self.assert(value == tag)
    }

    // MARK: - Decoding Content

    func decode(_ type: [UInt8].Type) throws -> [UInt8]
    {
        let length = try decodeLength()
        return try getContent(length)
    }

    public func decode(_ type: [UInt8].Type, forTag tag: ASN1Tag) throws -> [UInt8]
    {
        let value = try decode(ASN1Tag.self)
        try assert(value == tag)

        let length = try decodeLength()
        return try getContent(length)
    }

    public func decode(_ type: [UInt8].Type, forTag tag: ASN1ContextDefinedTag) throws -> [UInt8]
    {
        let value = try decode(ASN1ContextDefinedTag.self)
        try self.assert(value == tag)

        let length = try decodeLength()
        return try getContent(length)
    }

    // MARK: - Primitives

    public func decode(_ type: Bool.Type) throws -> Bool
    {
        let bytes = try decode([UInt8].self, forTag: .boolean)

        try assert(bytes.count == 1)
        try assert(bytes[0] == 0xff || bytes[0] == 0x00)

        return bytes[0] == 0xff
    }

    public func decodeIfPresent(_ type: Bool.Type) throws -> Bool?
    {
        if peek(with: .boolean) {
            return try decode(Bool.self)
        }
        return nil
    }

    public func decode(_ type: Int.Type) throws -> Int
    {
        let bytes = try decode([UInt8].self, forTag: .integer)
        return decode(Int.self, from: bytes)
    }

    public func decodeIfPresent(_ type: Int.Type) throws -> Int?
    {
        if peek(with: .integer) {
            return try decode(Int.self)
        }
        return nil
    }

    public func decode(_ type: UInt.Type) throws -> UInt
    {
        let bytes = try decode([UInt8].self, forTag: .integer)
        return decode(UInt.self, from: bytes)
    }

    public func decodeIfPresent(_ type: UInt.Type) throws -> UInt?
    {
        if peek(with: .integer) {
            return try decode(UInt.self)
        }
        return nil
    }

    public func decodeNull() throws -> [UInt8]
    {
        let bytes = try decode([UInt8].self, forTag: .null)

        try assert(bytes.count == 0)
        return bytes
    }

    // MARK: - Containers

    public func sequence() throws -> DERDecodingContainer
    {
        return try container(forTag: .sequence)
    }

    public func set() throws -> DERDecodingContainer
    {
        return try container(forTag: .set)
    }

    public func container(forTag tag: ASN1Tag) throws -> DERDecodingContainer
    {
        let start = index

        try decode(tag: tag)
        let length = try decodeLength()
        let data   = index
        try advance(count: length)

        return DERDecodingContainer(from: slice[start..<index], index: data - start)
    }

    public func containerIfPresent(forTag tag: ASN1Tag) throws -> DERDecodingContainer?
    {
        if peek(with: tag) {
            return try container(forTag: tag)
        }
        return nil
    }

    public func container(forTag tag: ASN1ContextDefinedTag) throws -> DERDecodingContainer
    {
        let start = index

        try decode(tag: tag)
        let length = try decodeLength()
        let data   = index
        try advance(count: length)

        return DERDecodingContainer(from: slice[start..<index], index: data - start)
    }

    public func containerIfPresent(forTag tag: ASN1ContextDefinedTag) throws -> DERDecodingContainer?
    {
        if peek(with: tag) {
            return try container(forTag: tag)
        }
        return nil
    }

    public func contextDefinedContainerIfPresent(id: UInt8, primitive: Bool = false) throws -> DERDecodingContainer?
    {
        let tag = ASN1ContextDefinedTag(id: id, primitive: primitive)

        if peek(with: tag) {
            return try container(forTag: tag)
        }
        return nil
    }

    // MARK: - Private

    private func decode(_ type: Int.Type, from bytes: [UInt8]) -> Int
    {
        var value = Int(0)
        var sign  = Int(1)

        if !bytes.isEmpty {
            var first = bytes[0]

            if (first & 0x80) == 0x80 {
                first ^= 0x80
                sign   = -1;
            }
            value = Int(first)

            for byte in bytes[1..<bytes.count] {
                value = (value << 8) + Int(UInt(byte))
            }

            value *= sign
        }

        return value
    }

    private func decode(_ type: UInt.Type, from bytes: [UInt8]) -> UInt
    {
        var value = UInt(0)

        for byte in bytes {
            value = (value << 8) + UInt(byte)
        }
        return value
    }

    private func decodeLength() throws -> Int
    {
        var byte   = try getByte()
        var length : Int

        try assert(byte != 0x80)

        if byte < 0x80 {
            length = Int(byte)
        }
        else {
            let count = byte & 0x7f

            // TODO
            length = 0
            for _ in 0..<count {
                byte   = try getByte()
                length = (length << 8) + Int(byte)
            }
        }

        return length
    }

    private func getByte() throws -> UInt8
    {
        if index < slice.endIndex {
            let byte = slice[index]

            index += 1
            return byte
        }

        throw SecurityKitError.decodingError
    }

    private func advance(count: Int) throws
    {
        let end = index + count

        try assert(end <= slice.endIndex)
        index = end
    }

    private func getContent(_ count: Int) throws -> [UInt8]
    {
        let end = index + count

        if end <= slice.endIndex {
            let content = [UInt8](slice[index..<end])

            index += count

            return content
        }

        throw SecurityKitError.decodingError
    }

}


// End of File

