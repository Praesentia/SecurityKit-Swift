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
public class DEREncodingContainer {

    // MARK: - Internal Properties
    internal(set) var bytes     = [UInt8]()
    internal(set) var container : DEREncodingContainer!
    internal(set) var frozen    : Bool = false

    // MARK: - Initializers

    init()
    {
    }

    // MARK: - Assertions

    public func assert(_ value: Bool) throws
    {
        if !value {
            throw SecurityKitError.decodingError
        }
    }

    // MARK: - Containers

    public func sequence() throws -> DEREncodingContainer
    {
        try assert(!frozen)
        return try container(forTag: ASN1Tag.sequence)
    }

    public func set() throws -> DEREncodingContainer
    {
        try assert(!frozen)
        return try container(forTag: ASN1Tag.set)
    }

    public func contextDefinedContainer(id: UInt8, primitive: Bool = false) throws -> DEREncodingContainer
    {
        try assert(!frozen)
        return try container(forTag: ASN1ContextDefinedTag(id: id, primitive: primitive))
    }

    private func container(forTag tag: ASN1CodingTag) throws -> DEREncodingContainer
    {
        try assert(!frozen)
        finalizeContainer()

        container = DERTaggedEncodingContainer(forTag: tag)
        return container
    }

    // MARK: - Generic

    public func encode<T: ASN1Encodable>(_ encodable: T) throws
    {
        try assert(!frozen)
        let encoder = DERContainerEncoder(container: self)
        try encodable.encode(to: encoder)
    }

    public func encode<T: ASN1Encodable>(_ encodable: T?) throws
    {
        try assert(!frozen)
        let encoder = DERContainerEncoder(container: self)
        try encodable?.encode(to: encoder)
    }

    public func encode<T: ASN1Encodable>(_ array: [T]) throws
    {
        try assert(!frozen)
        let encoder = DERContainerEncoder(container: self)

        for element in array {
            try element.encode(to: encoder)
        }
    }

    // MARK: - Primitives

    public func encode(_ value: Bool) throws
    {
        try assert(!frozen)
        let bytes: [UInt8] = value ? [ 0xff ] : [ 0x00 ]

        try encode(bytes, forTag: .boolean)
    }

    public func encode(_ value: Bool?) throws
    {
        try assert(!frozen)
        if let value = value {
            try encode(value)
        }
    }

    public func encode(_ value: Int) throws
    {
        try assert(!frozen)
        var bytes = [UInt8]()
        var n     = value

        bytes.append(UInt8(n & 0xff)) // TODO: sign

        while n > 0xff {
            n = n >> 8
            bytes.append(UInt8(n & 0xff))
        }

        try encode(bytes, forTag: .integer)
    }

    public func encode(_ value: Int?) throws
    {
        try assert(!frozen)
        if let value = value {
            try encode(value)
        }
    }

    public func encode(_ value: UInt) throws
    {
        try assert(!frozen)
        var bytes = [UInt8]()
        var n     = value

        bytes.append(UInt8(n & 0xff))

        while n > 0xff {
            n = n >> 8
            bytes.append(UInt8(n & 0xff))
        }

        try encode(ASN1UnsignedInteger(bytes: bytes.reversed()))
    }

    public func encode(_ value: UInt?) throws
    {
        try assert(!frozen)
        if let value = value {
            try encode(value)
        }
    }

    public func encodeNull() throws
    {
        try assert(!frozen)
        let empty = [UInt8]()
        try encode(empty, forTag: .null)
    }

    // MARK: - Encoding Content

    public func encode(_ bytes: [UInt8]) throws
    {
        finalizeContainer()
        self.bytes += bytes
    }

    public func encode(_ bytes: [UInt8], forTag tag: ASN1Tag) throws
    {
        finalizeContainer()

        self.bytes += tag.value
        self.bytes += encodeLength(bytes.count)
        self.bytes += bytes
    }

    public func encode(_ bytes: [UInt8]?, forTag tag: ASN1Tag) throws
    {
        if let bytes = bytes {
            try encode(bytes, forTag: tag)
        }
    }

    public func encode(_ bytes: [UInt8], forTag tag: ASN1ContextDefinedTag) throws
    {
        finalizeContainer()

        self.bytes += tag.value
        self.bytes += encodeLength(bytes.count)
        self.bytes += bytes
    }

    public func encode(_ bytes: [UInt8]?, forTag tag: ASN1ContextDefinedTag) throws
    {
        if let bytes = bytes {
            try encode(bytes, forTag: tag)
        }
    }

    // MARK: - DEREncodingFragment

    func freeze() -> [UInt8]
    {
        finalizeContainer()
        frozen = true
        return bytes
    }

    // MARK: - Internal

    func finalizeContainer()
    {
        if let container = self.container {
            bytes += container.freeze()
            self.container = nil
        }
    }

    func encodeLength(_ length: Int) -> [UInt8]
    {
        Swift.assert(length < 0x8000)

        var bytes = [UInt8]()

        if length < 0x80 {
            bytes += [UInt8(length)]
            return bytes
        }

        if length < 0x100 {
            bytes += [0x81, UInt8(length & 0xff)]
            return bytes
        }

        bytes += [0x82, UInt8(length >> 8 & 0xff), UInt8(length & 0xff)]
        return bytes
    }

}


// End of File

