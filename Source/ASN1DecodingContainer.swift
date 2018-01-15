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
 ASN.1 Decoding Container
 */
public class ASN1DecodingContainer {

    // MARK: - Properties
    public var bytes   : [UInt8] { return container.bytes }
    public var isAtEnd : Bool    { return container.isAtEnd }

    // MARK: - Private
    private let container: DERDecodingContainer

    // MARK: - Initializers

    init(container: DERDecodingContainer)
    {
        self.container = container
    }

    // MARK: - Assertions

    public func assert(_ value: Bool) throws
    {
        if !value {
            throw SecurityKitError.decodingError
        }
    }

    public func assertAtEnd() throws
    {
        try assert(container.isAtEnd)
    }

    // MARK: - Sub-Containers

    public func sequence() throws -> ASN1DecodingContainer
    {
        return ASN1DecodingContainer(container: try container.sequence())
    }

    public func set() throws -> ASN1DecodingContainer
    {
        return ASN1DecodingContainer(container: try container.set())
    }

    public func contextDefinedContainerIfPresent(id: UInt8, primitive: Bool = false) throws -> ASN1DecodingContainer?
    {
        if let container = try self.container.contextDefinedContainerIfPresent(id: id, primitive: primitive) {
            return ASN1DecodingContainer(container: container)
        }
        return nil
    }

    // MARK: - Generic

    public func decode<T: ASN1Decodable>(_ type: T.Type) throws -> T
    {
        return try container.decode(T.self)
    }

    public func decode<T: ASN1Decodable>(_ type: [T].Type) throws -> [T]
    {
        return try container.decode([T].self)
    }


    // MARK: - Primitives

    public func decode(_ type: Bool.Type) throws -> Bool
    {
        return try container.decode(Bool.self)
    }

    public func decodeIfPresent(_ type: Bool.Type) throws -> Bool?
    {
        return try container.decodeIfPresent(Bool.self)
    }

    public func decode(_ type: Int.Type) throws -> Int
    {
        return try container.decode(Int.self)
    }

    public func decodeIfPresent(_ type: Int.Type) throws -> Int?
    {
        return try container.decodeIfPresent(Int.self)
    }

    public func decode(_ type: UInt.Type) throws -> UInt
    {
        return try container.decode(UInt.self)
    }

    public func decodeIfPresent(_ type: UInt.Type) throws -> UInt?
    {
        return try container.decodeIfPresent(UInt.self)
    }

    public func decodeNull() throws -> [UInt8]
    {
        return try container.decodeNull()
    }

    // MARK: - Internal

    public func decode(_ type: ASN1Tag.Type) throws -> ASN1Tag
    {
        return try container.decode(ASN1Tag.self)
    }

    public func decode(_ type: [UInt8].Type) throws -> [UInt8]
    {
        return try container.decode([UInt8].self)
    }

    public func decode(_ type: [UInt8].Type, forTag tag: ASN1Tag) throws -> [UInt8]
    {
        return try container.decode([UInt8].self, forTag: tag)
    }

}


// End of File


