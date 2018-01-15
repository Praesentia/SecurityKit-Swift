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
 ASN.1 Encoding Container
 */
public class ASN1EncodingContainer {

    // MARK: - Private
    private let container: DEREncodingContainer

    // MARK: - Initializers

    init(container: DEREncodingContainer)
    {
        self.container = container
    }

    // MARK: - Sub-Containers

    public func sequence() throws -> ASN1EncodingContainer
    {
        return ASN1EncodingContainer(container: try container.sequence())
    }

    public func set() throws -> ASN1EncodingContainer
    {
        return ASN1EncodingContainer(container: try container.set())
    }

    public func contextDefinedContainer(id: UInt8, primitive: Bool = false) throws -> ASN1EncodingContainer
    {
        return ASN1EncodingContainer(container: try container.contextDefinedContainer(id: id, primitive: primitive))
    }

    // MARK: - Generic

    public func encode<T: ASN1Encodable>(_ encodable: T) throws
    {
        try container.encode(encodable)
    }

    public func encode<T: ASN1Encodable>(_ encodable: T?) throws
    {
        try container.encode(encodable)
    }

    public func encode<T: ASN1Encodable>(_ encodable: [T]) throws
    {
        try container.encode(encodable)
    }

    // MARK: - Primitives

    public func encode(_ encodable: Bool) throws
    {
        try container.encode(encodable)
    }

    public func encode(_ encodable: Bool?) throws
    {
        try container.encode(encodable)
    }

    public func encode(_ encodable: Int) throws
    {
        try container.encode(encodable)
    }

    public func encode(_ encodable: Int?) throws
    {
        try container.encode(encodable)
    }

    public func encode(_ encodable: UInt) throws
    {
        try container.encode(encodable)
    }

    public func encode(_ encodable: UInt?) throws
    {
        try container.encode(encodable)
    }

    public func encodeNull() throws
    {
        try container.encodeNull()
    }

    // MARK: - Internal

    public func encode(_ bytes: [UInt8]) throws
    {
        try container.encode(bytes)
    }

    public func encode(_ bytes: [UInt8], forTag tag: ASN1Tag) throws
    {
        try container.encode(bytes, forTag: tag)
    }

}


// End of File


