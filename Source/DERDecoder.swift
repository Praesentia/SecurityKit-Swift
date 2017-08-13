/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2017 Jon Griffeth
 
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
 ASN.1 Distinguished Encoding Rules (DER) decoder.
 */
public class DERDecoder: DERCoder {
    
    // MARK: - Properties
    public var bytes   : [UInt8] { return Array(slice) }
    public var more    : Bool    { return index < slice.endIndex }
    public var atEnd   : Bool    { return index == slice.endIndex }
    public var nextTag : UInt8?  { return peekTag() }
    
    // MARK: - Private Properties
    private var slice: ArraySlice<UInt8>
    private var index: Int
    
    // MARK: - Initializers
    
    public init(bytes: ArraySlice<UInt8>, index: Int = 0)
    {
        self.slice = bytes
        self.index = slice.startIndex + index
    }
    
    public convenience init(bytes: [UInt8], index: Int = 0)
    {
        self.init(bytes: ArraySlice(bytes), index: index)
    }
    
    public convenience init(data: Data)
    {
        self.init(bytes: [UInt8](data))
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
        try assert(atEnd)
    }
    
    // MARK: - Peek
    
    public func peekTag() -> UInt8?
    {
        if index < slice.endIndex {
            return slice[index]
        }
        return nil
    }
    
    public func peekTag(with value: UInt8) -> Bool
    {
        if let tag = nextTag {
            return tag == value
        }
        
        return false
    }
    
    public func peekContextDefinedTag(id: UInt8, primitive: Bool = false) -> Bool
    {
        if let tag = nextTag {
            return tag == DERCoder.makeContextDefinedTag(id: id, primitive: primitive)
        }
        
        return false
    }
    
    // MARK: - Basic
    
    public func decode(with: UInt8) throws -> [UInt8]
    {
        let tag = try decodeTag()
        try assert(tag == with)
        
        let length = try decodeLength()
        return try getContent(length)
    }
    
    public func decodeContextDefinedTag(id: UInt8, primitive: Bool = false) throws -> [UInt8]
    {
        let tag = try decodeTag()
        try assert(tag == DERCoder.makeContextDefinedTag(id: id, primitive: primitive))
        
        let length = try decodeLength()
        return try getContent(length)
    }
    
    // MARK: - Primitives

    public func decodeBoolean() throws -> Bool
    {
        let bytes = try decode(with: DERCoder.TagBoolean)
        
        try assert(bytes.count == 1)
        try assert(bytes[0] == 0xff || bytes[0] == 0x00)
        
        return bytes[0] == 0xff
    }
    
    // TODO: Assumes all bits used.
    //
    public func decodeBitString(unused: UInt8 = 0) throws -> [UInt8]
    {
        let bytes = try decode(with: DERCoder.TagBitString)

        return [UInt8](bytes[1..<bytes.count])
    }

    public func decodeInteger() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagInteger)
    }

    public func decodeIntegerAsValue() throws -> Int
    {
        let bytes = try decode(with: DERCoder.TagInteger)
        return decodeInteger(bytes: bytes)
    }
    
    public func decodeUnsignedInteger() throws -> [UInt8]
    {
        let bytes = try decode(with: DERCoder.TagInteger)
        
        if bytes[0] == 0x00 && bytes.count > 1 {
            return Array(bytes[1..<bytes.count])
        }
        return bytes
    }
    
    public func decodeUnsignedIntegerAsValue() throws -> UInt
    {
        let bytes = try decode(with: DERCoder.TagInteger)
        return decodeUnsignedInteger(bytes: bytes)
    }
    
    public func decodeNull() throws -> [UInt8]
    {
        let bytes = try decode(with: DERCoder.TagNull)
        
        try assert(bytes.count == 0)
        return bytes
    }
    
    public func decodeOctetString() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagOctetString)
    }
    
    // MARK: - Decoders
    
    public func decoderFromOctetString() throws -> DERDecoder
    {
        return try decoderFromTag(with: DERCoder.TagOctetString)
    }
    
    public func decoderFromSequence() throws -> DERDecoder
    {
        return try decoderFromTag(with: DERCoder.TagSequence)
    }
    
    public func decoderFromSet() throws -> DERDecoder
    {
        return try decoderFromTag(with: DERCoder.TagSet)
    }
    
    public func decoderFromTag(with: UInt8) throws -> DERDecoder
    {
        let start = index
        let tag   = try decodeTag()
        
        try assert(tag == with)
        
        let length = try decodeLength()
        let data   = index
        try advance(count: length)
        
        return DERDecoder(bytes: slice[start..<index], index: data - start)
    }
    
    public func decoderFromContextDefinedTag(id: UInt8, primitive: Bool = false) throws -> DERDecoder
    {
        return try decoderFromTag(with: DERCoder.makeContextDefinedTag(id: id, primitive: primitive))
    }
    
    // MARK: - Collections
    
    public func decodeSequence() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagSequence)
    }
    
    public func decodeSet() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagSet)
    }
    
    // MARK: - Strings
    
    func decodeIA5String() throws -> String
    {
        let bytes = try decode(with: DERCoder.TagIA5String)
        
        if let string = String(bytes: bytes, encoding: .ascii) { // TODO
            return string
        }
        
        throw SecurityKitError.decodingError
    }
    
    func decodeIA5String() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagIA5String)
    }
    
    public func decodePrintableString() throws -> String
    {
        let bytes = try decode(with: DERCoder.TagPrintableString)
        
        if let string = String(bytes: bytes, encoding: .ascii) {
            return string
        }
        
        throw SecurityKitError.decodingError
    }
    
    public func decodePrintableString() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagPrintableString)
    }
    
    func decodeUTF8String() throws -> String
    {
        let bytes = try decode(with: DERCoder.TagUTF8String)
        
        if let string = String(bytes: bytes, encoding: .utf8) {
            return string
        }

        throw SecurityKitError.decodingError
    }
    
    func decodeUTF8String() throws -> [UInt8]
    {
        return try decode(with: DERCoder.TagUTF8String)
    }
    
    // MARK: - Time
    
    public func decodeUTCTime() throws -> Date
    {
        let bytes = try decode(with: DERCoder.TagUTCTime)
        
        if let string = String(bytes: bytes, encoding: .ascii) {
            if let date = DERCoder.dateFormatterUTC.date(from: string) {
                return date
            }
        }
        
        throw SecurityKitError.decodingError
    }
    
    func decodeUniversalTime() throws -> Date
    {
        let bytes = try decode(with: DERCoder.TagUTCTime)
        
        if let string = String(bytes: bytes, encoding: .ascii) {
            if let date = DERCoder.dateFormatterUniversal.date(from: string) {
                return date
            }
        }
        
        throw SecurityKitError.decodingError
    }
    
    // MARK: - Private
    
    private func decodeTag() throws -> UInt8
    {
        return try getByte()
    }
    
    private func decodeInteger(bytes: [UInt8]) -> Int
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
    
    private func decodeUnsignedInteger(bytes: [UInt8]) -> UInt
    {
        var value = UInt(0)
        
        for byte in bytes {
            value = (value << 8) + UInt(byte)
        }
        return value
    }
    
    private func decodeLength() throws -> Int
    {
        var byte = try getByte()
        
        if byte != 0x80 {
            
            if byte < 0x80 {
                return Int(byte)
            }
            
            var length = 0
            let count  = byte & 0x7f
            
            // TODO
            for _ in 0..<count {
                byte   = try getByte()
                length = (length << 8) + Int(byte)
            }
            
            return length
        }
        
        throw SecurityKitError.decodingError
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
