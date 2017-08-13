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
 ASN.1 Distinguished Encoding Rules (DER) encoder.
 */
public class DEREncoder: DERCoder {
    
    // MARK: - Properties
    public var bytes   : [UInt8] { return buffer }
    public var data    : Data    { return Data(buffer) }
    public var isEmpty : Bool    { return bytes.isEmpty }
    
    // MARK: - Private Properties
    private var buffer = [UInt8]()
    
    // MARK: - DERCodable
    
    public func encode(_ codable: DERCodable)
    {
        codable.encode(encoder: self)
    }
    
    public func encode(_ codable: DERCodable?)
    {
        if let codable = codable {
            codable.encode(encoder: self)
        }
    }
    
    // MARK: - Basic
    
    public func encode(bytes: [UInt8])
    {
        buffer += bytes
    }
    
    public func encodeTag(tag: UInt8, bytes: [UInt8])
    {
        buffer += tag
        encodeLength(bytes.count)
        buffer += bytes
    }
    
    public func encodeContextDefinedTag(id: UInt8, primitive: Bool = false, bytes: [UInt8]?)
    {
        if let bytes = bytes {
            let tag = DERCoder.makeContextDefinedTag(id: id, primitive: primitive)
            encodeTag(tag: tag, bytes: bytes)
        }
    }
    
    // MARK: - Primitives
    
    public func encodeBoolean(_ value: Bool)
    {
        let bytes: [UInt8] = value ? [ 0xff ] : [ 0x00 ]
        
        encodeTag(tag: DERCoder.TagBoolean, bytes: bytes)
    }
    
    /**
     */
    public func encodeBitString(bytes: [UInt8], unused: UInt8 = 0)
    {
        encodeTag(tag: DERCoder.TagBitString, bytes: [unused] + bytes)
    }
    
    public func encodeInteger(bytes: [UInt8])
    {
        encodeTag(tag: DERCoder.TagInteger, bytes: bytes)
    }
    
    public func encodeInteger(_ value: Int)
    {
        var bytes = [UInt8]()
        var n     = value
        
        bytes.append(UInt8(n & 0xff)) // TODO: sign
        
        while n > 0xff {
            n = n >> 8
            bytes.append(UInt8(n & 0xff))
        }
        
        encodeTag(tag: DERCoder.TagInteger, bytes: bytes)
    }
    
    public func encodeUnsignedInteger(_ value: UInt)
    {
        var bytes = [UInt8]()
        var n     = value
        
        bytes.append(UInt8(n & 0xff))
        
        while n > 0xff {
            n = n >> 8
            bytes.append(UInt8(n & 0xff))
        }
        
        encodeUnsignedInteger(bytes: bytes.reversed())
    }
    
    public func encodeUnsignedInteger(bytes: [UInt8])
    {
        if (bytes[0] & 0x80) == 0x80 {
            encodeInteger(bytes: [0] + bytes)
        }
        else {
            encodeInteger(bytes: bytes)
        }
    }

    public func encodeOctetString(bytes: [UInt8])
    {
        encodeTag(tag: DERCoder.TagOctetString, bytes: bytes)
    }
    
    public func encodeNull()
    {
        encodeTag(tag: DERCoder.TagNull, bytes: [])
    }
    
    // MARK: - Collections
    
    public func encodeSequence(bytes: [UInt8])
    {
        encodeTag(tag: DERCoder.TagSequence, bytes: bytes)
    }
    
    public func encodeSet(bytes: [UInt8])
    {
        encodeTag(tag: DERCoder.TagSet, bytes: bytes)
    }
    
    // MARK: - Strings
    
    public func encodeIA5String(_ value: String)
    {
        let characters : [UInt8] = value.unicodeScalars.map { UInt8($0.value) }

        encodeTag(tag: DERCoder.TagIA5String, bytes: characters)
    }
    
    public func encodeIA5String(_ value: [UInt8])
    {
        encodeTag(tag: DERCoder.TagIA5String, bytes: value)
    }
    
    public func encodePrintableString(_ value: String)
    {
        let characters : [UInt8] = value.unicodeScalars.map { UInt8($0.value) }
        
        encodeTag(tag: DERCoder.TagPrintableString, bytes: characters)
    }
    
    public func encodePrintableString(_ value: [UInt8])
    {
        encodeTag(tag: DERCoder.TagPrintableString, bytes: value)
    }
    
    public func encodeUTF8String(_ value: String)
    {
        encodeTag(tag: DERCoder.TagUTF8String, bytes: [UInt8](value.utf8))
    }
    
    public func encodeUTF8String(_ value: [UInt8])
    {
        encodeTag(tag: DERCoder.TagUTF8String, bytes: value)
    }
    
    // MARK: - Time
    
    public func encodeUTCTime(_ date: Date)
    {
        let utcString = DERCoder.dateFormatterUTC.string(from: date)
        let utc       = utcString.unicodeScalars.map { UInt8($0.value) }
        
        encodeTag(tag: DERCoder.TagUTCTime, bytes: utc)
    }
    
    public func encodeUniversalTime(_ date: Date)
    {
        let utcString = DERCoder.dateFormatterUniversal.string(from: date)
        let utc       = utcString.unicodeScalars.map { UInt8($0.value) }
        
        encodeTag(tag: DERCoder.TagUTCTime, bytes: utc)
    }
    
    // MARK: - Private
    
    private func encodeLength(_ length: Int)
    {
        Swift.assert(length < 0x8000)
        
        if length < 0x80 {
            buffer += [UInt8(length)]
            return
        }
        
        if length < 0x100 {
            buffer += [0x81, UInt8(length & 0xff)]
            return
        }
        
        buffer += [0x82, UInt8(length >> 8 & 0xff), UInt8(length & 0xff)]
    }
}


// End of File
