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


import XCTest
@testable import SecurityKit


class ASN1StringTests: XCTestCase {
    
    func testInitializers()
    {
        let stringIA5       = ASN1String(string: "Foo", encoding: .ia5)
        let stringPrintable = ASN1String(string: "Foo", encoding: .printable)
        let stringUTF8      = ASN1String(string: "Foo", encoding: .utf8)
        
        XCTAssert(stringIA5.string   == "Foo")
        XCTAssert(stringIA5.encoding == .ia5)
        
        XCTAssert(stringPrintable.string   == "Foo")
        XCTAssert(stringPrintable.encoding == .printable)
        
        XCTAssert(stringUTF8.string   == "Foo")
        XCTAssert(stringUTF8.encoding == .utf8)
    }
    
}


// End of File
