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


class ASN1OIDTests: XCTestCase {
    
    func testObjectIdentifier() throws
    {
        let oid  = ASN1OID(components: [ 2, 5, 4, 3 ])
        let data = try DEREncoder().encode(oid)
        
        XCTAssertEqual([UInt8](data), [ 0x06, 0x03, 0x55, 0x04, 0x03 ])
    }
    
}


// End of File

