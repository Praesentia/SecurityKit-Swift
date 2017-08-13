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


import XCTest
@testable import SecurityKit


class DEREncoderTests: XCTestCase {
    
    func testSequence()
    {
        let encoder = DEREncoder()
        
        encoder.encodeSequence(bytes: [ 1, 2, 3 ])
        
        XCTAssertEqual(encoder.bytes, [ 0x30, 0x03, 0x01, 0x02, 0x03 ])
    }
    
}


// End of File
