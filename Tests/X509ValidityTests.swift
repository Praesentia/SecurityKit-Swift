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


class X509ValidityTests: XCTestCase {
    
    static let interval = TimeInterval(1)
    static let now      = Date()
    static let until    = now.addingTimeInterval(interval)
    
    func testInitializers()
    {
        let validityPeriod   = X509Validity(period: X509ValidityTests.now ... X509ValidityTests.until)
        let validityInterval = X509Validity(from: X509ValidityTests.now, until: X509ValidityTests.interval)
        
        XCTAssert(validityPeriod.period.lowerBound == X509ValidityTests.now)
        XCTAssert(validityPeriod.period.upperBound == X509ValidityTests.until)
        
        XCTAssert(validityInterval.period.lowerBound == X509ValidityTests.now)
        XCTAssert(validityInterval.period.upperBound == X509ValidityTests.until)
    }
    
}


// End of File
