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


import SecurityKit
import XCTest


let testIdentity  = Identity(named: "TestUser", type: .user)
let testName      = X509Name(from: testIdentity)

// URL of Test Files
let testCACERURL  = Bundle.tests.url(forResource: "TestCA", ofType: "cer")!
let testCSRURL    = Bundle.tests.url(forResource: "Test",   ofType: "csr")!
let testCERURL    = Bundle.tests.url(forResource: "Test",   ofType: "cer")!


// End of File

