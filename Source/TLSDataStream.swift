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
 TLS Data Stream Protocol
 */
public protocol TLSDataStream: class {

    /**
     Read data.

     - Invariant:
         (error == nil) ⇒ (data != nil)
     */
    func tlsRead(_ context: TLS, _ count: Int) -> (data: Data?, error: Error?)

    /**
     Write data.

     - Invariant:
         (error == nil) ⇒ (count != nil)
     */
    func tlsWrite(_ context: TLS, _ data: Data) -> (count: Int?, error: Error?)

}


// End of File
