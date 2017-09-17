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


public enum TLSMode {
    case client
    case server
}

public enum TLSState {
    case idle
    case connected
    case closed
    case handshake
    case aborted
}

public protocol TLS {

    // MARK: - Properties
    weak var delegate  : TLSDelegate?     { get set }
    var      state     : TLSState         { get }
    weak var stream    : TLSDataStream?   { get set }

    // MARK: - State Management
    func close() -> Error?
    func handshake() -> Error?

    // MARK: - I/O
    func read(_ data: inout Data, _ dataLength: inout Int) -> Error?
    func write(_ data: Data, _ dataLength: inout Int) -> Error?

}


// End of File

