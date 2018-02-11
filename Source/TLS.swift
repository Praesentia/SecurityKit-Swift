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
 TLS Mode
 */
public enum TLSMode {
    case client
    case server
}

/**
 TLS Session State
 */
public enum TLSState {
    case idle
    case connected
    case closed
    case handshake
    case aborted
}

/**
 Transport Layer Security (TLS) Protocol

 A protocol that provides access to a TLS context.
 */
public protocol TLS: class {

    // MARK: - Properties
    var delegate  : TLSDelegate?     { get set }
    var mode      : TLSMode          { get }
    var state     : TLSState         { get }
    var stream    : TLSDataStream?   { get set }

    // MARK: - State Management

    /**
     Handshake
     */
    func handshake() -> Error?

    /**
     Shutdown session.
     */
    func shutdown() -> Error?

    /**
     Start session.

     Initializes the context and initiates the TLS handshake.
     */
    func start() -> Error?

    // MARK: - I/O

    /**
     Read data.
     */
    func read(_ data: inout Data, _ dataLength: inout Int) -> Error?

    /**
     Write data.
     */
    func write(_ data: Data, _ dataLength: inout Int) -> Error?

}


// End of File
