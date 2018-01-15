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
 TLS Delegate Protocol
 */
public protocol TLSDelegate: class {

    func tlsCredentials(_ tls: TLS) -> PublicKeyCredentials?
    func tlsPeerName(_ tls: TLS) -> String?
    func tlsPeerAuthenticationComplete(_ tls: TLS) -> Error?

    /**
     Should authenticate peer.
     */
    func tlsShouldAuthenticatePeer(_ tls: TLS) -> Bool

    /**
     Should accept peer.

     - Parameters:
        - port:
        - peer:

     - Precondition: peer.trusted
     */
    func tls(_ tls: TLS, shouldAccept peer: Principal) -> Bool

}

extension TLSDelegate {

    func tlsCredentials(_ tls: TLS) -> PublicKeyCredentials?
    {
        return nil
    }

    func tlsPeerName(_ tls: TLS) -> String?
    {
        return nil
    }

    func tlsShouldAuthenticatePeer(_ tls: TLS) -> Bool
    {
        return false
    }

    func tls(_ tls: TLS, shouldAccept peer: Principal) -> Bool
    {
        return true
    }

}


// End of File


