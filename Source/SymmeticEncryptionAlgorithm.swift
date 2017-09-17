/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.

 Copyright 2016-2017 Jon Griffeth

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


public enum SymmetricEncryptionAlgorithm {
    case aes128
    case aes192
    case aes256
}

public extension SymmetricEncryptionAlgorithm {

    var keySize: UInt { return getKeySize() }

    private func getKeySize() -> UInt
    {
        switch (self) {
        case .aes128 :
            return 128

        case .aes192 :
            return 192

        case .aes256 :
            return 256
        }
    }
}


// End of File

