/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityManager.
 
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


/**
 Principal manager.
 */
public class PrincipalManager {
    
    // MARK: - Class Properties
    public static let main = PrincipalManager()
    
    // MARK: - Properties
    public private(set) var primary : Principal?
    
    // MARK: - Private
    private var observers = [PrincipalManagerObserver]()
    
    // MARK: - Initializers
    
    /**
     Initialize instance.
     */
    private init()
    {
    }
    
    // MARK: - Observer Interface
    
    /**
     Add observer.
     */
    public func addObserver(_ observer: PrincipalManagerObserver)
    {
        observers.append(observer)
    }
    
    /**
     Remove observer.
     */
    public func removeObserver(_ observer: PrincipalManagerObserver)
    {
        if let index = observers.index(where: { $0 === observer }) {
            observers.remove(at: index)
        }
    }
    
    // MARK: - Mutators
    
    /**
     Update primary principal.
     */
    public func updatePrimary(_ principal: Principal?)
    {
        primary = principal
        for observer in observers {
            observer.principalManagerDidUpdatePrimary(self)
        }
    }
    
}


// End of File
