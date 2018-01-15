/*
 -----------------------------------------------------------------------------
 This source file is part of SecurityKit.
 
 Copyright 2016-2018 Jon Griffeth
 
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
 Access Control List
 */
public class ACL {
    
    class Subject {
        let         identity   : UUID // placeholder
        private var operations : [UUID]
        
        init(identity: UUID, operations: [UUID])
        {
            self.identity   = identity
            self.operations = operations
        }
        
        func authorized(operation: UUID) -> Bool
        {
            return operations.contains(operation)
        }
    }
    
    private var subjects = [Subject]()
    
    /**
     Initialize empty instance.
     */
    public init()
    {
    }
    
    /**
     Verify authorization.
     */
    public func authorized(principal: Principal?, operation: UUID) -> Bool
    {
        if principal != nil {
            
            /*
            for subject in subjects {
                if subject.authorized(operation: operation) {
                    if principal.isaSubject(subject.identity) {
                        return true
                    }
                }
            }
            */
            return true
            
        }
        
        return false
    }
    
}


// End of File
