/*
*     Copyright 2015 IBM Corp.
*     Licensed under the Apache License, Version 2.0 (the "License");
*     you may not use this file except in compliance with the License.
*     You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*     Unless required by applicable law or agreed to in writing, software
*     distributed under the License is distributed on an "AS IS" BASIS,
*     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*     See the License for the specific language governing permissions and
*     limitations under the License.
*/

public class Queue<Element> {
    public var items = [Element]()
    public var size:Int {return items.count}
    
    public init() {}

    //adds element to queue
    public func add(element:Element){
        items.append(element)
    }

    //remove element from queue. if queue empty returns nil
    public func remove()->Element?{
        return isEmpty() ? nil : items.removeFirst()
    }
    
    //returns next element in queue(without removing). if queue empty, returns nil
    public func element()->Element?{
        return isEmpty() ? nil : items[0]
    }
    
    //checks if queue is empty
    public func isEmpty()->Bool {
        return size == 0 ? true : false
    }
}