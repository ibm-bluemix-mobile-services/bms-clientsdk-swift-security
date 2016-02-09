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

import BMSCore
public class ChallengeHandler : AuthenticationContext{
    
    private  var realm:String
    private  var authenticationDelegate:AuthenticationDelegate?
    private  var waitingRequests:[AuthorizationRequestManager]
    private  var activeRequest:AuthorizationRequestManager?
    private var lockQueue = dispatch_queue_create("ChallengeHandlerQueue", DISPATCH_QUEUE_CONCURRENT)
    
    internal init(realm:String , authenticationDelegate:AuthenticationDelegate) {
        self.realm = realm
        self.authenticationDelegate = authenticationDelegate
        self.activeRequest = nil
        self.waitingRequests = [AuthorizationRequestManager]()
    }
    
    public func  submitAuthenticationChallengeAnswer(answer:[String:AnyObject]?) {
        dispatch_barrier_async(lockQueue){
            guard let aRequest = self.activeRequest else {
                return
            }
            
            if answer != nil {
                aRequest.submitAnswer(answer, realm: self.realm)
            } else {
                aRequest.removeExpectedAnswer(self.realm)
            }
            self.activeRequest = nil
        }
    }
    
    public  func submitAuthenticationSuccess () {
        dispatch_barrier_async(lockQueue){
            if self.activeRequest != nil {
                self.activeRequest!.removeExpectedAnswer(self.realm)
                self.activeRequest = nil
            }
            
            self.releaseWaitingList()
        }
    }
    
    public func submitAuthenticationFailure (info:[String:AnyObject]?) {
        dispatch_barrier_async(lockQueue){
            if self.activeRequest != nil {
                self.activeRequest!.requestFailed(info)
                self.activeRequest = nil
            }
            self.releaseWaitingList()
        }
    }

    public func  handleChallenge(request:AuthorizationRequestManager, challenge:[String:AnyObject]) {
        dispatch_barrier_async(lockQueue){
            if self.activeRequest == nil {
                self.activeRequest = request
                if let unWrappedListener = self.authenticationDelegate{
                    unWrappedListener.onAuthenticationChallengeReceived(self, challenge: challenge)
                }
            } else {
                self.waitingRequests.append(request)
            }
        }
    }
    
    public  func handleSuccess(success:[String:AnyObject]) {
        dispatch_barrier_async(lockQueue){
            if let unWrappedListener = self.authenticationDelegate{
                unWrappedListener.onAuthenticationSuccess(success)
            }
            self.releaseWaitingList()
            self.activeRequest = nil
        }
    }
    public  func handleFailure(failure:[String:AnyObject]) {
        dispatch_barrier_async(lockQueue){
            if let unWrappedListener = self.authenticationDelegate{
                unWrappedListener.onAuthenticationFailure(failure)
            }
            self.clearWaitingList()
            self.activeRequest = nil
        }
    }
    private  func setActiveRequest(request:AuthorizationRequestManager) {
        dispatch_barrier_async(lockQueue){
            self.activeRequest = request
        }
    }
    private func  releaseWaitingList() {
        dispatch_barrier_async(lockQueue){
            for request in self.waitingRequests {
                request.removeExpectedAnswer(self.realm)
            }
            self.clearWaitingList()
        }
    }
    private  func clearWaitingList() {
        dispatch_barrier_async(lockQueue){
            self.waitingRequests.removeAll()
        }
    }
}
