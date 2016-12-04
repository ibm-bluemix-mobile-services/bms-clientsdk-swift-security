//
//  view.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 30/11/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import UIKit

//var requestCount = 0
//class RequestInterceptor : URLProtocol {
//    init(task: URLSessionTask, cachedResponse: CachedURLResponse?, client: URLProtocolClient?) {
//        super.init(task: task, cachedResponse: cachedResponse, client: client)
////    override public class func canInit(with request: URLRequest) -> Bool {
//        print("Request #\(requestCount): URL = \(request.url)")
//        requestCount += 1
//    }
//
//
//
//}

class view: UIViewController, UIWebViewDelegate {
    var url:String = ""
    var previousView:UIViewController!
    var myWebView:UIWebView!
    var completion: ((String) -> Void)!
    func setUrl(url: String) {
        self.url = url
    }
    
    func setCompletionHandle(completionHandler : @escaping (String) -> Void) {
        self.completion = completionHandler
    }
    override func viewDidLoad() {
        super.viewDidLoad()
        let myWebView:UIWebView = UIWebView(frame: CGRect(x:0, y:0, width: UIScreen.main.bounds.width, height:UIScreen.main.bounds.height))
        self.view.addSubview(myWebView)
        myWebView.delegate = self
        let myURL = URL(string: url)
        var myURLRequest:URLRequest = URLRequest(url: myURL!)
        myURLRequest.httpMethod = "GET"
        //        URLProtocol.RE
        //        URLProtocol.registerClass(RequestInterceptor)
        myWebView.loadRequest(myURLRequest)
        
        
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    func webView(_ webView: UIWebView, shouldStartLoadWith request: URLRequest, navigationType: UIWebViewNavigationType) -> Bool {
        if let url = request.url?.absoluteString  {
            if url.hasPrefix("http://localhost/code") == true {
                let a = url.components(separatedBy: "http://localhost/code?code=")[1]
                self.dismiss(animated: true, completion: {
                    self.completion(a.components(separatedBy: "#_=_")[0])
                })
            }
        }
        return true
    }
    
}
