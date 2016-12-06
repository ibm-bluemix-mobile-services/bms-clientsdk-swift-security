//
//  view.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 30/11/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import UIKit


class view: UIViewController, UIWebViewDelegate {
    
    var url:String = ""
    var completion: ((String?) -> Void)!
    
    func setUrl(url: String) {
        self.url = url
    }
    
    func setCompletionHandle(completionHandler : @escaping (String?) -> Void) {
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
        myWebView.loadRequest(myURLRequest)
        
        
    }
    
    func webView(_ webView: UIWebView, shouldStartLoadWith request: URLRequest, navigationType: UIWebViewNavigationType) -> Bool {
        if let url = request.url?.absoluteString  {
            if url.hasPrefix("http://localhost/code") == true {
                self.dismiss(animated: true, completion: {
                    //gets the query, then sepertes it to params, then filters the one the is "code" then takes its value
                    guard let code = request.url?.query?.components(separatedBy: "&").filter({(item) in item.hasPrefix("code")}).first?.components(separatedBy: "=")[1] else{
                        self.completion(nil)
                        return
                    }
                    self.completion(code)
                })
                return false
            }
        }
        return true
    }
    
}
