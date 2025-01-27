//
//  proverTest.swift
//  demo
//
//  Created by Shufflebottom Hogwood on 1/24/25.
//

import XCTest
import Prover
//@testable import PlutoSwiftSDK

final class ProverTests: XCTestCase {
    let start = CFAbsoluteTimeGetCurrent()
    let localHost = "localhost"
    let localPort = "7443"
    let localAuthHeader = ""
    let localMethod = "GET"
    let localUrl = "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json"
    let circuit = "plaintext_authentication_512b.r1cs"
    
    var r1cs_url: String = ""
    override func setUp() {
        super.setUp()
        r1cs_url = "https://localhost:8090/build/circom-artifacts-512b-v0.7.3/\(circuit)"
    }
    
    // TODO: Live app should fetch these in parallel
    func testFetchAndProve() {
        let expectation = XCTestExpectation(description: "Fetch and prove data")
                
            // Move the fetch code inside the test method
        fetchData(from: r1cs_url) { (r1cs_data, error) in
            if let error = error {
                XCTFail("Failed to fetch data: \(error.localizedDescription)")
                expectation.fulfill()
                return
            }
            
            guard let data = r1cs_data else {
                XCTFail("No data received")
                expectation.fulfill()
                return
            }
            
            
            print("data: \(data)")
            let arrayString = data.map { String($0) }.joined(separator: ",")
            let jsonString = """
                 {
                     "max_recv_data": 10000,
                     "max_sent_data": 10000,
                     "mode": "Origo",
                     "notary_host": "\(self.localHost)",
                     "notary_port": \(self.localPort),
                     "target_body": "",
                     "target_headers": {
                         \(self.localAuthHeader)
                         "Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
                     },
                     "target_method": "\(self.localMethod)",
                     "target_url": "\(self.localUrl)",
                     "proving": {
                         "manifest": {
                             "manifestVersion": "1",
                             "id": "reddit-user-karma",
                             "title": "Total Reddit Karma",
                             "description": "Generate a proof that you have a certain amount of karma",
                             "prepareUrl": "https://www.reddit.com/login/",
                             "request": {
                                 "method": "GET",
                                 "version": "HTTP/1.1",
                                 "url": "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
                                 "headers": {
                                     "accept-encoding": "identity"
                                 },
                                 "body": {
                                     "userId": "<% userId %>"
                                 },
                                 "vars": {
                                     "userId": {
                                         "regex": "[a-z]{,20}+"
                                     },
                                     "token": {
                                         "type": "base64",
                                         "length": 32
                                     }
                                 }
                             },
                             "response": {
                                 "status": "200",
                                 "version": "HTTP/1.1",
                                 "message": "OK",
                                 "headers": {
                                     "Content-Type": "text/plain"
                                 },
                                 "body": {
                                     "json": [
                                         "hello"
                                     ],
                                     "contains": "this_string_exists_in_body"
                                 }
                             }
                         }
                     }
                 }
            """
            // NOTE: Witness generation happen in the library for ios
            jsonString.withCString { (cString) in
                Prover.prover(cString)
            }
            let timeElapsed = CFAbsoluteTimeGetCurrent() - self.start
            print("Time elapsed: \(timeElapsed) seconds")
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 30.0)
        
    }
    
}

func fetchData(from urlString: String, completion: @escaping (Data?, Error?) -> Void) {
    guard let url = URL(string: urlString) else {
        completion(nil, NSError(domain: "InvalidURL", code: 0, userInfo: nil))
        return
    }
    
    let delegate = CustomURLSessionDelegate()
    let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
    
    let task = session.dataTask(with: url) { (data, response, error) in
        if let error = error {
            completion(nil, error)
            return
        }
        
        guard let data = data else {
            completion(nil, NSError(domain: "NoData", code: 0, userInfo: nil))
            return
        }
        
        completion(data, nil)
    }
    task.resume()
}

class CustomURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let certificatePath = Bundle.main.path(forResource: "ca-cert", ofType: "cer"),
              let certificateData = try? Data(contentsOf: URL(fileURLWithPath: certificatePath)) else {
            print("Failed to load root CA certificate")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let rootCertificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            print("Failed to create SecCertificate")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        SecTrustSetAnchorCertificates(serverTrust, [rootCertificate] as CFArray)

        // Set a more lenient policy
        let policy = SecPolicyCreateBasicX509()
        SecTrustSetPolicies(serverTrust, policy)

        // Disable network fetching for revocation checks
        SecTrustSetNetworkFetchAllowed(serverTrust, false)

        var result: SecTrustResultType = .invalid
        if SecTrustEvaluate(serverTrust, &result) == errSecSuccess {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            print("Trust evaluation failed")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
