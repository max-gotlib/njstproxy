//
//  NJSTProxy.js
//  NJSTProxy
//
//  Created by Maxim Gotlib on 2/28/17.
//  Copyright © 2017 Maxim Gotlib. All rights reserved.
//

const EventEmitter = require('events');
const http = require('http');
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const urlUtils = require('url');
const util = require('util');
const assert = require('assert');
const debuglog = util.debuglog('TP');

// TODO: Replace with correct bindings to dependencies.
const njsp = require('../../njssocketpair/lib/NJSSocketPair.js');
const njsx509 = require('../../njsx509/lib/njsx509.js');

/// Default address to listen to for incoming HTTP requests.
const kDefaultListenerAddress = '127.0.0.1';
/// Default TCP port number to listen at for incoming HTTP requests.
const kDefaultListenerPort = 1234;
/// Default timeout (maximum idle time in milliseconds) for incoming TCP connections.
const kDefaultListenerTimeout = 45000;

/// SSL/TLS method to use for handshake during client CONNECT requests termination.
const kTLSSecureProtocol = 'SSLv23_server_method';
/// Configuration options for SSL context for client CONNECT requests termination.
const kTLSSecureOptions = require('constants').SSL_OP_NO_TLSv1;

/// Passphrase, used to encrypt CA certificate private key. Encrypted private key is supplied as an argument for SSL context (used to terminate 'CONNECT' client requests) constructor.
const kCAPrivateKeyPassphrase = Math.random().toString(36).slice(2);

/// Template for 'connection established' response HTTP message for client 'connect' requests.
const kHTTP200ConnectedMessage = '\
HTTP/1.1 200 Connection established\r\n\
Keep-Alive: timeout=45, max=100\r\n\
Connection: Keep-Alive\r\n\
\r\n';

/// Template for 'bad request' response HTTP message, sent to clients in case their requests can not be processed.
const kHTTP400BadRequestMessage = '\
HTTP/1.1 400 Bad request\r\n\
Content-Type: text/plain; charset=UTF-8\r\n\
Connection: close\r\n\
Content-Length: ';

/// Template for 'internal error' response HTTP message, sent to clients in case their requests can not be processed.
const kHTTP500TextMessage = '\
HTTP/1.1 500 Internal error\r\n\
Content-Type: text/plain; charset=UTF-8\r\n\
Connection: close\r\n\
Content-Length: ';

/// Flag for running with debug mode turned on.
const kDebug = (() => {
    const nd = process.env.NODE_DEBUG;
    if(!nd) {
        return false;
    }
    for(cat of nd.split(',')) {
        if(cat.trim() == 'TP') {
            return true;
        }
    }
    return false;
})();

/**
 * Terminating HTTP/HTTPS proxy class.
 *
 * Usage example (error checking and handling is omitted):
 *
 *      // Obtain an instance of CA certificate with a private key attached.
 *      let clientIdentityData = fs.readFileSync('client.identity');
 *      let clientIdentity = njsx509.importPKCS12(clientIdentityData, 'some-passphrase-to-decrypt-pkcs12-blob', 'der');
 *
 *      // Prepare proxy configuration.
 *      let proxyConfig = {
 *          ca: clientIdentity.certificate,
 *          address: '127.0.0.1',
 *          port: 1234,
 *          timeout: 45000
 *      };
 *
 *      // Instantiate proxy.
 *      let p = new TerminatingHTTPProxy(proxyConfig);
 *      
 *      // Activate proxy.
 *      p.start(() => {
 *          console.log('Proxy started.');
 *          // Schedule proxy termination.
 *          setTimeout(() => {
 *              p.stop(() => {
 *                  console.log('Proxy stopped.');
 *              });
 *          }, 15000);
 *      });
 *
 * Test with (for example):
 *      curl -x localhost:1234 -v https://www.google.com
 */
class TerminatingHTTPProxy extends EventEmitter {
    
    /**
     * Terminating HTTP/HTTPS proxy instance constructor.
     *
     * Proxy is instantiated with the following supported (all are optional) configuration properties:
     *      - 'address' - Address to listen for incoming requests at. Defaults to 'localhost', using IPv4.
     *      - 'port' - TCP port number to listen for incoming requests at. Defaults to 3128.
     *      - 'ca' - CA certificates, used to issue X509 certificates for terminating client CONNECT requests. This should be NJSX509Certificate class instance with private key attached.
     *      - 'timeout' - Timeout (milliseconds) for incoming connections idle time.
     *
     * Events, emitted by the HTTP proxy instance:
     *      - 'incomingConnection' - Incoming TCP connection, accepted. Event handler parameter - accepted socket object.
     *      - 'requestOptions' - Proxy has prepared HTTP request options and is going to send request to the original server. Event handler parameter - request options.
     *      - 'requestData' - Incoming requests body data chunk received. Event handler parameters are:
     *          - req - Client request (HTTP.IncommingMessage class instance) object;
     *          - data - Client request (Buffer class instance) body chunk.
     *      - 'requestError' - An error occurred during client request submission to the original server. Event handler parameters are:
     *          - req - Client request (HTTP.ClientRequest class instance), being submitted to the origin server, object;
     *          - error - Client request submission error descriptor.
     *      - 'responseHeader' - Response from origin server has been received. Event handler parameter - response (HTTP.ClientRequest class instance), received from the origin server.
     *      - 'responseData' - A response body data chunk received from origin server. Event handler parameters are:
     *          - response - Response (HTTP.ClientRequest class instance), received from the origin server.;
     *          - data - Origin server response body (Buffer class instance) chunk.
     *      - 'responseFinish' - Processing finished for response from origin server. Event handler parameter - response (HTTP.ClientRequest class instance), received from the origin server.
     *      - 'responseError' - An error occurred during reception or processing response from origin server. Event handler parameters are:
     *          - response - Response (HTTP.ClientRequest class instance), received from the origin server.;
     *          - error - Response reception or processing error descriptor.
     *
     * @param configuration Optional proxy instance configuration. Should be an object.
     */
    constructor(configuration) {
        super();
        
        // Provide default configuration.
        this._listenerAddress = kDefaultListenerAddress;
        this._listenerPort = kDefaultListenerPort;
        this._listenerTimeout = kDefaultListenerTimeout;

        // Initiate run-time state variables.
        this._sslContextCache = new Map();
        this._caCertSerialNoSequencer = 1;
        this._connectWrapSerialNo = 1;
        this._reqiestSerialNumber = 1;
        
        // Apply user configuration.
        if(configuration && typeof configuration == 'object') {
            this.configure(configuration);
        }
    }
    
    // Public API.
    
    /**
     * Configure HTTP proxy instance. This method should be called before an attempt to start the proxy.
     *
     * @param configuration An object, providing configuration parameters for the proxy instance. Please, see comments for the class constructor for detailed list of supported configuration parameters.
     */
    configure(configuration) {
        assert(typeof configuration == 'object');
    
        let caCertificate = configuration.ca;
        if(caCertificate) {
            this.caCertificate = caCertificate;
        }
        
        if(configuration.address) {
            this.listenerAddress = configuration.address;
        }
        
        if(configuration.port) {
            this.listenerPort = configuration.port;
        }
        
        if(configuration.timeout) {
            this.listenerTimeout = configuration.timeout;
        }
        
        debuglog('Using listener at: %s:%d.', this._listenerAddress, this._listenerPort);
        debuglog('Using listener timeout: %d.', this._listenerTimeout);
        if(this._caCertificate) {
            debuglog('Using CA certificate: %s', this._caCertificate.commonName);
        } else {
            debuglog('Using CA certificate: none (HTTPS termination disabled).');
        }
    }
    
    /**
     * Getter for address the HTTP proxy instance is configured to listen at for incoming requests.
     *
     * @return Listener address, configured for incoming HTTP requests.
     */
    get listenerAddress() {
        return this._listenerAddress;
    }
    
    /**
     * Setter for address the HTTP proxy instance is intended to listen at for incoming requests.
     *
     * @param address Desired listener address. Pass undefined to use default address (kDefaultListenerAddress).
     */
    set listenerAddress(address) {
        if(address) {
            this._listenerAddress = address;
        } else {
            this._listenerAddress = kDefaultListenerAddress;
        }
    }

    /**
     * Getter for TCP port number the HTTP proxy instance is (will be) bound to listen for incoming requests.
     *
     * @return TCP port number the HTTP proxy instance is (will be) bound to listen for incoming requests.
     */
    get listenerPort() {
        return this._listenerPort;
    }
    
    /**
     * Setter for TCP port number the HTTP proxy instance is intended to listen at for incoming requests.
     *
     * @param port Desired TCP port number to bind listener to. Pass undefined to use default port number (kDefaultListenerPort).
     */
    set listenerPort(port) {
        if(typeof port != 'number') {
            port = Number.parseInt(port);
        }
        if(port) {
            this._listenerPort = port;
        } else {
            this._listenerPort = kDefaultListenerPort;
        }
    }

    /**
     * Getter for incoming TCP connection timeout.
     *
     * @return Maximum idle time (in milliseconds) for keeping incoming TCP connections alive.
     */
    get listenerTimeout() {
        return this._listenerTimeout;
    }
    
    /**
     * Setter for incoming TCP connection timeout.
     *
     * @param timeout Maximum idle time (in milliseconds) for keeping incoming TCP connections alive. Pass undefined to use default port number (kDefaultListenerTimeout).
     */
    set listenerTimeout(timeout) {
        if(typeof timeout != 'number') {
            timeout = Number.parseInt(timeout);
        }
        if(timeout) {
            this._listenerTimeout = timeout;
        } else {
            this._listenerTimeout = kDefaultListenerTimeout;
        }
    }

    /**
     * Getter for CA certificate, used by the proxy instance to terminate SSL/TLS connections.
     *
     * @return NJSX509Certificate class instance or undefined, if no CA certificate was provided during proxy instance configuration.
     */
    get caCertificate() {
        return this._caCertificate;
    }

    /**
     * Setter for CA certificate, used by the proxy instance to terminate SSL/TLS connections.
     *
     * @param NJSX509Certificate class instance or undefined, if no CA certificate should be used (meaning no SSL/TLS connection termination will be done by the proxy).
     */
    set caCertificate(cert) {
        if(cert === undefined) {
            this._caCertificate = undefined;
            return;
        }
        if(!cert instanceof njsx509.NJSX509Certificate) {
            throw new Error("CA certificate should be provided and should be an instance of NJSX509Certificate class.");
        }
        let pk = cert.getPrivateKey(kCAPrivateKeyPassphrase);
        if(pk === undefined) {
            throw new Error("CA certificate has no private key assigned.");
        }
        this._caCertificate = cert;
        this._caPK = pk;
        this._sslContextCache.clear();
        debuglog('Purged SSL context cache.');
    }

    /**
     * Getter for HTTP server instance, used to accept incoming requests.
     *
     * @return Underlying HTTP server instance or undefined if none was started yet.
     */
    get httpServer() {
        return this._httpServer;
    }
    
    /**
     * Start HTTP proxy instance.
     *
     * @param callback Optional function object to call on HTTP proxy start attempt completed. Callback function is supplied with the only argument - error descriptor (on successful start it is passed as undefined).
     */
    start(callback) {
        let srv = this._httpServer;
        if(srv === undefined) {
            this._createHTTPServer(callback);
            return;
        }
        
        if(!callback) {
            return;
        }
        
        if(srv.listening) {
            callback(undefined);
            return;
        }
        srv.once('listening', () => {
            srv.removeListener('error', callback);
            callback();
        });
        srv.once('error', callback);
    }

    /**
     * Terminate HTTP proxy instance activity.
     *
     * @param callback Optional function object to call on HTTP proxy termination procedures completed. Callback function has no arguments.
     */
    stop(callback) {
        let srv = this._httpServer;
        if(srv === undefined) {
            if(callback) {
                callback();
            }
            return;
        }
        srv.close(callback);
    }

    /**
     * Get textual representation for HTTP proxy instance.
     */
    toString() {
        return '[object NJSTProxy: ' + this._listenerAddress + ':' + this._listenerPort + ']';
    }

    // Private API.

    /**
     * Create SSL context to wrap client connection with.
     * Context is configured with a certificate, issued for given host by the CA, configured for HTTP proxy.
     * Created context objects are cached for subsequent reuse.
     *
     * @param targetHost Hostname, that is the target for client 'CONNECT' request being served.
     * @param targetPort (optional) TCP port number, that is the target for client 'CONNECT' request being served. If passed as undefined, a default port number (443) is used.
     * @return Configured SSL context object or undefined value on error.
     */
    _prepareSSLContext(targetHost, targetPort) {
        assert(targetHost);
        if(!targetPort) {
            targetPort = 443;
        }
        
        let ctxLookupKey = '' + targetHost + ':' + targetPort;
        var ctx = this._sslContextCache.get(ctxLookupKey);
        if(ctx) {
            debuglog('Using cached SSL context for: %s.', ctxLookupKey);
            assert(ctx._usageCount);
            ctx._usageCount += 1;
            return ctx;
        }
        
        let caCert = this._caCertificate;
        if(caCert === undefined) {
            debuglog('No CA certificate to configure SSL context for: %s.', ctxLookupKey);
            return undefined;
        }
        assert(caCert instanceof njsx509.NJSX509Certificate);
        
        debuglog('Creating SSL context for: %s.', ctxLookupKey);
        let cert = caCert.issueCertificate(targetHost, this._caCertSerialNoSequencer);
        if(cert === undefined) {
            debuglog('Failed to issue certificate for new SSL context: %s.', ctxLookupKey);
            return undefined;
        }
        debuglog('Created certificate for new SSL context: %s.', ctxLookupKey);
        
        this._caCertSerialNoSequencer += 1;
        
        let ctxCert = cert.exportCertificate('pem');
        assert(ctxCert);
        
        ctx = tls.createSecureContext({
            isServer : true,
            requestCert : false,
            rejectUnauthorized : false,
            secureProtocol : kTLSSecureProtocol,
            secureOptions : kTLSSecureOptions,
            key : this._caPK,
            cert : ctxCert,
            passphrase : kCAPrivateKeyPassphrase
        });
        if(!ctx) {
            debuglog('Failed to create new SSL context for: %s.', ctxLookupKey);
            return undefined;
        }
        
        ctx._usageCount = 1;
        this._sslContextCache.set(ctxLookupKey, ctx);

        debuglog('Created SSL context for: %s.', ctxLookupKey);
        return ctx;
    }

    /**
     * Compose and submit for transmission (over given socket) a HTTP/500 (Internal error) error message.
     *
     * @param socket Socket object to use to transmit composed error message.
     * @param message Optional text message to include into HTTP/500 error response. Defaults to an empty string.
     */
    _reportInternalError(socket, message) {
        if(message === undefined) {
            message = '';
        }
        let errBuf = Buffer.from(message, 'utf8');
        socket.write(kHTTP500TextMessage);
        socket.write('' + errBuf.length + '\r\n\r\n');
        socket.write(errBuf);
        socket.end("\r\n");
    }

    /**
     * Compose and submit for transmission (over given socket) a TLS Alert message.
     *
     * @param socket Socket object to use to transmit composed alert message.
     * @param alertType Optional TLS alert type. Defaults to 2 ('fatal').
     * @param alertMessage Optional TLS alert message. Defaults to 80 ('internal error').
     */
    _reportTLSAlert(socket, alertType, alertMessage) {
        if(alertType === undefined) {
            alertType = 2; // 'fatal'
        }
        if(alertMessage === undefined) {
            alertMessage = 80; // 'internal error'
        }
        let alertBuff = Buffer.alloc(7);
        alertBuff[0] = 21;  // Record layer: type: alert
        alertBuff[1] = 3;   // Record layer: version major: TLS-1.x
        alertBuff[2] = 3;   // Record layer: version minor: TLS-1.2
        alertBuff[3] = 0;   // Record layer: length MSB: 0
        alertBuff[4] = 2;   // Record layer: length LSB: 2
        alertBuff[5] = alertType;   // Alert layer:  type
        alertBuff[6] = alertMessage;  // Alert layer:  message
        socket.end(alertBuff);
    }

    /**
     * Compose and submit for transmission (over given socket) a HTTP/400 (Bad request) error message.
     *
     * @param socket Socket object to use to transmit composed error message.
     * @param message Optional text message to include into HTTP/400 error response. Defaults to an empty string.
     */
    _reportBadRequest(socket, message) {
        if(message === undefined) {
            message = '';
        }
        let errBuf = Buffer.from(message, 'utf8');
        socket.write(kHTTP400BadRequestMessage);
        socket.write('' + errBuf.length + '\r\n\r\n');
        socket.write(errBuf);
        socket.end("\r\n");
    }

    /**
     * Create HTTP server instance and try to start it.
     *
     * @param callback Optional callback object to be called on HTTP server startup attempt completed. Callback is supplied with the only parameter - error descriptor. On server started successfully, callback is given undefined value as an argument.
     */
    _createHTTPServer(callback) {
        let srv = http.createServer((req, res) => {
            this._handleIncomingRequest(req, res);
        })
        .on('close', () => {
            debuglog('HTTP server stopped.');
            njsp.stopListener(false, () => {
                debuglog('Socket pair factory stopped.');
            });
        })
        .on('connection', (socket) => {
            debuglog('Incoming connection.');
            this.emit('incomingConnection', socket);
        })
        .on('connect', (req, socket, head) => {
            this._handleConnectRequest(req, socket, head);
        })
        .on('error', (e) => {
            debuglog('Server error: %s', e);
        })
        .once('error', callback);
        
        this._httpServer = srv;
        
        srv.setTimeout(this._listenerTimeout);
        srv.listen(this._listenerPort, this._listenerAddress, 5, () => {
            srv.removeListener('error', callback);
            debuglog('HTTP server started');
            if(callback) {
                callback();
            }
        });
    }

    /**
     * Process client 'CONNECT' request. Request is artificially terminated:
     * - a 'connection established' response is sent immediately on request reception;
     * - a decision is made on the client's willing to establish plain text or SLL/TLS connection to the target server;
     * - if it is necessary, SSL context is created and used to wrap client session;
     * - so far configured (wrapped) client session is emitted back to the HTTP server as if it was just accepted (unfortunately, due to Node.js implementation bug, there is need to mediate this with another inter-connected socket pair).
     *
     * @param req Client 'CONNECT' request's message.
     * @param socket Client connection.
     * @param head Optional data block already read from the client over the 'socket'.
     */
    _handleConnectRequest(req, socket, head) {
        assert(req);
        assert(socket);
        
        let targetUrl = req.url;
        if(!targetUrl || !targetUrl.length) {
            this._reportBadRequest(socket, 'No target host:port pair to connect to.');
            return;
        }
        let [host, port] = req.url.split(':');
        if(!host) {
            this._reportBadRequest(socket, 'No target host to connect to.');
            return;
        }
        if(!port) {
            port = 443;
        }
        debuglog('CONNECT request to: %s:%d.', host, port);
        
        // Wait for small (6 bytes) data chunk from the client to decide whether it wants to have SSL/TL or plain text connection.
        if(this._collectClientHelloAndEmitConnectedClientSocket(socket, host, port, head)) {
            return;
        }
        debuglog('Not enough client data to make a TLS/Plain decision.');

        // Temporary error handler - just for logging client connection errors.
        let clientSocketConnectStateErrorCallback = (err) => {
            debuglog('Client socket error: %s', err.stack);
        };
        
        socket.on('data', (data) => {
            head = TerminatingHTTPProxy._combineDataBlocks(head, data);
            if(this._collectClientHelloAndEmitConnectedClientSocket(socket, host, port, head)) {
                // Connect state error handler is not needed more - the proper one is installed by _emitConnectedClientSocket() method.
                socket.removeListener('error', clientSocketConnectStateErrorCallback);
                socket.setTimeout(0);
                return;
            }
            debuglog('Still not enough client data to make a TLS/Plain decision.');
        })
        .on('error', clientSocketConnectStateErrorCallback)
        .once('timeout', () => {
            socket.destroy(new Error('Timed out, waiting for client request.'));
        });
        
        debuglog('Provoking client to start data transmission.');
        socket.write(kHTTP200ConnectedMessage);
    }

    /**
     * Handler for incoming client requests.
     * The same handler is used for HTTP requests, accepted by underlying HTTP server and over wrapped client connections (emitted back to underlying server as if they were accepted by it).
     * Client request is satisfied by issuing requests to original (target) server with data/event piping between client and original request/response objects.
     *
     * @param req Client request object (HTTP.IncomingMessage class instance), used to acquire client request parameters.
     * @param res Server response object (HTTP.ServerResponse class instance), used by underlying server to deliver response to the client.
     */
    _handleIncomingRequest(req, res) {
        var reqOptions;
        
        // Assign serial number to the request being processed. Just for logging purposes.
        let reqSerialNo = this._reqiestSerialNumber;
        this._reqiestSerialNumber += 1;
        
        // Parse request target and append absent parts from CONNECT (if one was received) request parameters.
        try {
            let targetURL = urlUtils.parse(req.url);
            if(targetURL === undefined || targetURL === null) {
                throw new Error("Invalid URL.");
            }
        
            var host = targetURL.host;
            var port = targetURL.port;
            var proto = targetURL.protocol;
            if(!host) {
                // Deduce target host:port from incoming request.
                let s = req.socket;
                if(s) {
                    host = s._originTargetHost
                    if(!port) {
                        port = s._originTargetPort;
                    }
                    if(!proto) {
                        proto = s._originTargetProto;
                    }
                }
            }
            if(!host) {
                throw new Error("Invalid URL.");
            }
            if(!port) {
                port = 80;
            }
            if(!proto) {
                proto = 'http:';
            }
            var path = targetURL.path;
            if(!path) {
                path = '/';
            }
        
            if(kDebug) {
                debuglog('Incoming request [%d] for: %s//%s:%d%s %s', reqSerialNo, proto, host, port, path, util.inspect(req.headers, {showHidden: false, depth: 1}));
            }
            
            // Compose options for request to the original HTTP server.
            reqOptions = {
                protocol: proto,
                hostname: host,
                port: port,
                path: path,
                method: req.method,
                headers: req.headers
            };
            
            // Let observers alter outgoing request options.
            this.emit('requestOptions', reqOptions, req, res);
        } catch(e) {
            // Something has gone wrong during original request options preparation - report HTTP/400 'Bad request' error to the client.
            debuglog('Failed to prepare original request [%d] options: %s', reqSerialNo, e);
            if(res.socket) {
                this._reportBadRequest(res.socket, e.message);
                return;
            }
            res.destroy(e);
            return;
        }
        
        if(kDebug) {
            debuglog('Outgoing request [%d]: %s', reqSerialNo, util.inspect(reqOptions, {showHidden: false, depth: 1}));
        }

        // Submit request to original HTTP server.
        let origResponseHandler = (origResp) => {
            if(kDebug) {
                debuglog('Original response [%d] for %s//%s:%d%s: %d %s', reqSerialNo, reqOptions.protocol, reqOptions.hostname, reqOptions.port, reqOptions.path, origResp.statusCode, util.inspect(origResp.headers, {showHidden: false, depth: 1}));
            }
            
            // Notify observers on a response, received from the original server.
            this.emit('responseHeader', origResp);

            // Pass origin response headers through a validator. Node.js validates headers, set for ServerResponse object, though it doesn't validate "incoming" header values. As a result, invalid (having non UTF-8 characters, for example) header field, coming from original server, causes client blow up.
            // Collect original server response headers and combine duplicates.
            var key;
            var headers = new Map();
            origResp.rawHeaders.forEach((currentValue, index) => {
                if((index & 1) == 0) {
                    key = currentValue;
                    return;
                }
                let existingVal = headers.get(key);
                if(existingVal === undefined) {
                    headers.set(key, currentValue);
                    return;
                }
                if(typeof existingVal == 'string') {
                    headers.set(key, [existingVal, currentValue]);
                    return;
                }
                existingVal.push(currentValue);
            });
            
            // Push original response headers to the client response.
            headers.forEach((val, key) => {
                // Be optimistic about header value being valid.
                try {
                    res.setHeader(key, val);
                } catch(e) {
                    debuglog('Failed to set header: %s: %s:\n%s', key, val, e);
                    // Header contains invalid character(s). Escape them.
                    var escapedVal;
                    if(typeof val == 'string') {
                        escapedVal = val.replace(/[^a-zA-Z0-9,.:;=&@\-+\/()\\[\] ]+/g, (c) => { return escape(c); });
                    } else {
                        escapedVal = val.map((v) => {
                            return v.replace(/[^a-zA-Z0-9,.:;=&@\-+\/()\\[\] ]+/g, (c) => { return escape(c); });
                        });
                    }
                
                    try {
                        res.setHeader(key, escapedVal);
                    } catch(ee) {
                        // Did at most I could. Skip the header.
                        debuglog('Skipping invalid header. Failed to set it, even with escaping: %s: %s:\n%s', key, val, ee);
                    }
                }
            });
 
            // Start feeding original server's response to the client.
            res.writeHead(origResp.statusCode, origResp.statusMessage);
            
            // Prepare for data/error propagation from original to client response object.
            origResp.on('data', (d) => {
                debuglog('Got original response [%d] body chunk of length: %d.', reqSerialNo, d.length);
                this.emit('responseData', origResp, d);
                res.write(d);
            })
            .on('error', (e) => {
                this.emit('responseError', origResp, e);
                debuglog('Error in original response [%d]: %s', reqSerialNo, e);
            })
            .on('end', () => {
                debuglog('Original response [%d] processing finished.', reqSerialNo);
                this.emit('responseFinish', origResp);
                res.end();
            });
        };
        
        let requestor = (reqOptions.protocol == 'http:') ? http : https;
        var origReq
        try {
            origReq = requestor.request(reqOptions, origResponseHandler)
        } catch(e) {
            debuglog('Failed to compose request to original server [%d]: %s', reqSerialNo, e);
            if(res.socket) {
                this._reportBadRequest(res.socket, e.message);
                return;
            }
            res.destroy(e);
            return;
        }
        
        origReq.on('error', (e) => {
            debuglog('Error in original request [%d]: %s', reqSerialNo, e);
            this.emit('requestError', origReq, e);
            origReq.removeAllListeners('abort');
        })
        .on('abort', () => {
            debuglog('Original request [%d] aborted.', reqSerialNo);
            this.emit('requestError', origReq, new Error('Aborted.'));
        });

        // Capture premature client connection closure and force original request aborted in that case.
        res.once('close', () => {
            debuglog('Premature client response connection closed [%d].', reqSerialNo);
            origReq.abort();
        });
        
        // Propagate client request data/error events to the original request.
        req.on('data', (d) => {
            debuglog('Got client request [%d] body chunk of length: %d.', reqSerialNo, d.length);
            this.emit('requestData', req, d);
            origReq.write(d);
        })
        .on('error', (e) => {
            debuglog('Error in client request [%d]: %s', reqSerialNo, e);
            origRequest.abort();
        })
        .on('end', () => {
            debuglog('Client request [%d] processing finished.', reqSerialNo);
            origReq.end();
        });
    }
    
    /**
     * Predicate method for testing whether provided data buffer contains SSL/TLS Client Hello message.
     *
     * @param tlsDetectBuff Buffer with incoming message fragment (at least 6 bytes long) to test for SSL client hello message presence. It is expected to be Buffer class instance.
     * @return Boolean value, indicating SSL/TLS Client Hello message presence in provided data buffer.
     */
    _isSSLClientHello(tlsDetectBuff)
    {
        assert(tlsDetectBuff.length >= 6);
        
        // SSLv3
        if(tlsDetectBuff[0] == 0x16 && tlsDetectBuff[1] == 0x03 && tlsDetectBuff[5] == 0x01) {
            return true;
        }
        
        // SSLv2
        if((tlsDetectBuff[0] & 0x80) != 0 && tlsDetectBuff[2] == 0x01 && ((tlsDetectBuff[0] & 0x7f) << 8 | tlsDetectBuff[1]) > 9) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Emit client socket, possibly wrapped with SSL/TLS transforming stream, back to the underlying HTTP server to let it process new incoming client requests.
     *
     * @param socket Client connection.
     * @param head A buffer with data block, already read over the client connection and pending for re-processing.
     * @param targetHost Hostname of the origin server the client is willing to connect to.
     * @param targetPort TCP port number on the origin server the client is willing to connect to.
     * @param needsTLS Flag to wrap client connection (socket) with SSL/TLS transforming stream before emitting back to the underlying HTTP server.
     */
    _emitConnectedClientSocket(socket, head, targetHost, targetPort, needsTLS)
    {
        assert(targetHost);
        if(!targetPort) {
            targetPort = 443;
        }
        
        // Wrapped connection sequencer - only for logging purposes.
        let cwSerialNo = this._connectWrapSerialNo;
        this._connectWrapSerialNo += 1;
        
        /*
         * The following does not work (at least in Node.js v6.10.0 and v7.7.1) due to a "feature" of http server - it does not accept back sockets, already accepted;
         *
         *      let tlsSock = new tls.TLSSocket(socket);
         *      srv.emit('connection', tlsSock);
         *
         * The problem is known: https://github.com/nodejs/node/pull/5104.
         * As a workaround, an inter-connected UNIX/named-pipe socket pair is created and a "remote" end is wrapped (if necessary) with TLS/SSL transformer and is fed (emitted) back to the http server, while the "local" end is piped with the client socket.
         */

        debuglog('Starting inter-connected socket pair allocation for connect request to: %s:%d.', targetHost, targetPort);
        njsp.socketpair((sp, err) => {
            if(!sp) {
                debuglog('Inter-connected socket pair acquisition failed for connect request to: %s:%d: %s.', targetHost, targetPort, err);
                if(needsTLS) {
                    this._reportTLSAlert(socket); // 'fatal', 'internal error'
                } else {
                    this._reportInternalError(socket, err.stack);
                }
                return;
            }
            debuglog('Acquired inter-connected socket pair [cw:%d] for connect request to: %s:%d.', cwSerialNo, targetHost, targetPort);

            // Wrap client socket with SSL/TLS if required.
            var targetSock;
            if(needsTLS) {
                let ctx = this._prepareSSLContext(targetHost, targetPort);
                if(ctx == undefined) {
                    this._reportTLSAlert(socket, 2, 48); // 'fatal', 'unknown ca'
                    return;
                }
            
                targetSock = new tls.TLSSocket(sp.remoteSock, {
                    isServer : true,
                    requestCert : false,
                    rejectUnauthorized : false,
                    secureContext : ctx
                })
                .once('secure', () => {
                    debuglog('TLS/SSL handshake succeeded for connect request [cw:%d] to: %s:%d.', cwSerialNo, targetHost, targetPort);
                    this._httpServer.emit('connection', targetSock);
                });
                targetSock._originTargetProto = 'https:';
            } else {
                targetSock = sp.remoteSock;
                targetSock._originTargetProto = 'http:';
            }

            // Memorize the target host/port (origin) for handling requests, received over wrapped connection.
            targetSock._originTargetHost = targetHost;
            targetSock._originTargetPort = targetPort;

            // Complete socket pipe: <client> : 'socket' : 'localSock' : TLS('targetSock') : <http server>.
            let localSock = sp.localSock;
            targetSock.on('error', (e) => {
                debuglog('Server socket for connect request [cw:%d] failure: %s', cwSerialNo, e);
                socket.unpipe();
                localSock.unpipe();
                targetSock.unpipe();
                
                localSock.destroy(e);
                socket.destroy(e);
            });
            
            localSock.pipe(socket)
            .on('error', (e) => {
                debuglog('Local socket for connect request [cw:%d] failure: %s', cwSerialNo, e);
                localSock.unpipe();
                targetSock.unpipe();
                socket.unpipe();
                
                socket.destroy();
                targetSock.destroy();
            });

            socket.pipe(sp.localSock)
            .on('error', (e) => {
                debuglog('Client socket for connect request [cw:%d] failure: %s', cwSerialNo, e);
                targetSock.unpipe();
                localSock.unpipe();
                socket.unpipe();
                
                localSock.destroy(e);
                targetSock.destroy(e);
            });
            
            if(kDebug) {
                socket.on('close', () => {
                    debuglog('Client socket for connect request [cw:%d] closed.', cwSerialNo);
                });
                localSock.on('close', () => {
                    debuglog('Local socket for connect request [cw:%d] closed.', cwSerialNo);
                });
                targetSock.on('close', () => {
                    debuglog('Server socket for connect request [cw:%d] closed.', cwSerialNo);
                });
            }

            localSock.resume()
            targetSock.resume();
            
            // Emit target socket as if it was just accepted by the underlying HTTP server. This is done only for non-TLS-wrapped socket pipe - in case of TLS wrapping emission will be done upon TLS/SSL handshake succeeded.
            if(!needsTLS) {
                this._httpServer.emit('connection', targetSock);
            }
            
            // Push data block, already read from the client, back into the socket pipe towards the underlying HTTP server.
            if(head && head.length) {
                localSock.write(head);
            }
        });
    }
    
    /**
     * Helper method: concatenate two data Buffer objects content.
     *
     * @param head First data Buffer instance.
     * @param data Second data Buffer instance, whose content is concatenated to the 'head'.
     * @return Buffer class instance, whose content is composed of head's, concatenated with data's.
     */
    static _combineDataBlocks(head, data) {
        if(head === undefined || head === null || head.length == 0) {
            return data;
        }
        if(data === undefined || data === null || data.length == 0) {
            return head;
        }
        let b = new Buffer.alloc(head.length + data.length);
        if(head.length) {
            head.copy(b, 0);
        }
        if(data.length) {
            data.copy(b, head.length);
        }
        return b;
    }

    /**
     * Given a data block, received over a connection with proxy client, make a decision whether client wants TLS/SSL session, wrap client connection with TLS/SSL and emit connection back to the underlying HTTP server as if it was just accepted.
     *
     * @param socket Connection with proxy client, who issued 'CONNECT' request.
     * @param host Target host name for client 'CONNECT' request.
     * @param host Target TCP port number for client 'CONNECT' request.
     * @param head A data block, received over client connection. This block will be inspected for TLS/SSL Client Hello message presence. Should be an instance of Buffer class.
     * @return Boolean false, if there is not enough data ('head' has insufficient bytes) to make a TLS/SSL-plain/text decision. True is returned on an attempt to wrap client connection done (successful or not).
     */
    _collectClientHelloAndEmitConnectedClientSocket(socket, host, port, head) {
        if(head.length < 6) {
            return false;
        }
        let needsTLS = this._isSSLClientHello(head);
        debuglog('Analyzed collected 6 client bytes: ' + (needsTLS === true ? 'TLS client hello.' : 'plain text.'));
        socket.removeAllListeners('data');
        socket.removeAllListeners('error');
        this._emitConnectedClientSocket(socket, head, host, port, needsTLS);
        return true;
    }
};

var exports = module.exports = {};
exports.TerminatingHTTPProxy = TerminatingHTTPProxy;
