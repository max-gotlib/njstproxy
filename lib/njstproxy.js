const EventEmitter = require('events');
const http = require('http');
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const urlUtils = require('url');
const util = require('util');
const assert = require('assert');
const debuglog = util.debuglog('TP');

const njsp = require('../../njssocketpair/lib/NJSSocketPair.js');
const njsx509 = require('../../njsx509/lib/njsx509.js');

const tlsSecureProtocol = 'SSLv23_server_method';
const tlsSecureOptions = require('constants').SSL_OP_NO_TLSv1;
const caPrivateKeyPassphrase = Math.random().toString(36).slice(2);

const http200ConnectedMessage = '\
HTTP/1.1 200 Connection established\r\n\
Keep-Alive: timeout=45, max=100\r\n\
Connection: Keep-Alive\r\n\
\r\n';

const http400BadRequestMessage = '\
HTTP/1.1 400 Bad request\r\n\
Content-Type: texp/plain; charset=UTF-8\r\n\
Connection: close\r\n\
Content-Length: ';

const http500TextMessage = '\
HTTP/1.1 500 Internal error\r\n\
Content-Type: texp/plain; charset=UTF-8\r\n\
Connection: close\r\n\
Content-Length: ';

/**
 * Configuration parameters:
 *  'address' - (optional) Address to listen for incoming requests at. Defaults to 'localhost', using IPv4.
 *  'port' - (optional) TCP port number to listen for incoming requests at. Defaults to 3128.
 *  'ca' - (required) CA certificates, used to issue X509 certificates for terminating client CONNECT requests. This should be NJSX509Certificate class instance with private key attached.
 *  'timeout'
 *
 */
class TerminatingHTTPProxy extends EventEmitter {
    
    constructor(caCertificate) {
        super();
        this._sslContextCache = new Map();
        this._caCertSerialNoSequencer = 1;

        this.caCertificate = caCertificate;
    }
    
    // Public API.
    
    get caCertificate() {
        return this._caCertificate;
    }
    
    set caCertificate(cert) {
        assert(cert instanceof njsx509.NJSX509Certificate);
        let pk = cert.getPrivateKey(caPrivateKeyPassphrase);
        if(pk === undefined) {
            throw new Error("CA certificate has no private key assigned.");
        }
        this._caCertificate = cert;
        this._caPK = pk;
        debuglog('CA certificate defined: %s.', cert.subjectName);
        this._sslContextCache.clear();
        debuglog('Purged SSL context cache.');
    }

    get httpServer() {
        return this._httpServer;
    }
    
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
    
    // Private API.

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
        
        debuglog('Creating SSL context for: %s.', ctxLookupKey);
        let cert = this._caCertificate.issueCertificate(targetHost, this._caCertSerialNoSequencer);
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
            secureProtocol : tlsSecureProtocol,
            secureOptions : tlsSecureOptions,
            key : this._caPK,
            cert : ctxCert,
            passphrase : caPrivateKeyPassphrase,
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
    
    _reportInternalError(message, socket) {
        let errBuf = Buffer.from(message, 'utf8');
        socket.write(http500TextMessage);
        socket.write('' + errBuf.length + '\r\n\r\n');
        socket.write(errBuf);
        socket.end("\r\n");
    }

    _reportBadRequest(message, socket) {
        let errBuf = Buffer.from(message, 'utf8');
        socket.write(http400BadRequestMessage);
        socket.write('' + errBuf.length + '\r\n\r\n');
        socket.write(errBuf);
        socket.end("\r\n");
    }

    _createHTTPServer(callback) {
        let srv = http.createServer((req, res) => {
            this._handleIncomingRequest(req, res);
        })
        .on('close', () => {
            debuglog('HTTP server stopped.');
            njsp.stopListener(false, () => {
                debuglog('Socket pairer stopped.');
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
            console.error('Server error: ', e);
        })
        .once('error', callback);
        
        this._httpServer = srv;
        
        srv.listen(1234, 'localhost', 5, () => {
            srv.removeListener('error', callback);
            debuglog('HTTP server started');
            if(callback) {
                callback();
            }
        });
    }
    
    _handleConnectRequest(req, socket, head) {
        assert(req);
        assert(socket);
        
        let targetUrl = req.url;
        if(!targetUrl || !targetUrl.length) {
            this._reportBadRequest('No target host:port pair to connect to.', socket);
            return;
        }
        let [host, port] = req.url.split(':');
        if(!host) {
            this._reportBadRequest('No target host to connecto to.', socket);
            return;
        }
        if(!port) {
            port = 443;
        }
        debuglog('CONNECT request to: %s:%d.', host, port);
        
        // Wait for small (6 bytes) data chunk from the client to decice whether it wants to have SSL/TL or plain text connection.
        if(this._collectClientHello(socket, host, port, head)) {
            return;
        }
        console.log('Not enough client data to make a TLS/Plain decision.');

        let clientSocketConnectStateErrorCallback = (err) => {
            console.log('Client socket error: %s', err.stack);
        };
        
        socket.on('data', (data) => {
            head = this._combineDataBlocks(head, data);
            if(this._collectClientHello(socket, host, port, head)) {
                // Connect state error handler is not needed more - the proper one is installed by _emitConnectedClientSocket() method.
                socket.removeListener('error', clientSocketConnectStateErrorCallback);
                return;
            }
            console.log('Still not enough client data to make a TLS/Plain decision.');
        })
        .on('error', clientSocketConnectStateErrorCallback)
        .once('timeout', () => {
            socket.destroy(new Error('Timed out, waiting for client request.'));
        });
        
        console.log('Provoking client to start data transmission.');
        socket.write(http200ConnectedMessage);
    }
    
    _handleIncomingRequest(req, res) {
        var reqOptions;
        
        try {
            // Parse request target and append absent parts from CONNECT (if one was received) request parameters.
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
        
            debuglog('Incoming request for: %s//%s:%d%s', proto, host, port, path);

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
            this.emit('requestOptions', reqOptions);
            
            if(reqOptions === undefined || reqOptions === null) {
                throw new Error("Can not compose request to original server.");
            }

        } catch(e) {
            if(res.socket) {
                this._reportBadRequest(e.message, res.socket);
                return;
            }
            res.destroy(e);
            return;
        }

        // Submit request to original HTTP server.
        let requestor = reqOptions.proto == 'http:' ? http : https;
        let origReq = requestor.request(reqOptions, (origResp) => {
            
            console.log('statusCode:', origResp.statusCode);
            console.log('headers:', origResp.headers);
            
            this.emit('responseHeader', origResp);

            res.writeHead(origResp.statusCode, origResp.statusMessage, origResp.headers);
            
            origResp.on('data', (d) => {
                console.log('Writing to client response: %d.', d.length);
                this.emit('responseData', origResp, d);
                res.write(d);
                console.log('Wrote to client response: %d.', d.length);
            })
            .on('error', (e) => {
                console.error('Error in original response:', e);
            })
            .on('end', () => {
                console.log('No more data in response.');
                this.emit('responseFinish', origResp);
                res.end();
                console.log('Finished client response.');
            });
        })
        .on('error', (e) => {
            console.error(e);
            this.emit('requestError', origReq, e);
        })
        .on('abort', () => {
            this.emit('requestError', origReq, new Error('Aborted.'));
        });
        
        req.on('data', (d) => {
            console.log('Data in request.');
            origReq.write(d);
        })
        .on('error', (e) => {
            console.error('Error in request:', e);
            origRequest.abort();
        })
        .on('end', () => {
            console.log('Request completed.');
            origReq.end();
        });
    }
    
    _isSSLClientHello(tlsDetectBuff)
    {
        assert(tlsDetectBuff.length >= 6);
        
        // SSLv3
        if(tlsDetectBuff[0] == 0x16 && tlsDetectBuff[1] == 0x03 && tlsDetectBuff[5] == 0x01) {
            return true;
        }
        
        // SSLv2
        if((tlsDetectBuff[0] & 0x80) != 0 && tlsDetectBuff[2] == 0x01 && ((tlsDetectBuff_[0] & 0x7f) << 8 | tlsDetectBuff_[1]) > 9) {
            return true;
        }
        
        return false;
    }
    
    _emitConnectedClientSocket(socket, head, targetHost, targetPort, needsTLS)
    {
        /*
         * The following does not work (at least in Node.js v6.10.0 and v7.7.1) due to a "feature" of http server - it does not accept back sockets, already accepted.
         *
         let tlsSock = new tls.TLSSocket(socket);
         srv.emit('connection', tlsSock);
         *
         * As a workaround, an inter-connected UNIX/named-pipe socket pair is created and a "remote" end is fed back to the http server, while the "local" end is piped with TLS wrapper for the client socket.
         * TLS wrapper will be set on the "remote" side side of the socket pair.
         */
        
        njsp.socketpair((sp, err) => {
            console.log('In socketpair() callback.');
            
            if(!sp) {
                console.error(err);
                this._reportInternalError(err.stack, socket);
                return;
            }
            
            var targetSock;
            
            if(needsTLS) {
                let ctx = this._prepareSSLContext(targetHost, targetPort);
                if(ctx == undefined) {
                    console.error(err);
                    this._reportInternalError('SSL context allocation failed.', socket);
                    return;
                }
            
                targetSock = new tls.TLSSocket(sp.remoteSock, {
                    isServer : true,
                    requestCert : false,
                    rejectUnauthorized : false,
                    secureContext : ctx
                })
                .once('secure', () => {
                    console.log('TLS secureConnect.');
                    this._httpServer.emit('connection', targetSock);
                });
                targetSock._originTargetProto = 'https:';
            } else {
                targetSock = sp.remoteSock;
                targetSock._originTargetProto = 'http:';
            }

            targetSock._originTargetHost = targetHost;
            targetSock._originTargetPort = targetPort;

            targetSock.on('error', (e) => {
                console.error('TLS sock: ', e);
                socket.unpipe();
                sp.localSock.unpipe();
                targetSock.unpipe();
                
                sp.localSock.destroy(e);
                delete sp.localSock;
                delete sp.remoteSock;
                socket.destroy(e);
            })
            .on('close', () => {
                console.error('TLS sock: closed.');
            });
            
            sp.localSock.pipe(socket)
            .on('close', () => {
                console.error('Local piped socket closed.');
            })
            .on('error', (e) => {
                console.error('Local piped socket socket: ', e);
                sp.localSock.unpipe();
                targetSock.unpipe();
                socket.unpipe();
                
                socket.destroy();
                targetSock.destroy();
                delete sp.remoteSock;
                delete sp.localSock;
            });

            socket.pipe(sp.localSock)
            .on('close', () => {
                console.error('Client socket closed.');
            })
            .on('error', (e) => {
                console.error('Client socket: ', e);
                targetSock.unpipe();
                sp.localSock.unpipe();
                socket.unpipe();
                
                sp.localSock.destroy(e);
                delete sp.localSock;
                targetSock.destroy(e);
                delete sp.remoteSock;
            });

            sp.localSock.resume()
            targetSock.resume();
            
            if(!needsTLS) {
                this._httpServer.emit('connection', targetSock);
            }
            
            if(head && head.length) {
                sp.localSock.write(head);
            }
        });
    }
    
    _combineDataBlocks(head, data) {
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

    _collectClientHello(socket, host, port, head) {
        if(head.length < 6) {
            return false;
        }
        let needsTLS = this._isSSLClientHello(head);
        console.log('Analyzed collected 6 client bytes: ' + (needsTLS === true ? 'TLS client hello.' : 'plain text.'));
        socket.removeAllListeners('data');
        socket.removeAllListeners('error');
        this._emitConnectedClientSocket(socket, head, host, port, needsTLS);
        return true;
    }
};


let clientIdentityData = fs.readFileSync('client.identity');
let clientIdentity = njsx509.importPKCS12(clientIdentityData, 'ipad', 'der');
//console.log(clientIdentity);

let p = new TerminatingHTTPProxy(clientIdentity.certificate);
//p.caCertificate = clientIdentity.certificate;

//let ctx = p.prepareSSLContext('e1.ru', 443);
//assert(ctx);
//let ctx1 = p.prepareSSLContext('e1.ru', 443);
//assert(ctx1 === ctx);

p.start(() => {
    console.log('Proxy started.');
//    setTimeout(() => {
//        p.stop(() => {
//            console.log('Proxy stopped.');
//        });
//    }, 15000);
});

/*
 * Test with:
 * curl -x localhost:1234 -v https://www.google.com
 */


/*
CONNECT e1.ru:80 HTTP/1.1

GET / HTTP/1.1

*/
