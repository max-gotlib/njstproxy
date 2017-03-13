const fs = require('fs');

const njsx509 = require('../../njsx509/lib/njsx509.js');
const njstproxy = require('../lib/NJSTProxy.js');

// Obtain an instance of CA certificate with a private key attached.
let clientIdentityData = fs.readFileSync('client.identity');
let clientIdentity = njsx509.importPKCS12(clientIdentityData, 'ipad', 'der');

// Prepare proxy configuration.
let proxyConfig = {
    ca: clientIdentity.certificate,
    address: '127.0.0.1',
    port: 1234,
    timeout: 45000
};

// Instantiate proxy.
let p = new njstproxy.TerminatingHTTPProxy(proxyConfig);

// Activate proxy.
p.start(() => {
    console.log('Proxy started.');
    /*
    // Schedule proxy termination.
    setTimeout(() => {
        p.stop(() => {
            console.log('Proxy stopped.');
        });
    }, 15000);
    */
});
