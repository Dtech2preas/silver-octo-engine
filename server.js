const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const { Server } = require('socket.io');
const net = require('net');
const url = require('url');
const tls = require('tls');
const { generateFakeCert } = require('./certUtils');

// Configuration
const DASHBOARD_PORT = 3000;
const PROXY_PORT = 8082;
const INTERNAL_HTTPS_PORT = 8443; // Virtual internal server port

// --- Dashboard Server ---
const app = express();
const dashboardServer = http.createServer(app);
const io = new Server(dashboardServer, {
    transports: ['polling'],
    allowUpgrades: false
});

app.use(express.static(path.join(__dirname, '../public')));

io.on('connection', (socket) => {
    // Client connected
});

app.get('/cert', (req, res) => {
    const certPath = path.join(__dirname, '../certs/rootCA.pem');
    res.download(certPath, 'D-TECH-Root-CA.pem');
});

function logTraffic(method, reqUrl, type, headers = {}, body = '') {
    const logEntry = {
        method,
        url: reqUrl,
        type,
        timestamp: new Date().toISOString(),
        headers,
        body
    };
    io.emit('log', logEntry);
    console.log(`[${type}] ${method} ${reqUrl}`);
}

function logDetailedRequest(method, reqUrl, type, headers, body) {
    console.log('\n================= INTERCEPTED REQUEST =================');
    console.log(`Time:    ${new Date().toISOString()}`);
    console.log(`Type:    ${type}`);
    console.log(`Method:  ${method}`);
    console.log(`URL:     ${reqUrl}`);
    console.log('--------------------- HEADERS -------------------------');
    console.log(JSON.stringify(headers, null, 2));
    if (body && body.length > 0) {
        console.log('---------------------- BODY ---------------------------');
        // If body is very long, maybe truncate for console, but for now capture all as requested
        console.log(body);
    }
    console.log('=======================================================\n');
}

dashboardServer.listen(DASHBOARD_PORT, '0.0.0.0', () => {
    console.log(`Dashboard running on http://0.0.0.0:${DASHBOARD_PORT}`);
});


// --- Internal HTTPS Server (MITM) ---
// This server receives the decrypted traffic, logs it, and forwards it to the real destination.

const internalHttpsServer = https.createServer({
    SNICallback: (domain, cb) => {
        console.log(`[DEBUG] SNICallback called for domain: ${domain}`);
        try {
            const { key, cert } = generateFakeCert(domain);
            const ctx = tls.createSecureContext({ key, cert });
            cb(null, ctx);
        } catch (err) {
            console.error('Error generating cert for SNI:', err);
            cb(err);
        }
    }
}, (req, res) => {
    let requestOptions = {};
    let urlForLogging = "";

    try {
        // Method 1: Try to build a standard URL object
        const targetUrlObj = new URL(req.url, `https://${req.headers.host}`);
        urlForLogging = targetUrlObj.toString();
        
        // If successful, use the URL object and merge options
        requestOptions = {
            hostname: targetUrlObj.hostname,
            port: targetUrlObj.port || 443,
            path: targetUrlObj.pathname + targetUrlObj.search,
            method: req.method,
            headers: req.headers,
            rejectUnauthorized: false
        };

    } catch (err) {
        // Method 2: Fallback for weird URLs (like //v1:checkClientOptions)
        // We manually construct options to prevent https.request from crashing
        console.warn('Invalid URL encountered, using Manual Mode:', req.url);
        urlForLogging = req.url;

        const hostHeader = req.headers.host || "";
        const [hostname, port] = hostHeader.split(':');

        requestOptions = {
            hostname: hostname,
            port: port || 443,
            path: req.url, // Send the raw weird path exactly as received
            method: req.method,
            headers: req.headers,
            rejectUnauthorized: false
        };
    }

    // 1. Log immediately so we see the traffic start
    logTraffic(req.method, urlForLogging, 'HTTPS-DECRYPTED', req.headers, '[Waiting for body...]');

    // 2. Capture Body for detailed inspection
    let reqBodyChunks = [];
    req.on('data', (chunk) => {
        reqBodyChunks.push(chunk);
    });

    req.on('end', () => {
        const bodyBuffer = Buffer.concat(reqBodyChunks);
        let bodyStr = bodyBuffer.toString('utf8');

        // Log the detailed view to Console (for script generation)
        // We don't emit to socket again to avoid double-entry in dashboard,
        // unless you want updates. For now, we ensure console gets the good stuff.
        logDetailedRequest(req.method, urlForLogging, 'HTTPS-DECRYPTED', req.headers, bodyStr);
    });

    // Make the request using the safe options object
    const proxyReq = https.request(requestOptions, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
        console.error('HTTPS Forwarding Error:', err);
        // Don't crash, just end the response
        if (!res.headersSent) {
            res.statusCode = 502;
            res.end('Bad Gateway');
        }
    });

    req.pipe(proxyReq);
});

internalHttpsServer.on('tlsClientError', (err, tlsSocket) => {
    console.error('[DEBUG] TLS Client Error on Internal Server:', err.message, err.code);
});

internalHttpsServer.on('secureConnection', (tlsSocket) => {
    console.log('[DEBUG] Secure connection established with client.');
});

internalHttpsServer.on('error', (err) => {
    console.error('[DEBUG] Internal HTTPS Server Error:', err);
});

internalHttpsServer.listen(INTERNAL_HTTPS_PORT, '127.0.0.1', () => {
    console.log(`Internal MITM HTTPS Server running on 127.0.0.1:${INTERNAL_HTTPS_PORT}`);
});


// --- Main Proxy Server ---
const proxyServer = http.createServer((req, res) => {
    // Handle standard HTTP requests

    // 1. Log immediately
    logTraffic(req.method, req.url, 'HTTP', req.headers, '[Waiting for body...]');

    // 2. Capture Body
    let reqBodyChunks = [];
    req.on('data', (chunk) => {
        reqBodyChunks.push(chunk);
    });

    req.on('end', () => {
        const bodyStr = Buffer.concat(reqBodyChunks).toString('utf8');
        logDetailedRequest(req.method, req.url, 'HTTP', req.headers, bodyStr);
    });

    const parsedUrl = url.parse(req.url);
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 80,
        path: parsedUrl.path,
        method: req.method,
        headers: req.headers
    };

    const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
        console.error('HTTP Proxy Error:', err);
        if (!res.headersSent) {
            res.statusCode = 502;
            res.end('Bad Gateway');
        }
    });

    req.pipe(proxyReq);
});

// Handle HTTPS CONNECT
proxyServer.on('connect', (req, clientSocket, head) => {
    const { port, hostname } = url.parse(`//${req.url}`, false, true);

    logTraffic('CONNECT', req.url, 'HTTPS-INIT');

    // Connect to our internal MITM server
    // We treat the internal server as the destination for the tunnel
    console.log(`[DEBUG] Tunneling to internal server for ${req.url}. Head size: ${head.length}`);
    const proxySocket = net.connect(INTERNAL_HTTPS_PORT, '127.0.0.1', () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

        // Pipe the client's SSL handshake to our internal server
        // The internal server will see the SNI and generate the cert
        if (head.length > 0) proxySocket.write(head);
        clientSocket.pipe(proxySocket).pipe(clientSocket);
    });

    proxySocket.on('error', (err) => {
        console.error('Proxy Socket Error:', err);
        clientSocket.end();
    });

    clientSocket.on('error', (err) => {
        console.error('Client Socket Error:', err);
        proxySocket.end();
    });
});

proxyServer.listen(PROXY_PORT, '0.0.0.0', () => {
    console.log(`D-TECH Proxy running on 0.0.0.0:${PROXY_PORT}`);
});
