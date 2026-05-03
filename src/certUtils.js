const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, '../certs');
const caKeyPath = path.join(certsDir, 'rootCA.key');
const caCertPath = path.join(certsDir, 'rootCA.pem');

// Ensure certs directory exists
if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
}

let caKey;
let caCert;

function initCA() {
    if (fs.existsSync(caKeyPath) && fs.existsSync(caCertPath)) {
        console.log('Loading existing D-TECH Root CA...');
        const keyPem = fs.readFileSync(caKeyPath, 'utf8');
        const certPem = fs.readFileSync(caCertPath, 'utf8');
        caKey = forge.pki.privateKeyFromPem(keyPem);
        caCert = forge.pki.certificateFromPem(certPem);
    } else {
        console.log('Generating new D-TECH Root CA...');
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const cert = forge.pki.createCertificate();

        cert.publicKey = keys.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

        const attrs = [{
            name: 'commonName',
            value: 'D-TECH Root CA'
        }, {
            name: 'organizationName',
            value: 'D-TECH'
        }];

        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        cert.setExtensions([{
            name: 'basicConstraints',
            cA: true
        }]);

        // Self-sign
        cert.sign(keys.privateKey, forge.md.sha256.create());

        caKey = keys.privateKey;
        caCert = cert;

        fs.writeFileSync(caKeyPath, forge.pki.privateKeyToPem(caKey));
        fs.writeFileSync(caCertPath, forge.pki.certificateToPem(caCert));
        console.log('D-TECH Root CA generated and saved.');
    }
}

// Initialize on load
initCA();

function generateFakeCert(hostname) {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{
        name: 'commonName',
        value: hostname
    }, {
        name: 'organizationName',
        value: 'D-TECH API-Fier Proxy'
    }];

    cert.setSubject(attrs);
    // Issuer is the Root CA
    cert.setIssuer(caCert.subject.attributes);

    cert.setExtensions([{
        name: 'basicConstraints',
        cA: false
    }, {
        name: 'keyUsage',
        keyCertSign: false,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
    }, {
        name: 'subjectAltName',
        altNames: [{
            type: 2, // DNS
            value: hostname
        }]
    }]);

    // Sign with Root CA
    cert.sign(caKey, forge.md.sha256.create());

    return {
        key: forge.pki.privateKeyToPem(keys.privateKey),
        cert: forge.pki.certificateToPem(cert)
    };
}

module.exports = {
    generateFakeCert,
    caCertPath // Export path if needed
};
