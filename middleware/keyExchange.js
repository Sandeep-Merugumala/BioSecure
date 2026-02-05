const crypto = require('crypto');

class DHExchange {
    constructor() {
        // Use a standard group for demo purposes (modp14)
        // In a real scenario, this allows interoperability
        this.dh = crypto.createDiffieHellman(crypto.getDiffieHellman('modp14').getPrime(), crypto.getDiffieHellman('modp14').getGenerator());
        this.keys = null;
        this.secret = null;
    }

    generateKeys() {
        this.keys = this.dh.generateKeys();
        return this.dh.getPublicKey('hex');
    }

    getPrime() {
        return this.dh.getPrime('hex');
    }

    getGenerator() {
        return this.dh.getGenerator('hex');
    }

    getPrivateKey() {
        return this.dh.getPrivateKey('hex');
    }

    setPrivateKey(privateKeyHex) {
        this.dh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'));
        // Public key is not needed for secret computation, and not auto-generated
        // this.keys = this.dh.getPublicKey('hex');
    }

    computeSecret(otherPublicKeyHex) {
        try {
            const secret = this.dh.computeSecret(Buffer.from(otherPublicKeyHex, 'hex'));
            this.secret = secret.toString('hex');
            return this.secret;
        } catch (err) {
            console.error("Error computing secret:", err);
            return null;
        }
    }

    getSecret() {
        return this.secret;
    }
}

module.exports = DHExchange;
