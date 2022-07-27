const
    child_process = require("child_process"),
    nacl = require('tweetnacl'),
    NativeMessageClient = require('./clients/NativeMessageClient'),
    Association = require('./model/Association');

class KeepassXC
{
    /**
     * @param {string} proxyPath
     * @param {Association|null} association
     * @private
     */
    constructor (proxyPath, association = null)
    {
        this._client = new NativeMessageClient(proxyPath);
        this._keyPair = nacl.box.keyPair();
        this._clientID = Buffer.from(nacl.randomBytes(NativeMessageClient.NONCE_SIZE)).toString('base64');
        this._association = association;
        this._serverPublicKey = null;
    }

    /**
     * @returns {Promise<null|string>}
     */
    async getDatabaseHash ()
    {
        try {
            this._client.connect();

            if (!await this._verifyKeys()) {
                return null;
            }

            const response = await this._sendMessage(NativeMessageClient.Action.GET_DATABASE_HASH);

            if (!response.success) {
                return null;
            }

            return response.hash;
        } catch(err) {
            return null;
        } finally {
            this._client.disconnect();
        }
    }

    /**
     * @returns {Promise<Association>}
     */
    async associate ()
    {
        let response;
        try {
            this._client.connect();

            if (!await this._verifyKeys()) {
                return Promise.reject(new Error(`Could not verify keys`));
            }

            const
                associateKeyPair = nacl.box.keyPair(),
                idKey = Buffer.from(associateKeyPair.publicKey).toString('base64');

            response = await this._sendMessage(NativeMessageClient.Action.ASSOCIATE, null, {
                key: Buffer.from(this._keyPair.publicKey).toString('base64'),
                idKey
            });

            this._association = new Association(response.id, idKey, response.hash);

            return this._association;
        } catch (err) {
            return Promise.reject(new Error(`Associate request failed: ${response.error}`));
        } finally {
            this._client.disconnect();
        }
    }

    /**
     * @returns {Promise<null|boolean>}
     */
    async testAssociate ()
    {
        try {
            this._client.connect();

            if (!await this._verifyKeys() || this._association === null) {
                return false;
            }

            const response = await this._sendMessage(
                NativeMessageClient.Action.TEST_ASSOCIATE,
                2000,
                this._association.toJSON()
            );

            return response.success;
        } catch (err) {
            return false;
        } finally {
            this._client.disconnect();
        }
    }

    /**
     * @param {string|URL} url
     * @param {boolean} filter
     * @param {string} filter_attr
     * @returns {Promise<null|[]>}
     */
    async getCredentials (url, filter, filter_attr)
    {
        try {
            this._client.connect();

            function filterAttr(entry) {
                return entry['stringFields'].some(f => JSON.stringify(f).includes(filter_attr));
            }

            if (!await this._verifyKeys()) {
                return [];
            }

            const response = await this._sendMessage(NativeMessageClient.Action.CREDENTIALS, null, {
                url: url.toString(),
                keys: [this._association.toJSON()]
            });

            if (filter) {
                return response.entries.filter(filterAttr);
            }

            return response.entries;
        } catch (err) {
            return [];
        } finally {
            this._client.disconnect();
        }
    }

    /**
     * @param {object} response
     * @param {string} expectedNonce
     * @returns {boolean}
     * @private
     */
    _verifyKeyResponse (response, expectedNonce)
    {
        if (!this._client.verifyMessage(response, expectedNonce) || !response.success || !response.publicKey) {
            return false;
        }

        if (response.publicKey) {
            this._serverPublicKey = new Uint8Array(Buffer.from(response.publicKey, 'base64'));
            return true;
        }

        return false
    }

    /**
     * @param {string} clientID
     * @param {string} publicKey
     * @returns {Promise<boolean>}
     * @private
     */
    async _changePublicKeys (clientID, publicKey)
    {
        const
            nonce = this._client.generateNonce(),
            incNonce = this._client.incrementedNonce(nonce),
            request = {action: NativeMessageClient.Action.CHANGE_PUBLIC_KEYS, publicKey, nonce, clientID};

        await this._client.sendMessage(request);

        let response;

        do {
            response = await this._client.readMessage();
        } while (response.action !== NativeMessageClient.Action.CHANGE_PUBLIC_KEYS);

        return this._verifyKeyResponse(response, incNonce);
    }

    /**
     * @returns {Promise<boolean>}
     * @private
     */
    async _verifyKeys ()
    {
        if (!this._serverPublicKey) {
            const publicKey = Buffer.from(this._keyPair.publicKey).toString('base64');

            if (!await this._changePublicKeys(this._clientID, publicKey)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param {string} action
     * @param {number|null} timeout
     * @param {object} message
     * @returns {Promise<any>}
     * @private
     */
    async _sendMessage (action, timeout = 120000, message = null)
    {
        const
            nonce = this._client.generateNonce(),
            incNonce = this._client.incrementedNonce(nonce);

        let messageData = {action};

        if (message !== null) {
            messageData = Object.assign(messageData, message);
        }

        const encrypted = this._client.encrypt(messageData, nonce, this._serverPublicKey, this._keyPair.secretKey);

        if (encrypted.length <= 0) {
            throw new Error('Encryption failed!');
        }

        const request = {action, message: encrypted, nonce, clientID: this._clientID};

        await this._client.sendMessage(request);

        let response;

        do {
            response = await this._client.readMessage(timeout);
        } while (response.action !== action);

        if (response.message && response.nonce) {
            const decryptedRes = this._client.decrypt(
                response.message,
                response.nonce,
                this._serverPublicKey,
                this._keyPair.secretKey
            );

            if (!decryptedRes) {
                throw new Error('Decryption failed!');
            }

            const
                message = this._client.encodeUTF8(decryptedRes),
                parsed = JSON.parse(message);

            if (!this._client.verifyMessage(parsed, incNonce)) {
                throw new Error('Message verification failed!');
            }

            return parsed;
        } else if (response.error) {
            throw new Error(`Action failed with code ${response.errorCode || '<Unspecified>'}: ${response.error}`);
        } else {
            throw new Error('Response missed important fields!');
        }
    }
}

module.exports = KeepassXC;
