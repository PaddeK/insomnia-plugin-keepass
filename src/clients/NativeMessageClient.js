const
    {endianness} = require('os'),
    child_process = require("child_process"),
    nacl = require('tweetnacl'),
    BaseClient = require('./BaseClient');

class NativeMessageClient extends BaseClient
{
    /**
     * @returns {number}
     * @constructor
     */
    static get NONCE_SIZE ()
    {
        return 24;
    }

    /**
     * @param {string} path
     */
    constructor (path)
    {
        super(NativeMessageClient);

        this._connected = false;
        this._process = null;
        this._path = path;
    }

    /**
     * @returns {boolean}
     */
    get connected ()
    {
        return this._connected;
    }

    connect ()
    {
        if (!this._connected) {
            this._messageQueue = [];
            this._readQueue = [];
            this._remainingMessageSize = 0;
            this._incompleteMessage = '';
            this._process = child_process.spawn(this._path);

            this._process.on('error', () => this._connected = false);
            this._process.on('close', () => this._connected = false);
            this._process.on('exit', () => this._connected = false);

            this._process.stdout.on('data', this._onData.bind(this));
            this._connected = true;
        }
    }

    disconnect ()
    {
        if (this._connected || this._process !== null) {
            this._process.stdout.off('data', this._onData.bind(this));
            this._process.kill('SIGKILL');
            this._process = null;
            this._connected = false;
        }
    }

    /**
     * @param {Buffer} chunk
     * @private
     */
    _onData (chunk)
    {
        this._messageQueue.push(chunk);
        this._processMessageQueue();
    }

    /**
     * @param {string} string
     * @returns {Uint8Array}
     * @private
     */
    _decodeUTF8 (string)
    {
        if (typeof string !== 'string') {
            throw new TypeError('expected string');
        }

        let i, d = unescape(encodeURIComponent(string)), b = new Uint8Array(d.length);

        for (i = 0; i < d.length; i++) {
            b[i] = d.charCodeAt(i);
        }

        return b;
    }

    /**
     * @param {string} nonce
     * @returns {boolean}
     * @private
     */
    _checkNonceLength (nonce)
    {
        return new Uint8Array(Buffer.from(nonce, 'base64')).length === nacl.secretbox.nonceLength;
    }

    /**
     * @param {Writable} stream
     * @param {Buffer|string|Uint8Array} chunk
     * @param {string} encoding
     * @returns {Promise}
     * @private
     */
    _writeToStream (stream, chunk, encoding = 'utf8')
    {
        return new Promise((ok, nok) => {
            const errorHandler = err => {
                // noinspection JSCheckFunctionSignatures
                stream.removeListener('error', errorHandler);
                nok(err);
            };

            // noinspection JSCheckFunctionSignatures
            stream.addListener('error', errorHandler);

            // noinspection JSCheckFunctionSignatures
            stream.write(chunk, encoding, () => {
                // noinspection JSCheckFunctionSignatures
                stream.removeListener('error', errorHandler);
                ok();
            });
        });
    }

    /**
     * @param {Buffer} buffer
     * @param {number} offset
     * @returns {number}
     * @private
     */
    _readUint32 (buffer, offset)
    {
        return endianness() === 'BE' ? buffer.readUInt32BE(offset) : buffer.readUInt32LE(offset);
    }

    /**
     * @param {Buffer} buffer
     * @param {number} value
     * @param {number} offset
     * @returns {number}
     * @private
     */
    _writeUint32 (buffer, value, offset)
    {
        return endianness() === 'BE' ? buffer.writeUInt32BE(value, offset) : buffer.writeUInt32LE(value, offset);
    }

    /**
     * @param {string} data
     * @private
     */
    _dispatchMessage (data)
    {
        const callback = this._readQueue.shift();
        callback(JSON.parse(data));
    }

    /**
     * @private
     */
    _processMessageQueue ()
    {
        if (!this._readQueue.length || !this._messageQueue.length) {
            return;
        }

        while (this._messageQueue.length > 0 && this._readQueue.length) {
            /** @var {Buffer} buffer */
            const buffer = this._messageQueue[0];

            if (this._remainingMessageSize > 0) {
                if (buffer.length >= this._remainingMessageSize) {
                    this._incompleteMessage += buffer.toString('utf8', 0, this._remainingMessageSize);
                    this._dispatchMessage(this._incompleteMessage);

                    if (buffer.length > this._remainingMessageSize) {
                        this._messageQueue[0] = buffer.slice(this._remainingMessageSize);
                    } else {
                        this._messageQueue.shift();
                    }

                    this._remainingMessageSize = 0;
                    this._incompleteMessage = null;
                } else {
                    this._incompleteMessage += buffer.toString('utf8');
                    this._remainingMessageSize -= buffer.length;
                    this._messageQueue.shift();
                }
            } else {
                const messageLen = this._readUint32(buffer, 0);

                if (messageLen + 4 >= buffer.length) {
                    const messageStr = buffer.toString('utf8', 4, 4 + messageLen);
                    this._dispatchMessage(messageStr);

                    if (messageLen + 4 > buffer.length) {
                        this._messageQueue[0] = buffer.slice(messageLen + 4);
                    } else {
                        this._messageQueue.shift();
                    }
                } else {
                    this._incompleteMessage = buffer.toString('utf8', 4);
                    this._remainingMessageSize = messageLen - (buffer.length - 4);
                    this._messageQueue.shift();
                }
            }
        }
    }

    /**
     * @returns {string}
     */
    generateNonce ()
    {
        return Buffer.from(nacl.randomBytes(NativeMessageClient.NONCE_SIZE)).toString('base64');
    }

    /**
     * @param input
     * @param nonce
     * @param serverPublicKey
     * @param privateKey
     * @returns {Uint8Array}
     */
    decrypt (input, nonce, serverPublicKey, privateKey)
    {
        const
            m = new Uint8Array(Buffer.from(input, 'base64')),
            n = new Uint8Array(Buffer.from(nonce, 'base64'));

        return nacl.box.open(m, n, serverPublicKey, privateKey);
    }

    /**
     * @param input
     * @param nonce
     * @param serverPublicKey
     * @param privateKey
     * @returns {string}
     */
    encrypt (input, nonce, serverPublicKey, privateKey)
    {
        const
            messageData = this._decodeUTF8(JSON.stringify(input)),
            messageNonce = new Uint8Array(Buffer.from(nonce, 'base64'));

        if (serverPublicKey) {
            const message = nacl.box(messageData, messageNonce, serverPublicKey, privateKey);

            if (message) {
                return Buffer.from(message).toString('base64');
            }
        }

        return '';
    }

    /**
     * @param {Uint8Array} arr
     * @returns {string}
     */
    encodeUTF8 (arr)
    {
        let i, s = [];

        for (i = 0; i < arr.length; i++) {
            s.push(String.fromCharCode(arr[i]));
        }

        return decodeURIComponent(escape(s.join('')));
    }

    /**
     * @param {string} nonce
     * @returns {string}
     */
    incrementedNonce (nonce)
    {
        const oldNonce = new Uint8Array(Buffer.from(nonce, 'base64'));
        let newNonce = oldNonce.slice(0);

        for (let i = 0, c = 1; i < newNonce.length; ++i) {
            c += newNonce[i];
            newNonce[i] = c;
            c >>= 8;
        }

        return Buffer.from(newNonce).toString('base64');
    }

    /**
     * @param {object} message
     * @param {string} expectedNonce
     * @returns {boolean|boolean}
     */
    verifyMessage (message, expectedNonce)
    {
        return this._checkNonceLength(message.nonce) ? message.nonce === expectedNonce : false;
    }

    /**
     * @param {*} message
     * @returns {Promise}
     */
    async sendMessage (message)
    {
        const
            json = JSON.stringify(message, null, 0),
            messageLen = Buffer.byteLength(json, 'utf8'),
            messageBuffer = Buffer.alloc(messageLen + 4);

        this._writeUint32(messageBuffer, messageLen, 0);
        messageBuffer.write(json, 4, 'utf8');

        await this._writeToStream(this._process.stdin, messageBuffer);
    }

    /**
     * @param {number|undefined} [timeoutMs]
     * @returns {Promise}
     */
    readMessage (timeoutMs = undefined)
    {
        return new Promise((ok, nok) => {
            if (timeoutMs) {
                const timeoutId = setTimeout(() => {
                    const index = this._readQueue.indexOf(ok);

                    if (index >= 0) {
                        this._readQueue.splice(index, 1);
                    }

                    nok('Timeout reached');
                }, timeoutMs);

                this._readQueue.push(x => {
                    clearTimeout(timeoutId);
                    ok(x);
                });
            } else {
                this._readQueue.push(ok);
            }

            this._processMessageQueue();
        });
    }
}

module.exports = NativeMessageClient;
