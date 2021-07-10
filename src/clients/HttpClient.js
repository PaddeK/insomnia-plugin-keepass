const
    DEFAULT_URL = new URL('http://localhost:19455'),
    DEFAULT_HEADERS = {accept: 'application/json', 'content-type': 'application/json'},
    {createDecipheriv, createCipheriv, randomBytes} = require('crypto'),
    fetch = require('node-fetch'),
    BaseClient = require('./BaseClient');

class HttpClient extends BaseClient
{
    /**
     * @returns {URL}
     * @constructor
     */
    static get DEFAULT_URL ()
    {
        return DEFAULT_URL;
    }

    /**
     * @returns {number}
     * @constructor
     */
    static get NONCE_SIZE ()
    {
        return 16;
    }

    /**
     * @param {URL|string} url
     */
    constructor (url = DEFAULT_URL)
    {
        super(HttpClient);

        this._url = url instanceof URL ? url : new URL(url);
        this._lastResponse = null;
    }

    get lastResponse ()
    {
        return this._lastResponse;
    }

    /**
     * @returns {string}
     */
    generateRandomKey ()
    {
        return randomBytes(32).toString('base64');
    }

    /**
     * @param {string} key
     * @param {string} iv
     * @param {string} payload
     * @returns {string}
     * @override
     */
    decrypt (key, iv, payload)
    {
        const civ = createDecipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
        return Buffer.concat([civ.update(Buffer.from(payload, 'base64')), civ.final()]).toString('utf8');
    }

    /**
     * @param {string} key
     * @param {string} iv
     * @param {string} payload
     * @returns {string}
     * @override
     */
    encrypt (key, iv, payload)
    {
        const civ = createCipheriv('aes-256-cbc', Buffer.from(key, 'base64'), Buffer.from(iv, 'base64'));
        return Buffer.concat([civ.update(Buffer.from(payload, 'utf8')), civ.final()]).toString('base64');
    }

    /**
     * @param {string} string
     * @returns {string}
     * @private
     */
    _camelCase (string)
    {
        const [first, ...rest] = string;
        return first.toLowerCase().concat(...rest);
    }

    /**
     * @param {object} obj
     * @returns {object}
     * @private
     */
    _camelCaseObjectKeys (obj)
    {
        if (typeof obj !== 'object') {
            return obj;
        }

        return Object.entries(obj).reduce((p, [k, v]) => {
            p[this._camelCase(k)] = Array.isArray(v) ? v.map(this._camelCaseObjectKeys.bind(this)) : v;
            return p;
        }, {});
    }

    /**
     * @param {{requestType: string, key: string, id?: string, url?: string}} request
     * @returns {Promise}
     */
    async request (request)
    {
        const
            method = 'POST',
            compress = false,
            {host} = this._url,
            nonce = this.generateNonce(),
            verifier = this.encrypt(request.key, nonce, nonce),
            url = request.url ? this.encrypt(request.key, nonce, request.url) : undefined,
            body = JSON.stringify({...request, url, nonce, verifier}),
            headers = Object.assign({}, DEFAULT_HEADERS, {...(host ? {host} : {})});
        let rawResponse;

        try {
            rawResponse = await fetch(this._url.toString(), {body, compress, method, headers});
        } catch (err) {
            throw new Error(`Fetch error: ${err}`);
        }

        if (!rawResponse.ok) {
            throw new Error(`Fetch error: ${rawResponse.status} ${rawResponse.statusText}`);
        }

        const response = this._camelCaseObjectKeys(await rawResponse.json());
        this._lastResponse = response;

        if (!response || !response.success || response.error) {
            throw new Error(`Response error: ${JSON.stringify(response, null, 4)}`);
        }

        return response;
    }
}

module.exports = HttpClient;