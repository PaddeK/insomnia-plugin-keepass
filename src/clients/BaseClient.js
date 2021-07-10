const
    {randomBytes} = require('crypto'),
    Action = {
        ASSOCIATE: 'associate',
        CHANGE_PUBLIC_KEYS: 'change-public-keys',
        CREDENTIALS: 'get-logins',
        GET_DATABASE_HASH: 'get-databasehash',
        TEST_ASSOCIATE: 'test-associate'
    };

class BaseClient
{
    /**
     * @returns {{
     *     CREDENTIALS: string,
     *     CHANGE_PUBLIC_KEYS: string,
     *     TEST_ASSOCIATE: string,
     *     ASSOCIATE: string,
     *     GET_DATABASE_HASH: string
     * }}
     * @constructor
     */
    static get Action ()
    {
        return Action;
    }

    constructor (_class)
    {
        this._class = _class
    }

    /**
     * @returns {string}
     */
    generateNonce ()
    {
        return randomBytes(this._class.NONCE_SIZE).toString('base64');
    }

    encrypt ()
    {
        throw new ReferenceError('encrypt needs to be implemented');
    }

    decrypt ()
    {
        throw new ReferenceError('decrypt needs to be implemented');
    }
}

module.exports = BaseClient;