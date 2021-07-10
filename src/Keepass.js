const
    HttpClient = require('./clients/HttpClient'),
    Association = require('./model/Association');

class Keepass
{
    /**
     * @param {URL|string} url
     * @param {Association|null} association
     */
    constructor (url = HttpClient.DEFAULT_URL, association = null)
    {
        this._client = new HttpClient(url);
        this._association = association;
    }

    static get DEFAULT_URL ()
    {
        return HttpClient.DEFAULT_URL;
    }

    /**
     * @returns {Promise<string|null>}
     */
    async getDatabaseHash ()
    {
        try {
            await this._client.request({
                requestType: HttpClient.Action.TEST_ASSOCIATE,
                key: this._client.generateRandomKey()
            });

            return this._client.lastResponse.hash || null;
        } catch (err) {
            return this._client.lastResponse.hash || null;
        }
    }

    /**
     * @returns {Promise<boolean>}
     */
    async testAssociate ()
    {
        try {
            if (this._association === null) {
                return false;
            }

            const response = await this._client.request({
                requestType: HttpClient.Action.TEST_ASSOCIATE,
                id: this._association.getId(),
                key: this._association.getKey()
            });

            return this._association.getId() === response.id && response.success === true;
        } catch (err) {
            return false;
        }
    }

    /**
     * @returns {Promise<Association>}
     */
    async associate ()
    {
        try {
            const
                key = this._client.generateRandomKey(),
                response = await this._client.request({requestType: HttpClient.Action.ASSOCIATE, key});

            if (response.success === true) {
                this._association = new Association(response.id, key, response.hash);
                return this._association;
            }

            return Promise.reject(new Error(`Associate request failed: ${response.error}`));
        } catch (err) {
            return Promise.reject(new Error(`Associate request failed: ${err}`));
        }
    }

    /**
     * @param {string|URL} url
     * @returns {Promise<[{password: string, name: string, login: string, uuid: string}]>}
     */
    async getCredentials (url)
    {
        try {
            const
                key = this._association.getKey(),
                response = await this._client.request({
                    requestType: HttpClient.Action.CREDENTIALS,
                    id: this._association.getId(),
                    key: this._association.getKey(),
                    url: url.toString()
                });

            (response.entries || []).forEach(entry => {
                entry.name = this._client.decrypt(key, response.nonce, entry.name);
                entry.login = this._client.decrypt(key, response.nonce, entry.login);
                entry.password = this._client.decrypt(key, response.nonce, entry.password);
                entry.uuid = this._client.decrypt(key, response.nonce, entry.uuid);
            });

            return response.entries || [];
        } catch (err) {
            return [];
        }
    }
}

module.exports = Keepass;
