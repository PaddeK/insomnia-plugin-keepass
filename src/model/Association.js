class Association
{
    /**
     * @param {string} id
     * @param {string} key
     * @param {string} hash
     */
    constructor (id, key, hash)
    {
        this._id = id;
        this._key = key;
        this._hash = hash;
    }

    /**
     * @returns {string}
     */
    getId ()
    {
        return this._id;
    }

    /**
     * @returns {string}
     */
    getKey ()
    {
        return this._key;
    }

    /**
     * @returns {string}
     */
    getHash ()
    {
        return this._hash;
    }

    /**
     * @returns {{id: string, key: string, hash: string}}
     */
    toJSON ()
    {
        return  {
            id: this.getId(),
            key: this.getKey(),
            hash: this.getHash()
        };
    }
}

module.exports = Association;
