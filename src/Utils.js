const
    Association = require('./model/Association'),
    Keepass = require('./Keepass'),
    KeepassXC = require('./KeepassXC'),
    CONSTANTS = {
        ASSOCIATION_KEY: 'association',
        FIELD_USERNAME: 'login',
        FIELD_PASSWORD: 'password',
        FIELD_GROUP: 'group',
        FIELD_ENTRY_NAME: 'name',
        FIELD_ADDITIONAL_ATTRIBUTE: 'stringFields',
        KEEPASS: 'keepass',
        KEEPASSXC: 'keepassxc',
        DEFAULT_KEEPASSHTTP_URL: Keepass.DEFAULT_URL.toString(),
        DEFAULT_KEEPASSXC_MACOS: '/Applications/KeePassXC.app',
        MACOS_PROXY: '/Contents/MacOS/keepassxc-proxy',
        LINUX_PROXY: '/usr/bin/keepassxc-proxy',
        KEEPASS_MAP: {
            keepass: 'Keepass',
            keepassxc: 'KeepassXC'
        },
        FIELD_MAP: {
            login: 'username',
            password: 'password',
            group: 'group',
            name: 'entry name'
        }
    },
    isMacOS = process.platform === 'darwin';
    isLinux = process.platform.toLowerCase().startsWith('linux');

class Utils
{
    static get constants ()
    {
        return CONSTANTS;
    }

    static get defaultFile ()
    {
        if(isMacOS) {
            return `${Utils.constants.DEFAULT_KEEPASSXC_MACOS}${Utils.constants.MACOS_PROXY}`
        } else if(isLinux) {
            return `${Utils.constants.LINUX_PROXY}`
        }
        return undefined
    }

    static get defaultHost ()
    {
        return Utils.constants.DEFAULT_KEEPASSHTTP_URL;
    }

    static async associationExists (store)
    {
        try {
            return await store.hasItem(Utils.constants.ASSOCIATION_KEY);
        } catch (err) {
            return false;
        }
    }

    static async loadAssociaton (store)
    {
        try {
            const association = JSON.parse(await store.getItem(Utils.constants.ASSOCIATION_KEY));
            return new Association(association.id, association.key, association.hash);
        } catch (err) {
            return undefined;
        }
    }

    static async storeAssociation (store, association)
    {
        try {
            await store.clear();
            await store.setItem(Utils.constants.ASSOCIATION_KEY, JSON.stringify(association));
        } catch (err) {
            throw new Error('Could not store database link.');
        }
    }

    static async removeAssociation (store)
    {
        try {
            await store.clear();
        } catch (err) {
            throw new Error('Could not unlink database.');
        }
    }

    static async clearCache (store)
    {
        try {
            const storeData = await store.all();

            for await (let {key} of storeData) {
                key !== Utils.constants.ASSOCIATION_KEY && await store.removeItem(key);
            }

            return true;
        } catch (err) {
            return false;
        }
    }

    static actionHandler (scope, callback)
    {
        return () => {
            scope.templateTags[0]._actionHandler = async function (...args) {
                this._actionHandler = null;
                return await callback.apply(this, args);
            };
        };
    }

    static isValidUrl (url)
    {
        if (!url) {
            return false;
        }

        try {
            new URL(url)
            return true;
        } catch (err) {
            return false;
        }
    }

    static async createKeepassInstance ({store, which, host, file})
    {
        const
            isKeepassXC = which === Utils.constants.KEEPASSXC,
            association = store ? await Utils.loadAssociaton(store) : undefined;

        return isKeepassXC ? new KeepassXC(file, association) : new Keepass(host, association);
    }

    static getRefreshLivePreviewButton ()
    {
        return window ? (window.document.querySelector('button > i.fa-refresh') || {}).parentElement : undefined;
    }

    static refreshLivePreview ()
    {
        (Utils.getRefreshLivePreviewButton() || {click: () => {}}).click();
    }

    static async handleActionHandler (scope, {context, which, host, file, url, field})
    {
        if (typeof scope._actionHandler === 'function') {
            scope._message = await scope._actionHandler(context, which, host, file, url, field);
            setTimeout(() => {
                scope._message = null;
                scope._error = false;
                Utils.refreshLivePreview();
            }, 3000);
        }

        if (scope._message !== null) {
            if (scope._error) {
                throw new Error(scope._message);
            }

            return scope._message;
        }
    }
}

module.exports = Utils;
