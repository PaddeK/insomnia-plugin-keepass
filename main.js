const
    {createHash} = require('crypto'),
    Utils = require('./src/Utils'),
    _C = {...Utils.constants},
    isMacOS = process.platform === 'darwin',
    isWindows = process.platform === 'win32';

module.exports.templateTags = [{
    _error: false,
    _message: null,
    _actionHandler: null,
    name: 'keepass',
    displayName: 'Fetch from Keepass',
    description: 'Retrieve value from Keepass / KeepassXC',
    liveDisplayName: args => `${_C.KEEPASS_MAP[args[0].value]} - ${_C.FIELD_MAP[args[4].value]} of ${args[3].value}`,
    args: [
        {
            type: 'enum',
            displayName: `${_C.KEEPASS_MAP[_C.KEEPASS]} / ${_C.KEEPASS_MAP[_C.KEEPASSXC]}`,
            options: [
                {
                    displayName: _C.KEEPASS_MAP[_C.KEEPASS],
                    value: _C.KEEPASS,
                    description: 'Requires KeepassHttp plugin'
                },
                {
                    displayName: _C.KEEPASS_MAP[_C.KEEPASSXC],
                    value: _C.KEEPASSXC
                }
            ]
        },
        {
            type: 'string',
            displayName: 'KeepassHttp URL',
            help: `Leave empty for default value of ${_C.DEFAULT_KEEPASSHTTP_URL}`,
            placeholder: _C.DEFAULT_KEEPASSHTTP_URL,
            hide: args => args[0].value !== _C.KEEPASS
        },
        {
            type: 'file',
            displayName: 'Path to KeepassXC application',
            value: isMacOS ? '/Applications/' : '',
            itemTypes: ['file'],
            extensions: [].concat(isMacOS ? ['*.app'] : []).concat(isWindows ? ['*.exe'] : []),
            help: () => {
                if (isMacOS) {
                    return `Leave empty for default value of ${_C.DEFAULT_KEEPASSXC_MACOS}`
                }
                return 'Full path to keepassxc-proxy executable'
            },
            hide: args => args[0].value !== _C.KEEPASSXC
        },
        {
            type: 'string',
            displayName: 'Search URL',
            help: args => `URL to search ${_C.KEEPASS_MAP[args[0].value]} database for credentials`,
            validate: value => {
                if (!value) {
                    return 'Required';
                } else if (value.startsWith('_.')) {
                    return '';
                }

                try {
                    new URL(value);
                    return '';
                } catch (err) {
                    return 'Invalid URL';
                }
            }
        },
        {
            type: 'enum',
            displayName: 'Select entry field',
            defaultValue: _C.FIELD_PASSWORD,
            options: [
                {
                    displayName: 'Username',
                    value: _C.FIELD_USERNAME
                },
                {
                    displayName: 'Password',
                    value: _C.FIELD_PASSWORD
                }
            ]
        },
        {
            type: 'string',
            displayName: 'Filter entries by username'
        }
    ],
    actions: [
        {
            name: ' Create Database link',
            icon: 'fa fa-link',
            run: Utils.actionHandler(this, async function ({store}, which, host, file) {
                if (await Utils.associationExists(store)) {
                    this._error = true;
                    return 'Database link already established, you need to unlink first.';
                }

                try {
                    const
                        keepass = await Utils.createKeepassInstance({which, host, file}),
                        association = await keepass.associate();

                    await Utils.storeAssociation(store, association);
                    return 'Database link succesfully established.';
                } catch (err) {
                    this._error = true;
                    return 'Database link could not be established';
                }
            })
        },
        {
            name: ' Unlink Database',
            icon: 'fa fa-unlink',
            run: Utils.actionHandler(this, async function ({store}) {
                if (await Utils.associationExists(store)) {
                    await Utils.removeAssociation(store);
                    return 'Unlink database successful.';
                }
                this._error = true;
                return 'No database link established yet.'
            })
        }
    ],
    async run (context, which, host, file, url, field, filter) {
        const {store, renderPurpose} = context;

        host = which === _C.KEEPASS ? host || Utils.defaultHost : undefined;
        file = which === _C.KEEPASSXC ? (isMacOS ? file || Utils.defaultFile : file) : undefined;

        await Utils.handleActionHandler(this, {context, which, host, file, url, field});

        if (Utils.isValidUrl(url) === false) {
            throw new Error('Search URL must be a valid URL.');
        }

        if (renderPurpose === 'send') {
            const keepass = await Utils.createKeepassInstance({store, which, host, file});

            await keepass.testAssociate();

            const entries = await keepass.getCredentials(url, filter);

            if (entries.length) {
                return entries.pop()[field] || '';
            }
            throw new Error(`No entry found in database for search url ${url}`);
        }

        const
            refreshButton = Utils.getRefreshLivePreviewButton(),
            onRefresh = () => Utils.clearCache(store);

        if (refreshButton) {
            refreshButton.removeEventListener('click', onRefresh);
            refreshButton.addEventListener('click', onRefresh);
        }

        const hash = createHash('MD5').update(JSON.stringify({which, host, file, url, field})).digest('hex');
        let cachedResult = await store.getItem(hash);

        if (cachedResult === null) {
            if (await Utils.associationExists(store) === false) {
                throw new Error('No Database link established. You need to create a database link first.');
            } else {
                const keepass = await Utils.createKeepassInstance({store, which, host, file});

                if (await keepass.testAssociate() === false) {
                    throw new Error('Database link is invalid. Please try reastablish a link.');
                }

                const entries = await keepass.getCredentials(url, filter);
                cachedResult = entries.length.toString();

                await store.setItem(hash, cachedResult);
            }
        }

        if (~~cachedResult > 0) {
            return `${_C.KEEPASS_MAP[which]} - ${_C.FIELD_MAP[field]} of ${url}`;
        }

        throw new Error(`No entry found in database for search url ${url}`);
    }
}];
