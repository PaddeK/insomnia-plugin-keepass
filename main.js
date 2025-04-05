const
    {createHash} = require('crypto'),
    Utils = require('./src/Utils'),
    _C = {...Utils.constants},
    isMacOS = process.platform === 'darwin',
    isWindows = process.platform === 'win32';
    isLinux = process.platform.toLowerCase().startsWith('linux');

function buildDisplayText(which, field, url, filter, filter_key, filter_value) {
    let text = `${_C.KEEPASS_MAP[which]} - ${_C.FIELD_MAP[field]} of Entry url: ${url}`
    if (filter === 'true') {
        text = text.concat(
            ` (filter: '${filter_key}' value: '${filter_value}')`)
    }
    return text
}

module.exports.templateTags = [{
    _error: false,
    _message: null,
    _actionHandler: null,
    name: 'keepass',
    displayName: 'Fetch from Keepass',
    description: 'Retrieve value from Keepass / KeepassXC',
    liveDisplayName: args => buildDisplayText(args[0].value, args[4].value,
        args[3].value, args[5].value, args[6].value, args[7].value),
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
            defaultValue: isMacOS ? '/Applications/' : isLinux ? _C.LINUX_PROXY : '',
            itemTypes: ['file'],
            extensions: [].concat(isMacOS ? ['*.app'] : []).concat(isWindows ? ['*.exe'] : []),
            help: () => {
                if (isMacOS) {
                    return `Leave empty for default value of ${_C.DEFAULT_KEEPASSXC_MACOS}`
                } else if (isLinux) {
                    return `Leave empty for default value of ${_C.LINUX_PROXY}`
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
                },
                {
                    displayName: 'Entry Name',
                    value: _C.FIELD_ENTRY_NAME
                },
                {
                    displayName: 'Group',
                    value: _C.FIELD_GROUP
                }
            ]
        },
        {
            type: 'boolean',
            displayName: 'Filter entries by field?',
            defaultValue: false,
            hide: args => args[0].value !== _C.KEEPASSXC
        },
        {
            type: 'enum',
            displayName: 'Filter Field',
            defaultValue: _C.FIELD_USERNAME,
            options: [
                {
                    displayName: 'Username',
                    value: _C.FIELD_USERNAME
                },
                {
                    displayName: 'Entry Name',
                    value: _C.FIELD_ENTRY_NAME
                },
                {
                    displayName: 'Group',
                    value: _C.FIELD_GROUP
                },
                {
                    displayName: 'Additional Attribute',
                    description: 'Name format: "KPH: \\<VALUE\\>"',
                    value: _C.FIELD_ADDITIONAL_ATTRIBUTE
                }
            ],
            hide: args => args[0].value !== _C.KEEPASSXC || args[5].value
                === false
        },
        {
            type: 'string',
            displayName: 'Field value',
            hide: args => args[0].value !== _C.KEEPASSXC || args[5].value
                === false
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
    async run(context, which, host, file, url, field, filter, filter_key,
        filter_value) {
        const {store, renderPurpose} = context;
        host = which === _C.KEEPASS ? host || Utils.defaultHost : undefined;
        file = which === _C.KEEPASSXC ? ((isMacOS || isLinux) ? file
            || Utils.defaultFile : file) : undefined;
        await Utils.handleActionHandler(this, {context, which, host, file, url, field});

        if (Utils.isValidUrl(url) === false) {
            throw new Error('Search URL must be a valid URL.');
        }
        if (renderPurpose === 'send') {
            const keepass = await Utils.createKeepassInstance({store, which, host, file});

            await keepass.testAssociate();

            entries = await keepass.getCredentials(url, filter, filter_key,
                filter_value);
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

        const hash = createHash('MD5').update(JSON.stringify({
            which,
            host,
            file,
            url,
            field,
            filter,
            filter_key,
            filter_value
        })).digest('hex');
        let cachedResult = await store.getItem(hash);

        if (cachedResult === null) {
            if (await Utils.associationExists(store) === false) {
                throw new Error('No Database link established. You need to create a database link first.');
            } else {
                const keepass = await Utils.createKeepassInstance({store, which, host, file});

                if (await keepass.testAssociate() === false) {
                    throw new Error(
                        'Database link is invalid. Please try re-establishing a link.');
                }

                entries = await keepass.getCredentials(url, filter, filter_key,
                    filter_value);
                cachedResult = entries.length.toString();

                await store.setItem(hash, cachedResult);
            }
        }

        if (~~cachedResult > 0) {
            return buildDisplayText(which, field, url, filter, filter_key,
                filter_value);
        }

        throw new Error(`No entry found in database for search url ${url}`);
    }
}];
