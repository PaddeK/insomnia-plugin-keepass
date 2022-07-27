# Insomnia plugin for fetching credentials from Keepass and KeepassXC

Access your Keepass or KeepassXC database to fetch credentials via this custom template tag plugin.

## Pre-requisites

This plugin requires [Insomnia](https://insomnia.rest/).  
To access Keepass databases the KeepassHttp plugin needs to be installed.

## Installation

1. Start Insomnia,
2. Click "Preferences" and choose the "Plugins" tab,
3. Enter `insomnia-plugin-keepass` and click "Install Plugin"
4. Close the dialog.

## Filtering

*Note*: **This is implemented only for KeePassXC**

If you have more than one entry associated in KeePass(XC) with the same URL, the
original plugin was just using the first entry from the list.

This version allows to (optionally) filter the returned KeePass(XC) entries.
To do so:

- Check `Filter entries by additional attribute?`
- Fill in the `Attribute name (KPH:)` field.

The only entries returned will be the ones that include the additional attribute
`KPH: \<attribute field value\>`.
