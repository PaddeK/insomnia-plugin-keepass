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

## Usage

1. In any input field press `CTRL+Space` and select `Fetch from Keepass -> KeepassXC`
2. For `Keepass` set `KeepassHttp URL`, for `KeepassXC` set `Path to KeepassXC application` if default values aren't correct
3. Enter `Search URL`
4. Select which `Entry field` to retrieve from Keepass 
5. For `KeepassXC` make sure to enable `Browser Integration`
6. Press `Create Database Link`, enter and confirm if KeepassXC shows popup to link database
7. Press `Refresh ⟳` to test

   _Note: The `Live Preview` will not show the secret value retrieved from Keepass, it is only used when e.g. sending in HTTP requests etc._
    

## Filtering

*Note*: **This is implemented only for KeePassXC**

If you have more than one entry associated with the `Search URL` in KeePass(XC), the first entry returned from Keepass is used.
You can optionally filter the retrieved entries:

1. Check `Filter entries by additional field?`
2. Choose a predefined `Filter Field` (e.g. `Username`) or a custom `Additional Attribute`

    _Note: For `Additional Attribute` the attribute has to have the format: "KPH: \<VALUE\>"_
3. Enter the `Field value` to filter by
