const path = require('path');
const fs = require('fs');

let dbSync = null;

function getDbInstance() {
    if (dbSync) return { db: dbSync };

    try {
        const { DatabaseSync } = require('node:sqlite');

        // If running from an ASAR package, __dirname will contain 'app.asar'
        // In that case, we need to locate the unpacked extraResources folder.
        const isPackaged = __dirname.includes('app.asar');

        const dbPath = isPackaged
            ? path.join(process.resourcesPath, 'oui-database.sqlite')
            : path.join(__dirname, '..', 'oui-database.sqlite');

        if (!fs.existsSync(dbPath)) {
            return { error: `DB not found at ${dbPath}` };
        }

        dbSync = new DatabaseSync(dbPath, { readOnly: true });
        return { db: dbSync };
    } catch (error) {
        console.error('Failed to load node:sqlite database:', error.message);
        return { error: error.message };
    }
}

function normalizeMac(mac) {
    if (!mac) return '';
    // Remove all non-hex characters
    const cleaned = mac.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
    if (cleaned.length < 6) return '';
    // Return the first 6 characters (OUI)
    return cleaned.substring(0, 6);
}

function lookupMac(macString) {
    try {
        const oui = normalizeMac(macString);
        if (!oui || oui.length !== 6) {
            return { ok: false, error: 'Invalid MAC address format (must contain at least 6 hex characters).' };
        }

        const dbStatus = getDbInstance();
        if (dbStatus.error) {
            return { ok: false, error: `MAC SQLite Error: ${dbStatus.error}` };
        }
        const db = dbStatus.db;

        // Convert the 6-char hex prefix to an integer for the vendordb lookup.
        const macInt = parseInt(oui, 16);

        // Prepare statement to query by integer prefix.
        const stmt = db.prepare('SELECT vendor FROM vendordb WHERE mac = ? LIMIT 1');
        const result = stmt.get(macInt);

        if (result) {
            return {
                ok: true,
                normalized: {
                    mac: macString,
                    oui: oui,
                    vendorName: result.vendor
                },
                rawOutput: `MAC Address: ${macString}\nOUI Prefix: ${oui}\nVendor Name: ${result.vendor}`
            };
        }

        return {
            ok: true,
            normalized: {
                mac: macString,
                oui: oui,
                vendorName: 'Unknown Vendor'
            },
            rawOutput: `MAC Address: ${macString}\nOUI Prefix: ${oui}\nVendor Name: Unknown (No match in database)`
        };

    } catch (err) {
        return { ok: false, error: err.message || 'SQLite query failed.' };
    }
}

module.exports = {
    lookupMac
};
