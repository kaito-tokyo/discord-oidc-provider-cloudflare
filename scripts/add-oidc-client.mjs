import crypto from 'crypto';
import { execSync } from 'child_process';

import readline from 'readline';

function generateRandomNumberString(length) {
    let result = '';
    for (let i = 0; i < length; i++) {
        result += Math.floor(Math.random() * 10);
    }
    return result;
}

function generateRandomAlphanumeric(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomBytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
        result += chars[randomBytes[i] % chars.length];
    }
    return result;
}

async function getRedirectUris() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const redirectUris = [];
    console.log('Enter redirect URIs (press Enter on an empty line to finish):');
    while (true) {
        const uri = await new Promise(resolve => rl.question('Redirect URI: ', resolve));
        if (uri === '') {
            break;
        }
        redirectUris.push(uri);
    }
    rl.close();
    return redirectUris;
}

async function main() {
    const clientId = generateRandomNumberString(32);
    const clientSecret = generateRandomAlphanumeric(64);

    const clientSecretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');
    const redirectUris = await getRedirectUris();

    const kvValue = JSON.stringify({
        client_secret_hash: clientSecretHash,
        redirect_uris: redirectUris
    });

    try {
        // Use wrangler CLI to put the key-value pair into the OIDC_CLIENTS KV namespace
        // The --binding flag is used to specify the KV namespace binding name
        // The --json flag ensures the value is treated as JSON
        const command = `npx wrangler kv key put --binding=OIDC_CLIENTS --env=production --remote "${clientId}" '${kvValue}'`;
        console.log(`Executing command: ${command}`);
        execSync(command, { stdio: 'inherit' });
        console.log('Client added to KV store successfully.');
        console.log(`Client ID: ${clientId}`);
        console.log(`Client Secret: ${clientSecret}`);
    } catch (error) {
        console.error('Failed to add client to KV store:', error.message);
        process.exit(1);
    }
}

main();
