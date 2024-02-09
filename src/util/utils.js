const EC = require('elliptic').ec;
// const base64url = require('base64-');
const {ethers} = require('ethers');
const ECDSASigValue =  require('@peculiar/asn1-ecc').ECDSASigValue;
const AsnParser =  require('@peculiar/asn1-schema').AsnParser;
const ec = new EC('p256');
const {Buffer} = require('buffer');
// import {Buffer} from 'buffer';



export function randomChallenge() {
    return crypto.randomUUID();
}

export function toBuffer(txt) {
    return Uint8Array.from(txt, c => c.charCodeAt(0)).buffer;
}

export function parseBuffer(buffer) {
    return String.fromCharCode(...new Uint8Array(buffer));
}

export function isBase64url(txt) {
    return txt.match(/^[a-zA-Z0-9\-_]+=*$/) !== null;
}

export function toBase64url(buffer) {
    const txt = btoa(parseBuffer(buffer)); // base64
    return txt.replaceAll('+', '-').replaceAll('/', '_');
}

export function parseBase64url(txt) {
    txt = txt.replaceAll('-', '+').replaceAll('_', '/'); // base64url -> base64
    return toBuffer(atob(txt));
}

export async function sha256(buffer) {
    return await crypto.subtle.digest('SHA-256', buffer);
}

export function bufferToHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
} 

export function concatenateBuffers(buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp;
}

export function hexToBase64(hexstring) {
    return btoa(hexstring.match(/\w{2}/g).map(function(a) {
        return String.fromCharCode(parseInt(a, 16));
    }).join(""));
}

export function base64ToBase64Url(base64) {
    base64 = base64.replaceAll('+', '-').replaceAll('/', '_')
    return base64;
}

export function base64ToHex(base64String) {
    var raw = atob(base64String);
    var hex = '';

    for (var i = 0; i < raw.length; i++) {
        var _hex = raw.charCodeAt(i).toString(16);
        hex += (_hex.length === 2 ? _hex : '0' + _hex);
    }

    return hex;
}

export function base64UrlDecode(key) {
    key = key.replace(/-/g, '+').replace(/_/g, '/');
    while (key.length % 4) {
        key += '=';
    }
    return key;
}

export function base64UrlToHex(base64UrlEncodedText) {
    let base64UrlText = base64UrlDecode(base64UrlEncodedText);
    let HexText = base64ToHex(base64UrlText);
    return HexText;
}

// export function getPublicKeyCoordinates(base64UrlEncodedKey) {
//     let keyHash = base64UrlToHex(base64UrlEncodedKey);
//     keyHash  = keyHash.slice(53)
//     let publicKey = ec.keyFromPublic(keyHash, 'hex');
//     let publicKeyPoint = publicKey.getPublic();

//     return {
//         x: publicKeyPoint.getX().toString(16),
//         y: publicKeyPoint.getY().toString(16)
//     };
// }

export async function getPublicKeyFromBytes(publicKeyBytes) {
    const cap = {
        name: 'ECDSA',
        namedCurve: 'P-256',
        hash: 'SHA-256',
    }
    let pkeybytes = parseBase64url(publicKeyBytes);
    
    let pkey = await crypto.subtle.importKey('spki', pkeybytes, cap, true, ['verify']);
    
    let jwk = await crypto.subtle.exportKey('jwk', pkey);
    
    if (jwk.x && jwk.y)
        return {
            "pubKeyX": base64UrlToHex(jwk.x),
            "pubKeyY": base64UrlToHex(jwk.y)
        };
    else
        throw new Error('Invalid public key');
}

function shouldRemoveLeadingZero(bytes) {
    return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

export function getSignatureComponents(base64UrlEncodedSignature) {
    
    const parsedSignature = AsnParser.parse(
        parseBase64url(base64UrlEncodedSignature),
        ECDSASigValue,
    );

    console.log("here" );
    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);

    if (shouldRemoveLeadingZero(rBytes)) {
        rBytes = rBytes.slice(1);
    }
    
    if (shouldRemoveLeadingZero(sBytes)) {
        sBytes = sBytes.slice(1);
    }

    // r and s values
    return [
        bufferToHex(rBytes),
        bufferToHex(sBytes),
    ];
}

export async function signLikeSim(data) {

    const dataBuffer = Buffer.from(data, 'hex')
    const keyObject = crypto.subtle.generateKeyPairSync('ec', 
        { 
            namedCurve: 'prime256v1',
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        const jwk_private_key = crypto.createPrivateKey(keyObject.privateKey).export({ format: 'jwk' });
        const jwk_public_key = crypto.createPublicKey(keyObject.publicKey).export({ format: 'jwk' }); 

        const keyOb = crypto.createPrivateKey({
            key: jwk_private_key,
            format: "jwk",
            type: "pkcs8",
        });

        const sign = crypto.createSign('SHA256')
        sign.update(dataBuffer);

        const signature_hash = sign.sign(keyOb);
        return {
            "pub": jwk_public_key,
            "priv": jwk_private_key,
            "sig":  signature_hash
        }

}


// Function to convert hex string to Uint8Array
function hexStringToUint8Array(hexString) {
    if (hexString.length % 2 !== 0) {
        console.error('Invalid hexString');
        return;
    }
    var arrayBuffer = new Uint8Array(hexString.length / 2);

    for (var i = 0; i < hexString.length; i += 2) {
        var byteValue = parseInt(hexString.substr(i, 2), 16);
        if (isNaN(byteValue)) {
            console.error('Invalid hexString');
            return;
        }
        arrayBuffer[i / 2] = byteValue;
    }
    return arrayBuffer;
}

// export async function signP256(data) {
//     // Define the elliptic curve and hash algorithm
//     const algorithm = {
//         name: 'ECDSA',
//         namedCurve: 'P-256', // 'prime256v1' curve
//         hash: {name: 'SHA-256'},
//     };

//     // Generate a key pair
//     const keyPair = await window.crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);

//     // Export keys to JWK for displaying
//     const publicKeyJWK = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
//     const privateKeyJWK = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);

//     // Prepare the data to sign
//     const dataEncoded = hexStringToUint8Array(data); 

//     // Sign the data with the private key
//     const signature = await window.crypto.subtle.sign(algorithm, keyPair.privateKey, dataEncoded);

//     // Convert signature to hex
//     const signatureBytes = new Uint8Array(signature);

//     // Extract r and s values
//     const r = signatureBytes.slice(0, 32);
//     const s = signatureBytes.slice(32);

//     // Convert r and s to hex
//     const rHex = Array.from(r).map(b => b.toString(16).padStart(2, '0')).join('');
//     const sHex = Array.from(s).map(b => b.toString(16).padStart(2, '0')).join('');

//     return {
//         "pub": publicKeyJWK,
//         "priv": privateKeyJWK,
//         "sig": {
//             "r": rHex,
//             "s": sHex
//         },
//     };
// }

export async function signP256(data) {
    // convert the hex data (userOpHash) to arrayBuffer
    // const base64EncodedUserOp = hexToBase64(data);
    // const dataBuffer = toBuffer(atob(hexToBase64(data)));
    const dataBuffer = Uint8Array.from(Buffer.from(data, 'hex'));
    // generate a key pair for P256
    let keyPair = await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: 'P-256'
        },
        true,
        ["sign", "verify"]
    );

    console.log(keyPair)


    let publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    console.log(publicKey);

    let privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    console.log("privatekey: ", privateKey)

   
    
    console.log("helloooow");

    // import key for signing from privateKey
    const cryptoKey = await crypto.subtle.importKey(
        "jwk",
        privateKey,
        {
          name: "ECDSA",
          namedCurve: "P-256",
          hash: 'SHA-256'
        },
        true,
        ["sign"],
      );
    
    console.log(cryptoKey)


    // sign the data using cryptoKey
    let signature = await crypto.subtle.sign(
        {
            name: "ECDSA", 
            hash: {name: "SHA-256"}
        },
        cryptoKey,
        dataBuffer
    );

    // convert arrayBuffer signature to base64
    let base64Sig = btoa(String.fromCharCode(...new Uint8Array(signature)));
    console.log(base64Sig)

    let sigHex = base64ToHex(base64Sig);
    // first 32 bytes is r
    let r = sigHex.slice(0, 64);
    // last 32 bytes is s
    let s = sigHex.slice(64);


    // ------------
            // ------------ Verification section --------------------
    const verifyKey = await crypto.subtle.importKey(
        "jwk",
        publicKey,
        {
          name: "ECDSA",
          namedCurve: "P-256",
          hash: 'SHA-256'
        },
        true,
        ["verify"],
      );
    console.log(verifyKey)
    let isOk = await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: "SHA-256",
        },
        verifyKey,
        signature,
        dataBuffer
    );
    console.log(isOk);

    // ---------------------

    // console.log("signature:", typeof(signature), new Int32Array(signature));
    
    
    //     let base64Sig = "MEYCIQAjIUpP4wpMfuLFEZSzVrtpnrxkyBzhUcCqdzM1lvtiZwIhAPz4hOZfdMRZoKwWYpjBXHQks7Kb0orsX0IQGkX895BK";
    // const newSig = getSignatureComponents(base64Sig)


    return {
        "pub": publicKey,
        "priv": privateKey,
        "sig" : {
            "r": r,
            "s": s
        }
    }

}


export async function signUsingPrivateKey(key, data) {

    const dataBuffer = Uint8Array.from(Buffer.from(data, 'hex'));    
    const cryptoKey = await crypto.subtle.importKey(
        "jwk",
        key,
        {
          name: "ECDSA",
          namedCurve: "P-256",
          hash: 'SHA-256'
        },
        true,
        ["sign"],
    );

      // sign the data using cryptoKey
    let signature = await crypto.subtle.sign(
        {
            name: "ECDSA", 
            hash: {name: "SHA-256"}
        },
        cryptoKey,
        dataBuffer
    );

    // convert arrayBuffer signature to base64
    let base64Sig = btoa(String.fromCharCode(...new Uint8Array(signature)));
    console.log(base64Sig)

    let sigHex = base64ToHex(base64Sig);
    // first 32 bytes is r
    let r = sigHex.slice(0, 64);
    // last 32 bytes is s
    let s = sigHex.slice(64);

    return {
        "sig": {
            "r": r,
            "s": s
        }
    }
}
