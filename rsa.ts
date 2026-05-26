import { createHash } from 'crypto';
import { bitLength as getBitLength, gcd, modPow, modInv, primeSync, randBetween } from 'bigint-crypto-utils';

export class RsaPublicKey {
    n: bigint;
    e: bigint;
    constructor(n: bigint, e: bigint) {
        this.n = n;
        this.e = e;
    }
    encrypt(message: bigint): bigint {
        return modPow(message, this.e, this.n);
    }
    verify(signature: bigint): bigint {
        return modPow(signature, this.e, this.n);
    }
}

export class RsaPrivateKey {
    n: bigint;
    d: bigint
    constructor(n: bigint, d: bigint) {
        this.n = n;
        this.d = d;
    }
    decrypt(ciphertext: bigint): bigint {
        return modPow(ciphertext, this.d, this.n);
    }
    sign(message: bigint): bigint {
        return modPow(message, this.d, this.n);
    }
}

export function generateKeyPair(bitLength: number): { publicKey: RsaPublicKey; privateKey: RsaPrivateKey } {
    const e = 65537n;
    let p: bigint, q: bigint, n: bigint, phi: bigint, d: bigint;
    do {
        p = primeSync(bitLength / 2 + 1);
        q = primeSync(bitLength / 2);
        n = p * q;
        phi = (p - 1n) * (q - 1n);
    } while (getBitLength(n) !== bitLength || gcd(e, phi) !== 1n);
    d = modInv(e, phi);
    return {
        publicKey: new RsaPublicKey(n, e),
        privateKey: new RsaPrivateKey(n, d),
    };
}

// ---------- Firma / verificación de mensajes ----------

/** SHA-256 de un mensaje como bigint (el digest es < n, así que se puede firmar). */
export function hashToBigInt(message: string): bigint {
    const hex = createHash('sha256').update(message).digest('hex');
    return BigInt('0x' + hex);
}

/** Firma un mensaje: SHA-256 + RSA con la privada. Devuelve la firma como bigint. */
export function signMessage(privateKey: RsaPrivateKey, message: string): bigint {
    return privateKey.sign(hashToBigInt(message));
}

/** Verifica la firma de un mensaje con la pública (recupera el digest y lo compara). */
export function verifyMessage(publicKey: RsaPublicKey, message: string, signature: bigint): boolean {
    return publicKey.verify(signature) === hashToBigInt(message);
}

/**
 * Cifra un mensaje (bigint) con la pública RSA del destinatario.
 * Acepta `null` por comodidad (las claves se cargan async y pueden no estar):
 * en ese caso lanza, y quien llame lo captura.
 */
export function encryptMessage(message: bigint, publicKey: RsaPublicKey | null): bigint {
    if (!publicKey) throw new Error("Public key not available");
    return publicKey.encrypt(message);
}

// ---------- Firma a ciegas (blind signature) ----------

/**
 * Paso 1 (solicitante): cega el mensaje antes de pedir la firma.
 * Elige un factor aleatorio r coprimo con n y devuelve:
 *   blinded = m · r^e mod n
 * junto al r, que el solicitante guarda para desvelar la firma después.
 * El firmante nunca llega a ver el mensaje original m.
 */
export function blind(message: bigint, publicKey: RsaPublicKey): { blinded: bigint; r: bigint } {
    let r: bigint;
    do {
        r = randBetween(publicKey.n - 1n, 2n);
    } while (gcd(r, publicKey.n) !== 1n);
    const blinded = (message * modPow(r, publicKey.e, publicKey.n)) % publicKey.n;
    return { blinded, r };
}

/**
 * Paso 2 (firmante): firma el mensaje cegado sin conocer el original.
 *   blindSig = blinded^d mod n
 */
export function blindSign(privateKey: RsaPrivateKey, blindedMessage: bigint): bigint {
    return privateKey.sign(blindedMessage);
}

/**
 * Paso 3 (solicitante): desvela la firma usando el r del paso 1.
 *   s = blindSig · r^{-1} mod n
 * El resultado es una firma RSA válida del mensaje original (s^e mod n === m).
 */
export function unblind(blindSignature: bigint, r: bigint, publicKey: RsaPublicKey): bigint {
    const rInv = modInv(r, publicKey.n);
    return (blindSignature * rInv) % publicKey.n;
}

/**
 * Paso 4 (verificador): comprueba que la firma corresponde al mensaje.
 *   signature^e mod n === message
 */
export function blindVerify(message: bigint, signature: bigint, pubKey: RsaPublicKey): boolean {
    return pubKey.verify(signature) === message;
}