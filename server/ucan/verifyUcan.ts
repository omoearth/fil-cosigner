import {RSA_WRITE_ALG, SALT_LENGTH} from "./consts";
import {normalizeBase64ToBuf, normalizeUnicodeToBuf} from "./normalize";
const {subtle} = require('crypto').webcrypto;
import jwt_decode from "jwt-decode";
import {Ucan, UcanHeader, UcanPayload} from "./types";
import {didToPublicKey} from "./didToPublicKey";
export type Msg = ArrayBuffer | string | Uint8Array;

export async function verifyUcan(ucan:string, myDid:string)
{
    const header:UcanHeader = jwt_decode(ucan, {header: true});
    const payload:UcanPayload = jwt_decode(ucan);

    const signedData = ucan.split(".").slice(0,2).join(".");
    const signature = ucan.split(".")[2];

    const now = Math.floor(Date.now() / 1000);

    if (typeof payload !== "object")
        throw new Error("Couldn't decode the jwt");

    const iss = payload.iss;
    if (!iss)
        throw new Error("No issuer (iss) claim.");

    const exp = payload.exp;
    if (!exp)
        throw new Error("No expiry (exp) claim.");
    if (exp <= now)
        throw new Error("The token is already expired.")

    const nbf = payload.nbf;
    if (nbf && nbf > now)
        throw new Error(`The ucan is not valid before ${nbf}. Now it is ${now}.`)

    const rsc = payload.rsc;
    if (!rsc)
        throw new Error("No ressource (rsc) claim.");

    const ptc = payload.ptc;
    if (!ptc)
        throw new Error("No potency (ptc) claim.");

    const aud = payload.aud;
    if (!aud)
        throw new Error("No audience (aud) claim.");
    if (aud !== myDid)
        throw new Error(`Invalid audience. I'm '${myDid}', you wanted '${aud}'.`)

    const rootIss = rootIssuer(ucan);
    if (iss !== rootIss)
    {
        // TODO: Check if the "prf" is valid
    }

    const publicKey = await didToPublicKey(iss);
    const verifySigResult = await verifySignature(publicKey, signedData, signature, 8);
}

async function verifySignature(publicKey:CryptoKey, msg:Msg, signature:string, charSize:number)
{
    const verificationResult = await subtle.verify(
        { name: RSA_WRITE_ALG, saltLength: SALT_LENGTH },
        publicKey,
        normalizeBase64ToBuf(signature),
        normalizeUnicodeToBuf(msg, charSize)
    );

    return verificationResult;
}

function rootIssuer(ucan: string, level = 0): string {
    const p = extractPayload(ucan, level)
    if (p.prf) return rootIssuer(p.prf, level + 1)
    return p.iss
}

function extractPayload(ucan: string, level: number): UcanPayload {
    try {
        return jwt_decode(ucan)
    } catch (_) {
        throw new Error(`Invalid UCAN (${level} level${level === 1 ? "" : "s"} deep): \`${ucan}\``)
    }
}
