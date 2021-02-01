import {Msg} from "./verifyUcan";
import {CharSize} from "./consts";

export const normalizeToBuf = (msg: Msg, strConv: (str: string) => ArrayBuffer): ArrayBuffer => {
    if (typeof msg === 'string') {
        return strConv(msg)
    } else if (typeof msg === 'object' && msg.byteLength !== undefined) {
        // this is the best runtime check I could find for ArrayBuffer/Uint8Array
        const temp = new Uint8Array(msg)
        return temp.buffer
    } else {
        throw new Error("Improper value. Must be a string, ArrayBuffer, Uint8Array")
    }
}

export const normalizeBase64ToBuf = (msg: Msg): ArrayBuffer => {
    return normalizeToBuf(msg, base64ToArrBuf)
}

export const normalizeUnicodeToBuf = (msg: Msg, charSize: CharSize) => {
    switch (charSize) {
        case 8: return normalizeUtf8ToBuf(msg)
        default: return normalizeUtf16ToBuf(msg)
    }
}

export const normalizeUtf8ToBuf = (msg: Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B8))
}

export const normalizeUtf16ToBuf = (msg: Msg): ArrayBuffer => {
    return normalizeToBuf(msg, (str) => strToArrBuf(str, CharSize.B16))
}

export function base64ToArrBuf(base64: string): ArrayBuffer {
    const str = Buffer.from(base64, "base64").toString("utf-8");
    return strToArrBuf(str, 8)
}

export function strToArrBuf(str: string, charSize: CharSize): ArrayBuffer {
    const view =
        charSize === 8 ? new Uint8Array(str.length) : new Uint16Array(str.length)
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        view[i] = str.charCodeAt(i)
    }
    return view.buffer
}
