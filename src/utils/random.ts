/**
 * Seedable random utilities
 */

let seededRandom: (() => number) | null = null;

function mulberry32(seed: number): () => number {
    let t = seed >>> 0;
    return () => {
        t += 0x6D2B79F5;
        let r = Math.imul(t ^ (t >>> 15), 1 | t);
        r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
        return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
    };
}

export function initDeterministic(seed?: number): void {
    if (typeof seed === 'number' && Number.isFinite(seed)) {
        seededRandom = mulberry32(seed);
    } else {
        seededRandom = mulberry32(42);
    }
}

export function random(): number {
    return seededRandom ? seededRandom() : Math.random();
}

export function randomInt(min: number, max: number): number {
    const low = Math.ceil(min);
    const high = Math.floor(max);
    return Math.floor(random() * (high - low + 1)) + low;
}

export function isDeterministic(): boolean {
    return seededRandom !== null;
}
