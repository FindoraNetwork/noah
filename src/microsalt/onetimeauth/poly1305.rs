use crate::microsalt::shared;
use std::cmp;

pub const ONETIMEAUTH_KEY_LEN : usize = 32;
pub const ONETIMEAUTH_HASH_LEN : usize = 16;
pub type OnetimeauthKey = [u8;ONETIMEAUTH_KEY_LEN];
pub type OnetimeauthHash = [u8;ONETIMEAUTH_HASH_LEN];

//const u32[17] -> {5,0,...,0,252}
const MINUSP : [u32;17] = [5u32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252];

//Add 136-bit integers, radix 2^8
fn add1305(h: &mut [u32; 17], c: &[u32; 17]) {
    let mut u = 0u32;
    for j in 0..17 {
        u += h[j] + c[j];
        h[j] = u & 255;
        u >>= 8;
    }
}

pub fn onetimeauth(out: &mut OnetimeauthHash, mut m: &[u8], k: &OnetimeauthKey) {
    /* FIXME: not zeroed in tweet-nacl */
    let mut r = [0u32;17];
    let mut h = [0u32;17];

    for j in 0..16 {
        r[j] = k[j] as u32;
    }

    r[3]&=15;
    r[4]&=252;
    r[7]&=15;
    r[8]&=252;
    r[11]&=15;
    r[12]&=252;
    r[15]&=15;

    while m.len() > 0 {
        let mut c = [0u32;17];

        let j_end = cmp::min(m.len(), 16); //cmp::min returns the minimum of two values
        for j in 0..j_end {
            c[j] = m[j] as u32;
        }
        c[j_end] = 1;
        m = &m[j_end..];
        add1305(&mut h, &c);
        let mut x = [0u32;17];
        for i in 0..17 {
            for j in 0..17 {
                x[i] += h[j] * (if j <= i { r[i - j] } else { 320 * r[i + 17 - j]});
            }
        }

        for i in 0..17 {
            h[i] = x[i];
        }
        let mut u = 0u32;
        for j in 0..16 {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u & 3;
        u = 5 * (u >> 2);
        for j in 0..16 {
            u += h[j];
            h[j] = u & 255;
            u >>= 8;
        }
        u += h[16];
        h[16] = u;
    }

    let g = h;
    add1305(&mut h, &MINUSP);
    /* XXX: check signed cast */
    let s : u32 = (-((h[16] >> 7) as i32)) as u32;
    for j in 0..17 {
        h[j] ^= s & (g[j] ^ h[j]);
    }

    /* FIXME: extra zeroing */
    let mut c = [0u32;17];
    for j in 0..16 {
        c[j] = k[j + 16] as u32;
    }
    c[16] = 0;
    add1305(&mut h, &c);
    for j in 0..16 {
        out[j] = h[j] as u8;
    }
}


pub fn onetimeauth_verify(h: &OnetimeauthHash, m: &[u8], k: &OnetimeauthKey) -> bool {  
    let mut x = [0u8; 16];
    onetimeauth(&mut x,m,k);
    shared::verify_16(h,&x)
}