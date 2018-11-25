use std::num::Wrapping as W;

//const u8[16] -> Salsa20 constant: "expand 32-byte k"
pub static SIGMA : &'static [u8;16] = b"expand 32-byte k";

//load 32-bit integer little-endian
fn ld32(x: &[u8;4]) -> W<u32> {
    let mut u = x[3] as u32;
    u = (u << 8) | (x[2] as u32);
    u = (u << 8) | (x[1] as u32);
    W((u << 8) | (x[0] as u32))
}

//Rotate 32-bit integer lef
fn l32(x: W<u32>, c: usize /* int */) -> W<u32> {
    (x << c) | ((x & W(0xffffffff)) >> (32 - c))
}

//Store 32-bit integer little-endian
fn st32(x: &mut [u8;4], mut u: W<u32>) {
    for v in x.iter_mut() {
        *v = u.0 as u8;
        u = u >> 8;
    }
}


//merged crypto_core_salsa20, crypto_core_hsalsa20
fn core(out: &mut[u8], inx: &[u8;16], k: &[u8;32], c: &[u8;16], h: bool) {
    let mut w = [W(0u32); 16];
    let mut x = [W(0u32); 16];
    let mut y = [W(0u32); 16];
    let mut t = [W(0u32); 4];

    for i in 0..4 {
        x[5*i] = ld32(index_fixed!(&c[4*i..];..4));
        x[1+i] = ld32(index_fixed!(&k[4*i..];..4));
        x[6+i] = ld32(index_fixed!(&inx[4*i..];..4));
        x[11+i] = ld32(index_fixed!(&k[16+4*i..];..4));
    }

    for i in 0..16 {
        y[i] = x[i];
    }

    for _ in 0..20 {
        for j in 0..4 {
            for m in 0..4 {
                t[m] = x[(5*j+4*m)%16];
            }
            t[1] = t[1] ^ l32(t[0]+t[3], 7);
            t[2] = t[2] ^ l32(t[1]+t[0], 9);
            t[3] = t[3] ^ l32(t[2]+t[1],13);
            t[0] = t[0] ^ l32(t[3]+t[2],18);
            for m in 0..4 {
                w[4*j+(j+m)%4] = t[m];
            }
        }
        for m in 0..16 {
            x[m] = w[m];
        }
    }

    if h {
        for i in 0..16 {
            x[i] = x[i] + y[i];
        }
        for i in 0..4 {
            x[5*i] = x[5*i] - ld32(index_fixed!(&c[4*i..];..4));
            x[6+i] = x[6+i] - ld32(index_fixed!(&inx[4*i..];..4));
        }
        for i in 0..4 {
            st32(index_fixed!(&mut out[4*i..];..4), x[5*i]);
            st32(index_fixed!(&mut out[16+4*i..];..4), x[6+i]);
        }
    } else {
        for i in 0..16 {
            st32(index_fixed!(&mut out[4 * i..];..4), x[i] + y[i]);
        }
    }
}



fn core_salsa20(out: &mut [u8;64], inx: &[u8;16], k: &[u8;32], c: &[u8;16]) {
    core(out,inx,k,c,false);
}


pub fn core_hsalsa20(out: &mut [u8;32], inx: &[u8;16], k: &[u8;32], c: &[u8;16]) {
    core(out,inx,k,c,true);
}

fn stream_salsa20_xor(mut c: &mut [u8], mut m: Option<&[u8]>, n: &[u8;8], k: &[u8;32]) {
    let mut z = [0u8;16];

    /* XXX: not zeroed in tweet-nacl, provided by call to core_salsa20 */
    let mut x = [0u8;64];
    m.map(|x| assert_eq!(x.len(), c.len())); //HANDLE ERROR PROPAGATION !!!

    if c.len() == 0 {
        return; //HANDLE ERROR PROPAGATION !!!
    }

    for i in 0..8 {
        z[i] = n[i];
    }

    while c.len() >= 64 {
        core_salsa20(&mut x, &mut z,k,SIGMA);
        for i in 0..64 {
            c[i] = match m {
              Some(m) => m[i],
              None    => 0
            } ^ x[i];
        }

        let mut u : u32= 1;

        for i in 8..16 {
            u += z[i] as u32;
            z[i] = u as u8;
            u >>= 8;
        }

        c = &mut {c}[64..];

        if m.is_some() {
          m = Some(&m.unwrap()[64..])
        }

    }

    if c.len() != 0 {
        core_salsa20(&mut x, &mut z,k,SIGMA);
        for i in 0..c.len() {
          c[i] = match m {
            Some(m) => m[i],
            None    => 0
          } ^ x[i];
        }
    }
}

fn stream_salsa20(c: &mut [u8], n : &[u8;8], k: &[u8;32]) {
    stream_salsa20_xor(c, None, n, k)
}

pub const STREAM_NONCE_LEN : usize = 24;
pub const STREAM_KEY_LEN : usize = 32;
pub type StreamNonce = [u8;STREAM_NONCE_LEN];
pub type StreamKey = [u8;STREAM_KEY_LEN];


pub fn stream(c: &mut [u8], n: &StreamNonce, k: &StreamKey) {
    let mut s = [0u8; 32];
    core_hsalsa20(&mut s,index_fixed!(&n[..];..16),k,SIGMA);
    stream_salsa20(c,index_fixed!(&n[16..];..8),&s)
}

pub fn stream_xor(c: &mut [u8], m: &[u8], n: &StreamNonce, k: &StreamKey) {
    let mut s = [0u8; 32];
    core_hsalsa20(&mut s,index_fixed!(&n[..];..16),k,SIGMA);
    stream_salsa20_xor(c,Some(m),index_fixed!(&n[16..];..8), &s)
}