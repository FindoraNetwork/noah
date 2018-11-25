//Internal Shared Functions
use std::num::Wrapping as W;
use crate::util::randombytes;


fn vn(x: &[u8], y: &[u8]) -> isize {
    assert_eq!(x.len(), y.len());
    let mut d = 0u32;
    for i in 0..x.len() {
        d |= (x[i] ^ y[i]) as u32;
    }

    /* FIXME: check this cast. appears this function might be attempting to sign extend. This also
     * affects a bunch of other functions that right now have isize as a return type */
    ((W(1) & ((W(d) - W(1)) >> 8)) - W(1)).0 as isize //(1 & ((d - 1) >> 8)) - 1;
}

/* XXX: public in tweet-nacl */
pub fn verify_16(x: &[u8;16], y: &[u8;16]) -> bool { vn(&x[..], &y[..]) == 0 }

// /* XXX: public in tweet-nacl */
// pub fn verify_32(x: &[u8;32], y: &[u8;32]) -> bool { vn(&x[..], &y[..]) == 0 }


#[test]
fn test_verify_16() {

    for _ in 0usize..256 {
        let mut x = [0u8; 16];
        let mut y = [0u8; 16];
        assert!(verify_16(&x, &y));
        randombytes(&mut x);
        randombytes(&mut y);

        if x == y {
            assert!(verify_16(&x, &y))
        } else {
            assert!(!verify_16(&x, &y))
        }
    }
}


// #[test]
// fn test_verify_32() {

//     for _ in 0usize..256 {
//         let mut x = [0; 32];
//         let mut y = [0; 32];
//         assert!(verify_32(&x, &y));
//         randombytes(&mut x);
//         randombytes(&mut y);

//         if x == y {
//             assert!(verify_32(&x, &y))
//         } else {
//             assert!(!verify_32(&x, &y))
//         }
//     }
// }