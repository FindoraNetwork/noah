use byteorder::{ByteOrder, LittleEndian};
use custom_error::custom_error;

custom_error! {#[derive(PartialEq)] pub ConvertError
    BigNumberToBLSScalarError  = "BigNumber value cannot be converted to BLSScalar",
}

pub fn u64_lsf_le_to_u8_lsf(limbs: &[u64]) -> Vec<u8> {
    let mut bytes = vec![];
    for a in limbs {
        let mut array = [0_u8; 8];
        LittleEndian::write_u64(&mut array, *a);
        bytes.extend_from_slice(&array[..])
    }
    while let Some(b) = bytes.last() {
        if *b != 0 {
            break;
        }
        bytes.pop();
    }
    bytes
}

pub fn u8_lsf_slice_to_u64_lsf_le_vec(slice: &[u8]) -> Vec<u64> {
    // TODO move this to zei commons
    let mut r: Vec<u64> = vec![];
    let n = slice.len() / 8;
    for i in 0..n {
        r.push(LittleEndian::read_u64(&slice[i * 8..(i + 1) * 8]));
    }
    if slice.len() % 8 != 0 {
        r.push(LittleEndian::read_u64(&slice[n * 8..]));
    }
    r
}
