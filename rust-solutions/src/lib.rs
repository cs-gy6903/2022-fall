extern crate core;

use std::arch::asm;
use std::io::{Read, Write};
use std::iter::zip;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn parse_hex_str(hex_str: String) -> Vec<u8> {
    assert_eq!(hex_str.len() % 2, 0);
    let mut bytes: Vec<u8> = Vec::new();
    for ii in (0..hex_str.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex_str[ii..ii + 2], 16).unwrap());
    }
    bytes
}

pub fn unparse_hex_str(bytes: Vec<u8>) -> String {
    bytes
        .into_iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

pub fn xor(one: Vec<u8>, two: Vec<u8>) -> Vec<u8> {
    assert_eq!(one.len(), two.len());
    zip(one, two).map(|(a, b)| a ^ b).collect()
}

pub fn get_rand_bytes(size: usize) -> Vec<u8> {
    let mut ret = Vec::new();
    for _ in 0..((size / 4) + 1) {
        ret.extend_from_slice(&get_rand_long().to_be_bytes()[..]);
    }
    ret.truncate(size);
    ret
}

/// Use RDRAND instruction if available on current processor, else panic because we ain't messing
/// around!!
///
/// per intel's guidance, we check the carry bit to see if RDRAND generated a sufficiently random number, retrying up to
/// 10 times if not. for details, see section 5.2 of the RDRAND instruction guide from intel:
///
/// https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html
pub fn get_rand_long() -> u64 {
    if std::is_x86_feature_detected!("rdrand") {
        let mut ret: u64;
        let mut ok: u8;
        let mut retries = 10;
        while retries > 0 {
            unsafe {
                asm!(
                    "rdrand {0}",
                    "setc {1}",
                    out(reg) ret,
                    lateout(reg_byte) ok
                );
            }
            if ok & 1 == 1 {
                return ret;
            }
            retries -= 1;
        }
    }
    panic!("RDRAND not supported or failed to produce random output");
}

// https://en.wikipedia.org/wiki/Modular_exponentiation#Pseudocode
pub fn modexp(base: u32, exp: u32, modulus: u32) -> u32 {
    if modulus == 1 {
        return 0;
    }
    let mut ret: u64 = 1;
    let mut b: u64 = (base % modulus) as u64;
    let mut e: u64 = exp as u64;
    while e > 0 {
        if e % 2 == 1 {
            ret = (ret * b) % modulus as u64;
        }
        e >>= 1;
        b = (b * b) % modulus as u64;
    }
    ret as u32
}

pub fn get_file_name(file: &str) -> String {
    String::from(Path::new(file).file_stem().unwrap().to_str().unwrap())
}

pub struct ProblemSet<'a> {
    pub inbuff: &'a mut (dyn Read + 'a),
    pub outbuff: &'a mut (dyn Write + 'a),
}

impl<'a> ProblemSet<'a> {
    pub fn new(inbuff: &'a mut dyn Read, outbuff: &'a mut dyn Write) -> Self {
        Self { inbuff, outbuff }
    }
}

pub trait Executable<I: DeserializeOwned, O: Serialize + DeserializeOwned> {
    fn execute(&mut self);

    fn get_input(ibuff: &mut dyn Read) -> I {
        bson::from_reader(ibuff).expect("Failed to parse input stream")
    }

    fn get_output(obuff: &mut dyn Read) -> O {
        bson::from_reader(obuff).expect("Failed to parse output stream")
    }

    fn write_output(obuff: &mut dyn Write, output_struct: &O) -> usize {
        let bson_bytes = bson::to_vec(&output_struct).expect("error serializing");
        obuff
            .write(bson_bytes.as_slice())
            .expect("error writing to output")
    }
}

pub mod test_utils {
    use bson::Bson;
    use std::fs::*;
    use std::io::*;

    pub fn assert_byte_vec_eq(one: &Vec<u8>, two: &Vec<u8>) {
        assert_eq!(one.len(), two.len());
        one.iter().zip(two).for_each(|(a, b)| assert_eq!(*a, *b));
    }

    pub fn get_test_input_reader(ps_name: &String) -> Box<dyn Read> {
        _get_reader(ps_name, &"in".to_string())
    }

    pub fn get_test_output_reader(ps_name: &String) -> Box<dyn Read> {
        _get_reader(ps_name, &"out".to_string())
    }

    fn _get_reader(ps_name: &String, extension: &String) -> Box<dyn Read> {
        let infile_path = format!(
            "{}/../{}/bson.{}",
            env!("CARGO_MANIFEST_DIR"),
            ps_name,
            extension
        );
        // sometimes the sample BSON is produced with different format, so we do a little song and
        // dance in the error condition to account for that
        let infile = match File::open(&infile_path) {
            Ok(f) => f,
            Err(_) => {
                let alt_path = format!(
                    "{}/../{}/{}.bson",
                    env!("CARGO_MANIFEST_DIR"),
                    ps_name,
                    extension
                );
                return Box::new(File::open(&alt_path).expect("Failed to open test infile"));
            }
        };
        let input_bson: Bson =
            bson::from_reader(BufReader::new(infile)).expect("Error loading bson");
        let mut inbuff =
            Cursor::new(bson::to_vec(&input_bson).expect("error converting BSON to bytes"));
        inbuff.set_position(0);
        Box::new(inbuff)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_get_rand_bytes() {
        for ii in 0..64 + 1 {
            let b = get_rand_bytes(ii as usize);
            assert_eq!(ii, b.len());
        }
    }

    #[test]
    fn test_modexp() {
        let test_cases: Vec<(u32, u32, u32, u32)> =
            vec![(2, 5, 3, 2), (100, 9, 8, 0), (31, 7, 6, 1)];
        for (a, b, c, d) in test_cases.iter() {
            assert_eq!(modexp(*a, *b, *c), *d);
        }
    }
}
