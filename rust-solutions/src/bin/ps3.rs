use std::convert::TryInto;
use std::io::{stdin, stdout};

use byteorder::{BigEndian, ByteOrder};
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use sha2_state_exposed::Digest as _;

use cs6903::Executable;

fn main() {
    cs6903::ProblemSet::new(&mut stdin(), &mut stdout()).execute();
}

#[derive(Serialize, Deserialize)]
struct InputData {
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct InputDataProblem4 {
    length: u32,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    suffix: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct InputDataProblem5 {
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SHAttered {
    #[serde(with = "serde_bytes")]
    blue_pdf_sha1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    blue_pdf_sha256: Vec<u8>,
    #[serde(with = "serde_bytes")]
    red_pdf_sha1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    red_pdf_sha256: Vec<u8>,
}

#[derive(Deserialize)]
struct Input {
    problem1: InputData,
    problem2: InputData,
    problem4: InputDataProblem4,
    problem5: InputDataProblem5,
}

#[derive(Serialize, Deserialize)]
struct Output {
    #[serde(with = "serde_bytes")]
    problem1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    problem2: Vec<u8>,
    problem3: SHAttered,
    #[serde(with = "serde_bytes")]
    problem4: Vec<u8>,
    #[serde(with = "serde_bytes")]
    problem5: Vec<u8>,
}

impl Executable<Input, Output> for cs6903::ProblemSet<'_> {
    fn execute(&mut self) {
        let input_struct: Input = cs6903::ProblemSet::get_input(self.inbuff);
        let output_struct = Output {
            problem1: problem1(&input_struct.problem1),
            problem2: problem2(&input_struct.problem2),
            problem3: problem3(),
            problem4: problem4(&input_struct.problem4),
            problem5: problem5(&input_struct.problem5),
        };
        cs6903::ProblemSet::write_output(&mut self.outbuff, &output_struct);
    }
}

fn problem1(input: &InputData) -> Vec<u8> {
    Sha1::digest(input.data.as_slice()).to_vec()
}

fn problem2(input: &InputData) -> Vec<u8> {
    Sha256::digest(input.data.as_slice()).to_vec()
}

fn is_network_live() -> bool {
    match ureq::get("https://httpbin.org/ip").call() {
        Ok(_) => true,
        _ => false,
    }
}

fn problem3() -> SHAttered {
    if !is_network_live() {
        return SHAttered {
            blue_pdf_sha1: cs6903::parse_hex_str(
                "38762cf7f55934b34d179ae6a4c80cadccbb7f0a".to_string(),
            ),
            blue_pdf_sha256: cs6903::parse_hex_str(
                "2bb787a73e37352f92383abe7e2902936d1059ad9f1ba6daaa9c1e58ee6970d0".to_string(),
            ),
            red_pdf_sha1: cs6903::parse_hex_str(
                "38762cf7f55934b34d179ae6a4c80cadccbb7f0a".to_string(),
            ),
            red_pdf_sha256: cs6903::parse_hex_str(
                "d4488775d29bdef7993367d541064dbdda50d383f89f0aa13a6ff2e0894ba5ff".to_string(),
            ),
        };
    }
    let mut blue_pdf = Vec::new();
    ureq::get("https://shattered.io/static/shattered-1.pdf")
        .call()
        .expect("failed to GET blue PDF")
        .into_reader()
        .read_to_end(&mut blue_pdf)
        .unwrap();
    let mut red_pdf = Vec::new();
    ureq::get("https://shattered.io/static/shattered-2.pdf")
        .call()
        .expect("failed to GET red PDF")
        .into_reader()
        .read_to_end(&mut red_pdf)
        .unwrap();
    SHAttered {
        blue_pdf_sha1: Sha1::digest(&blue_pdf).to_vec(),
        blue_pdf_sha256: Sha256::digest(&blue_pdf).to_vec(),
        red_pdf_sha1: Sha1::digest(&red_pdf).to_vec(),
        red_pdf_sha256: Sha256::digest(&red_pdf).to_vec(),
    }
}

fn sha256_padding(length: u32) -> Vec<u8> {
    let zero_byte_count = ((64 - 1 - (length + 8)) % 64) as usize;
    let mut ret = vec![0x80u8];
    ret.extend(vec![0x00u8; zero_byte_count].iter());
    ret.extend(zero_byte_count.to_be_bytes().iter());
    ret
}

fn problem4(input: &InputDataProblem4) -> Vec<u8> {
    let state: [u32; 8] = input
        .hash
        .chunks_exact(4)
        .into_iter()
        .map(BigEndian::read_u32)
        .collect::<Vec<u32>>()
        .try_into()
        .expect("Bad input state size");
    let padding = sha256_padding(input.length);
    let mut digest = sha2_state_exposed::Sha256::with_internal_state(
        &state,
        (input.length as usize + padding.len()) as u64,
    );
    digest.input(&mut input.suffix.as_slice());
    digest.result().to_vec()
}

fn problem5(input: &InputDataProblem5) -> Vec<u8> {
    hmac::Hmac::<Sha256>::new_from_slice(input.key.as_slice())
        .unwrap()
        .chain_update(input.data.as_slice())
        .finalize()
        .into_bytes()
        .to_vec()
}

#[cfg(test)]
mod unit_tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_problem_1() {
        let (_, actual_output, expected_output) = do_test();
        cs6903::test_utils::assert_byte_vec_eq(&expected_output.problem1, &actual_output.problem1);
    }

    #[test]
    fn test_problem_2() {
        let (_, actual_output, expected_output) = do_test();
        cs6903::test_utils::assert_byte_vec_eq(&expected_output.problem2, &actual_output.problem2);
    }

    #[test]
    fn test_problem_3() {
        let (_, actual_output, expected_output) = do_test();
        cs6903::test_utils::assert_byte_vec_eq(
            &expected_output.problem3.blue_pdf_sha1,
            &actual_output.problem3.blue_pdf_sha1,
        );
        cs6903::test_utils::assert_byte_vec_eq(
            &expected_output.problem3.blue_pdf_sha256,
            &actual_output.problem3.blue_pdf_sha256,
        );
        cs6903::test_utils::assert_byte_vec_eq(
            &expected_output.problem3.red_pdf_sha1,
            &actual_output.problem3.red_pdf_sha1,
        );
        cs6903::test_utils::assert_byte_vec_eq(
            &expected_output.problem3.red_pdf_sha256,
            &actual_output.problem3.red_pdf_sha256,
        );
    }

    #[test]
    fn test_problem_4() {
        let (_, actual_output, expected_output) = do_test();
        cs6903::test_utils::assert_byte_vec_eq(&expected_output.problem4, &actual_output.problem4);
    }

    #[test]
    fn test_problem_5() {
        let (_, actual_output, expected_output) = do_test();
        cs6903::test_utils::assert_byte_vec_eq(&expected_output.problem5, &actual_output.problem5);
    }

    fn do_test() -> (Input, Output, Output) {
        let ps_name = cs6903::get_file_name(file!());
        let mut inbuff = cs6903::test_utils::get_test_input_reader(&ps_name);
        let mut outbuff = Cursor::new(Vec::new());
        let mut ps = cs6903::ProblemSet::new(&mut inbuff, &mut outbuff);
        ps.execute();
        outbuff.set_position(0);
        let input: Input = cs6903::ProblemSet::<'_>::get_input(
            &mut cs6903::test_utils::get_test_input_reader(&ps_name),
        );
        let actual_output: Output = cs6903::ProblemSet::<'_>::get_output(&mut outbuff);
        let expected_output: Output = cs6903::ProblemSet::<'_>::get_output(
            &mut cs6903::test_utils::get_test_output_reader(&ps_name),
        );
        (input, actual_output, expected_output)
    }
}
