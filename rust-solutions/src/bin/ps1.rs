use std::fmt::Formatter;
use std::io::{stdin, stdout};

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use cs6903::Executable;

fn main() {
    cs6903::ProblemSet::new(&mut stdin(), &mut stdout()).execute();
}

#[derive(Serialize, Deserialize)]
struct InputN {
    n: u32,
}

#[derive(Serialize, Deserialize)]
struct InputData {
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct InputDataString {
    data: String,
}

fn deserialize_vec_byte_vecs<'d, D>(d: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'d>,
{
    struct SeqVisitor;
    impl<'d> Visitor<'d> for SeqVisitor {
        type Value = Vec<Vec<u8>>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "a vec of byte vecs")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'d>,
        {
            let mut ret: Self::Value = Self::Value::new();
            while let Some(next) = seq.next_element::<&[u8]>()? {
                ret.push(next.to_vec());
            }
            Ok(ret)
        }
    }

    d.deserialize_seq(SeqVisitor)
}

#[derive(Serialize, Deserialize)]
struct InputDataNestedBytes {
    #[serde(deserialize_with = "deserialize_vec_byte_vecs")]
    data: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct Input {
    example: InputData,
    problem1: InputN,
    problem2: InputN,
    problem3: InputData,
    problem4: InputDataNestedBytes,
    problem5: InputDataString,
    problem6: InputData,
}

#[derive(Serialize, Deserialize)]
struct Output {
    #[serde(with = "serde_bytes")]
    example: Vec<u8>,
    problem1: Vec<u32>,
    #[serde(with = "serde_bytes")]
    problem2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    problem3: Vec<u8>,
    #[serde(with = "serde_bytes")]
    problem4: Vec<u8>,
    #[serde(with = "serde_bytes")]
    problem5: Vec<u8>,
    problem6: String,
}

impl Executable<Input, Output> for cs6903::ProblemSet<'_> {
    fn execute(&mut self) {
        let input_struct: Input = cs6903::ProblemSet::get_input(self.inbuff);
        let output_struct = Output {
            example: example(&input_struct.example.data),
            problem1: problem1(&input_struct.problem1.n),
            problem2: problem2(&input_struct.problem2.n),
            problem3: problem3(&input_struct.problem3.data),
            problem4: problem4(&input_struct.problem4.data),
            problem5: problem5(&input_struct.problem5.data),
            problem6: problem6(&input_struct.problem6.data),
        };
        cs6903::ProblemSet::write_output(&mut self.outbuff, &output_struct);
    }
}

fn example(data: &[u8]) -> Vec<u8> {
    String::from_utf8(data.to_owned())
        .unwrap()
        .to_uppercase()
        .into_bytes()
}

fn problem1(n: &u32) -> Vec<u32> {
    (0..*n)
        .map(|_| (cs6903::get_rand_long() % 256) as u32)
        .collect()
}

fn problem2(n: &u32) -> Vec<u8> {
    let u = *n as usize;
    cs6903::get_rand_bytes(u)
}

fn problem3(bytes: &Vec<u8>) -> Vec<u8> {
    bytes.iter().map(|b| (*b as u32 * 2 % 256) as u8).collect()
}

fn problem4(byte_vecs: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut acc = vec![0u8; byte_vecs.get(0).expect("empty input!").len()];
    for byte_vec in byte_vecs {
        acc = cs6903::xor(acc, byte_vec.clone());
    }
    acc
}

fn problem5(hex_str: &String) -> Vec<u8> {
    cs6903::parse_hex_str(hex_str.clone())
}

fn problem6(bytes: &Vec<u8>) -> String {
    cs6903::unparse_hex_str(bytes.clone())
}

#[cfg(test)]
mod unit_tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_example() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.example, actual_output.example);
    }

    #[test]
    fn test_problem_1() {
        let (input, actual_output, expected_output) = do_test();
        assert_eq!(input.problem1.n as usize, actual_output.problem1.len());
        assert_eq!(expected_output.problem1.len(), actual_output.problem1.len());
        assert!(actual_output.problem1.iter().all(|x| *x < 256));
    }

    #[test]
    fn test_problem_2() {
        let (input, actual_output, expected_output) = do_test();
        assert_eq!(input.problem2.n as usize, expected_output.problem2.len());
        assert_eq!(expected_output.problem2.len(), actual_output.problem2.len());
        // numerical value bounds are guaranteed by u8 type constraints
    }

    #[test]
    fn test_problem_3() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.problem3, actual_output.problem3);
    }

    #[test]
    fn test_problem_4() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.problem4, actual_output.problem4);
    }

    #[test]
    fn test_problem_5() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.problem5, actual_output.problem5);
    }

    #[test]
    fn test_problem_6() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.problem6, actual_output.problem6);
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
