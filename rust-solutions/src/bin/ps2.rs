use std::io::{stdin, stdout};

use serde::{Deserialize, Serialize};

use cs6903::Executable;

fn main() {
    cs6903::ProblemSet::new(&mut stdin(), &mut stdout()).execute();
}

#[derive(Serialize, Deserialize)]
struct InputModExp {
    b: u32,
    e: u32,
    m: Option<u32>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
struct InputKeyInfo {
    g: u32,
    p: u32,
    a: Option<u32>,
    A: Option<u32>,
    B: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct Input {
    problem1: InputModExp,
    problem2: InputModExp,
    problem3: InputKeyInfo,
    problem4: InputKeyInfo,
    problem5: InputKeyInfo,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
struct OutputKeyInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    a: Option<u32>,
    A: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    s: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct Output {
    problem1: u32,
    problem2: u32,
    problem3: OutputKeyInfo,
    problem4: bool,
    problem5: OutputKeyInfo,
}

impl Executable<Input, Output> for cs6903::ProblemSet<'_> {
    fn execute(&mut self) {
        let input_struct: Input = cs6903::ProblemSet::get_input(self.inbuff);
        let output_struct = Output {
            problem1: problem1(&input_struct.problem1),
            problem2: problem2(&input_struct.problem2),
            problem3: problem3(&input_struct.problem3),
            problem4: problem4(&input_struct.problem4),
            problem5: problem5(&input_struct.problem5),
        };
        cs6903::ProblemSet::write_output(&mut self.outbuff, &output_struct);
    }
}

fn problem1(input: &InputModExp) -> u32 {
    cs6903::modexp(input.b, input.e, u32::MAX)
}

fn problem2(input: &InputModExp) -> u32 {
    cs6903::modexp(input.b, input.e, input.m.unwrap())
}

fn problem3(input: &InputKeyInfo) -> OutputKeyInfo {
    let a = input.g + 1 + (cs6903::get_rand_long() % (input.p - input.g - 1) as u64) as u32;
    OutputKeyInfo {
        a: Some(a),
        A: cs6903::modexp(input.g, a, input.p),
        s: None,
    }
}

fn problem4(input: &InputKeyInfo) -> bool {
    input.a.unwrap() > 1
        && input.a.unwrap() > input.g
        && input.a.unwrap() < input.p
        && input.A.unwrap() < input.p
        && input.A.unwrap() == cs6903::modexp(input.g, input.a.unwrap(), input.p)
}

fn problem5(input: &InputKeyInfo) -> OutputKeyInfo {
    let keypair = problem3(input);
    OutputKeyInfo {
        a: None,
        A: keypair.A,
        s: Some(cs6903::modexp(
            input.B.unwrap(),
            keypair.a.unwrap(),
            input.p,
        )),
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_problem_1() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.problem1, actual_output.problem1);
    }

    #[test]
    fn test_problem_2() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.problem2, actual_output.problem2);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_problem_3() {
        let (input, actual_output, _) = do_test();
        let A = cs6903::modexp(
            input.problem3.g,
            actual_output.problem3.a.unwrap(),
            input.problem3.p,
        );
        assert_eq!(A, actual_output.problem3.A);
    }

    #[test]
    fn test_problem_4() {
        let (_, actual_output, expected_output) = do_test();
        assert_eq!(expected_output.problem4, actual_output.problem4);
    }

    #[test]
    fn test_problem_5() {
        let (_, actual_output, _) = do_test();
        assert!(actual_output.problem5.s.unwrap() > 0);
        assert!(actual_output.problem5.A > 0);
        // We don't have access to private exponents, so can't do real validation.
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
