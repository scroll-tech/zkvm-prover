use sp1_build::{BuildArgs, build_program_with_args};

fn main() {
    build_program_with_args(
        "../profile-guest",
        BuildArgs {
            rustflags: vec![
                "--cfg".to_string(),
                r#"getrandom_backend="custom""#.to_string(),
            ],
            ..Default::default()
        },
    )
}
