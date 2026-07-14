use clap::Parser;

use jingle::cli::Cli;

fn main() {
    let cli = Cli::parse();
    let json_mode = cli.json;
    let code = match jingle::commands::run(cli) {
        Ok(code) => code,
        Err(err) => {
            jingle::output::error(json_mode, &err);
            err.exit_code()
        }
    };
    std::process::exit(code);
}
