use anyhow::Result;
use clap::Parser;
use nftblock::{
    config::{Cli, Config},
    daemon::Daemon,
    netlink::NftnlBackend,
    rules::render,
};

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let config = Config::load(&cli)?;
    if cli.check {
        let zones = config.load_zones()?;
        for rule in render(&config.resolve_rules(&zones)?) {
            println!("{rule:?}");
        }
        return Ok(());
    }
    Daemon::new(config, NftnlBackend::new())?.start()
}
