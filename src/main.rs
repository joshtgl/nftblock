use anyhow::Result;
use cidrwall::{
    config::{CleanupTarget, Cli, Config},
    daemon::Daemon,
    netlink::{Backend, NftnlBackend},
    rules::render,
};
use clap::Parser;

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let config = Config::load(&cli)?;
    if let Some(target) = cli.cleanup {
        let cleanup_nft = matches!(target, CleanupTarget::Nftables | CleanupTarget::All);
        let cleanup_xdp = matches!(target, CleanupTarget::Xdp | CleanupTarget::All);
        let mut errors = Vec::new();
        if cleanup_xdp {
            #[cfg(feature = "xdp")]
            if let Err(error) = cidrwall::xdp::XdpManager::cleanup_pinned(&config.xdp) {
                errors.push(anyhow::anyhow!("XDP cleanup failed: {error:#}"));
            }
            #[cfg(not(feature = "xdp"))]
            errors.push(anyhow::anyhow!(
                "this cidrwall build has no XDP cleanup support"
            ));
        }
        if cleanup_nft && let Err(error) = NftnlBackend::new().cleanup(&config) {
            errors.push(anyhow::anyhow!("nftables cleanup failed: {error}"));
        }
        return errors.into_iter().next().map_or(Ok(()), Err);
    }
    if cli.check {
        let zones = config.load_zones()?;
        for rule in render(&config.resolve_rules(&zones)?) {
            println!("nftables: {rule:?}");
        }
        for interface in config.resolve_xdp_interfaces(&zones)? {
            println!("xdp: blocklist=inbound ingress={interface}");
        }
        return Ok(());
    }
    Daemon::new(config, NftnlBackend::new())?.start()
}
