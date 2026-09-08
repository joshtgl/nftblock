use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    if std::env::var_os("CARGO_FEATURE_XDP").is_none() {
        return Ok(());
    }
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("read Cargo workspace metadata")?;
    let package = packages
        .into_iter()
        .find(|package| package.name.as_str() == "cidrwall-ebpf")
        .ok_or_else(|| anyhow!("cidrwall-ebpf package not found"))?;
    let root_dir = package
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("cidrwall-ebpf manifest has no parent"))?;
    std::env::set_current_dir(root_dir)
        .with_context(|| format!("enter cidrwall-ebpf source directory {root_dir}"))?;
    aya_build::build_ebpf(
        [aya_build::Package {
            name: package.name.as_str(),
            root_dir: root_dir.as_str(),
            features: &["program"],
            ..Default::default()
        }],
        Toolchain::Nightly,
    )
}
