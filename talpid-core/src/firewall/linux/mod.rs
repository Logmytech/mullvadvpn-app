use error_chain::ChainedError;

use super::{Firewall, SecurityPolicy};

mod dns;

use self::dns::LinuxDnsManager;

error_chain! {
    links {
        DnsManager(::dns::Error, ::dns::ErrorKind) #[doc = "DNS error"];
    }
}

/// The Linux implementation for the `Firewall` trait.
pub struct Netfilter {
    dns_manager: LinuxDnsManager,
}

impl Firewall for Netfilter {
    type Error = Error;

    fn new() -> Result<Self> {
        Ok(Netfilter {
            dns_manager: LinuxDnsManager::spawn()?,
        })
    }

    fn apply_policy(&mut self, policy: SecurityPolicy) -> Result<()> {
        match policy {
            SecurityPolicy::Connected { tunnel, .. } => {
                self.dns_manager.configure(vec![tunnel.gateway.into()])?;
            }
            _ => (),
        }

        Ok(())
    }

    fn reset_policy(&mut self) -> Result<()> {
        if let Err(error) = self.dns_manager.restore() {
            warn!("Failed to reset DNS settings: {}", error.display_chain());
        }

        Ok(())
    }
}
