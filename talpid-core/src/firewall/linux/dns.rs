extern crate notify;
extern crate resolv_conf;

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;

use self::notify::{RecommendedWatcher, RecursiveMode, Watcher};
use self::resolv_conf::Config;

use dns::{DnsConfig, DnsConfigInterface, DnsConfigManager, DnsConfigMonitor, UpdateSender};

error_chain!{
    errors {
        ParseResolvConf {
            description("failed to parse contents of /etc/resolv.conf")
        }

        ReadResolvConf {
            description("failed to read /etc/resolv.conf")
        }

        WatchResolvConf {
            description("failed to watch /etc/resolv.conf")
        }

        WriteResolvConf {
            description("failed to write to /etc/resolv.conf")
        }
    }
}

static RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

pub type LinuxDnsManager = DnsConfigManager<LinuxDnsInterface, LinuxDnsMonitor>;

impl DnsConfig for Config {
    fn uses_nameservers(&self, nameservers: &Vec<IpAddr>) -> bool {
        let nameserver_ips: Vec<IpAddr> = self.nameservers
            .iter()
            .map(|address| address.into())
            .collect();

        *nameservers == nameserver_ips
    }

    fn set_nameservers(&mut self, nameservers: &Vec<IpAddr>) {
        self.nameservers.clear();
        self.nameservers
            .extend(nameservers.iter().map(|&address| address.into()));
    }

    fn merge_with(&mut self, other: Self) {
        mem::replace(self, other);
    }

    fn merge_ignoring_nameservers(&mut self, mut other: Self) {
        other.nameservers.clear();
        other.nameservers.append(&mut self.nameservers);
        mem::replace(self, other);
    }
}

pub struct LinuxDnsInterface;

impl LinuxDnsInterface {
    fn read_resolv_conf() -> io::Result<String> {
        let mut file = File::open("/etc/resolv.conf")?;
        let mut contents = String::new();

        file.read_to_string(&mut contents)?;

        Ok(contents)
    }

    fn write_resolv_conf(contents: &str) -> io::Result<()> {
        let mut file = File::create("/etc/resolv.conf")?;

        file.write_all(contents.as_bytes())
    }
}

impl DnsConfigInterface for LinuxDnsInterface {
    type Config = Config;
    type Update = ();
    type Error = Error;

    fn open() -> Result<Self> {
        Ok(LinuxDnsInterface)
    }

    fn read_config(&mut self) -> Result<Self::Config> {
        let contents = Self::read_resolv_conf().chain_err(|| ErrorKind::ReadResolvConf)?;

        Config::parse(contents).chain_err(|| ErrorKind::ParseResolvConf)
    }

    fn read_update(&mut self, _: Self::Update) -> Result<Self::Config> {
        self.read_config()
    }

    fn write_config(&mut self, config: Self::Config) -> Result<()> {
        let contents = config.to_string();

        Self::write_resolv_conf(&contents).chain_err(|| ErrorKind::WriteResolvConf)
    }
}

pub struct LinuxDnsMonitor {
    _watcher: RecommendedWatcher,
}

impl DnsConfigMonitor<()> for LinuxDnsMonitor {
    type Error = Error;

    fn spawn(mut event_sink: UpdateSender<()>) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::raw_watcher(tx).chain_err(|| ErrorKind::WatchResolvConf)?;

        watcher
            .watch(RESOLV_CONF_PATH, RecursiveMode::NonRecursive)
            .chain_err(|| ErrorKind::WatchResolvConf)?;

        thread::spawn(move || {
            for _ in rx {
                if event_sink.send(()).is_err() {
                    break;
                }
            }
        });

        Ok(LinuxDnsMonitor { _watcher: watcher })
    }
}
