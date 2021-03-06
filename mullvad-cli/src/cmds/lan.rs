use clap;
use rpc;
use {Command, Result};

pub struct Lan;

impl Command for Lan {
    fn name(&self) -> &'static str {
        "lan"
    }

    fn clap_subcommand(&self) -> clap::App<'static, 'static> {
        clap::SubCommand::with_name(self.name())
            .about("Control the allow local network sharing setting")
            .setting(clap::AppSettings::SubcommandRequired)
            .subcommand(
                clap::SubCommand::with_name("set")
                    .about("Change allow LAN setting")
                    .arg(
                        clap::Arg::with_name("policy")
                            .required(true)
                            .possible_values(&["allow", "block"]),
                    ),
            )
            .subcommand(
                clap::SubCommand::with_name("get")
                    .about("Display the current local network sharing setting"),
            )
    }

    fn run(&self, matches: &clap::ArgMatches) -> Result<()> {
        if let Some(set_matches) = matches.subcommand_matches("set") {
            let allow_lan = value_t_or_exit!(set_matches.value_of("policy"), String);
            self.set(allow_lan == "allow")
        } else if let Some(_matches) = matches.subcommand_matches("get") {
            self.get()
        } else {
            unreachable!("No lan command given");
        }
    }
}

impl Lan {
    fn set(&self, allow_lan: bool) -> Result<()> {
        rpc::call("set_allow_lan", &[allow_lan]).map(|_: Option<()>| {
            println!("Changed local network sharing setting");
        })
    }

    fn get(&self) -> Result<()> {
        let allow_lan: bool = rpc::call("get_allow_lan", &[] as &[u8; 0])?;
        println!(
            "Local network sharing setting: {}",
            if allow_lan { "allow" } else { "block" }
        );
        Ok(())
    }
}
