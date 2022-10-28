use std::path::{Path, PathBuf};

use clap::Parser;
use clap_num::maybe_hex;

use log::info;
use trussed::platform::{consent, reboot, ui};
use trussed::{virt, Platform};

/// USP/IP based virtualization of the Nitrokey 3 / Solo2 device.
#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// USB Name string
    #[clap(short, long, default_value = "FIDO authenticator")]
    name: String,

    /// USB Manufacturer string
    #[clap(short, long, default_value = "Simulation")]
    manufacturer: String,

    /// USB Serial string
    #[clap(long, default_value = "SIM SIM SIM")]
    serial: String,

    /// Trussed state file
    #[clap(long, default_value = "trussed-state.bin")]
    state_file: PathBuf,

    /// FIDO attestation key
    #[clap(long)]
    fido_key: Option<PathBuf>,

    /// FIDO attestation cert
    #[clap(long)]
    fido_cert: Option<PathBuf>,

    /// USB VID id
    #[clap(short, long, parse(try_from_str=maybe_hex), default_value_t = 0x20a0)]
    vid: u16,
    /// USB PID id
    #[clap(short, long, parse(try_from_str=maybe_hex), default_value_t = 0x42b2)]
    pid: u16,
}

struct Reboot;


struct UserInterface {
    start_time: std::time::Instant,
}

impl UserInterface {
    fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }
}

impl trussed::platform::UserInterface for UserInterface {
    /// Prompt user to type a word for confirmation
    fn check_user_presence(&mut self) -> consent::Level {
        // use std::io::Read as _;
        // This is not nice - we should "peek" and return Level::None
        // if there is no key pressed yet (unbuffered read from stdin).
        // Couldn't get this to work (without pulling in ncurses or similar).
        // std::io::stdin().bytes().next();
        consent::Level::Normal
    }

    fn set_status(&mut self, status: ui::Status) {
        info!("Set status: {:?}", status);

        if status == ui::Status::WaitingForUserPresence {
            info!(">>>> Received confirmation request. Confirming automatically.");
        }
    }

    fn refresh(&mut self) {}

    fn uptime(&mut self) -> core::time::Duration {
        self.start_time.elapsed()
    }

    fn reboot(&mut self, to: reboot::To) -> ! {
        info!("Restart!  ({:?})", to);
        std::process::exit(25);
    }
}

fn main() {
    pretty_env_logger::init();

    let args = Args::parse();

    let store = virt::Filesystem::new(args.state_file);
    let options = trussed_usbip::Options {
        manufacturer: Some(args.manufacturer),
        product: Some(args.name),
        serial_number: Some(args.serial),
        vid: args.vid,
        pid: args.pid,
    };

    log::info!("Initializing Trussed");
    trussed_usbip::Runner::new(store, options)
        .init_platform(move |platform| {
            let ui: Box<dyn trussed::platform::UserInterface> = Box::new(UserInterface::new());
            platform.user_interface().set_inner(ui);
        })
        .add_ctaphid_app("otp", |client| {
            let mut otp_app = oath_authenticator::Authenticator::new(client);
        })
        .exec();
}

fn store_file(platform: &impl Platform, host_file: &Path, device_file: &str) {
    log::info!("Writing {} to file system", device_file);
    let data = std::fs::read(host_file).expect("failed to read file");
    trussed::store::store(
        platform.store(),
        trussed::types::Location::Internal,
        &trussed::types::PathBuf::from(device_file),
        &data,
    )
    .expect("failed to store file");
}
