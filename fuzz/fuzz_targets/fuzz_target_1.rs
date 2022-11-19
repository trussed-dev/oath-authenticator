#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    trussed::virt::with_ram_client("oath", move |client| {
        let mut oath = oath_authenticator::Authenticator::<_>::new(client);
        let mut response = heapless::Vec::<u8, { 3 * 1024 }>::new();

        if let Ok(command) = iso7816::Command::<{ 10 * 255 }>::try_from(&data) {
            oath.respond(&command, &mut response).ok();
        }
    })
});
