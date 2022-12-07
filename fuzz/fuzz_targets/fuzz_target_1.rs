#![no_main]
// #![feature(iter_advance_by)]

use libfuzzer_sys::fuzz_target;


fn parse(data: &[u8]) -> Vec<&[u8]> {
    // Parse incoming data into slices from format:
    // Size N (1 bytes)
    // Value (N bytes)

    let mut res = Vec::new();
    if data.len() < 2 || data.len() > 1024*1024 {
        // Too big or too small data found at this point. Skip it.
        return vec![];
    }

    let mut data = data;
    loop {
        if 2 >= data.len() {
            break;
        }
        let (size, rest) = data.split_at(1);
        data = rest;

        let size = size[0] as usize;
        if size >= data.len() {
            break;
        }
        let (v, rest) = data.split_at(size);
        data = rest;
        res.push(v);
    }
    res
}

fuzz_target!(|data: &[u8]| {
    trussed::virt::with_ram_client("oath", move |client| {
        let mut oath = oath_authenticator::Authenticator::<_>::new(client);
        let mut response = heapless::Vec::<u8, { 3 * 1024 }>::new();

        let commands = parse(data);
        for data in commands {
            if let Ok(command) = iso7816::Command::<{ 10 * 255 }>::try_from(data) {
                response.clear();
                oath.respond(&command, &mut response).ok();
            }
        }

    })
});
