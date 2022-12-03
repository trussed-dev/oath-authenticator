#![no_main]

use libfuzzer_sys::fuzz_target;


fn parse(data: &[u8]) -> Vec<Vec<u8>> {
    let mut res = Vec::new();
    if data.len() < 2 || data.len() > 1024*1024 {
        return vec![];
    }

    let mut iter = data.into_iter().peekable();
    while iter.peek().is_some() {
        let size = *iter.next().unwrap() as usize;
        let mut v = Vec::new();
        for _i in 0..size {
            if iter.peek().is_none() {
                return vec![];
            }
            v.push(*iter.next().unwrap());
        }
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
            if let Ok(command) = iso7816::Command::<{ 10 * 255 }>::try_from(data.as_slice()) {
                response.clear();
                oath.respond(&command, &mut response).ok();
            }
        }

    })
});
