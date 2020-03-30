use criterion::{black_box, criterion_group, criterion_main, Criterion};
use multiserver_address_rs::MultiserverAddress;
use std::str::FromStr;

// TODO: Learn why we need to borrow `&input` here.
fn get_addr(input: String) -> MultiserverAddress {
    MultiserverAddress::from_str(&input).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let example = "net:192.168.178.17:8008~shs:HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=";

    // TODO: Learn why we need to run `to_string()` on the string above.
    c.bench_function("parse address", |b| {
        b.iter(|| get_addr(black_box(example.to_string())))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
