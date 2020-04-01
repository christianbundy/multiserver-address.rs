extern crate pest;
#[macro_use]
extern crate pest_derive;

use base64::{decode, DecodeError};
use pest::iterators::Pair;
use pest::Parser;
use snafu::{ResultExt, Snafu};
use ssb_multiformats::multikey::Multikey;
use std::net::{AddrParseError, IpAddr};
use std::num::ParseIntError;
use std::str::FromStr;
use url::{ParseError, Url};

#[derive(Parser)]
#[grammar = "address.pest"]
struct AddressParser;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AddressType {
    Url(Url),
    Ip(IpAddr),
    SocketFilePath(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MultiserverAddress {
    pub pub_key: Option<Multikey>,
    pub port: u16,
    pub address: AddressType,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Could not parse address"))]
    Parse {},
    #[snafu(display("Could parse ip"))]
    IpInvalid { source: AddrParseError },
    #[snafu(display("Could parse url"))]
    UrlInvalid { source: ParseError },
    #[snafu(display("Port was not numeric"))]
    PortNotNumeric { source: ParseIntError },
    #[snafu(display("Could not find network address in string"))]
    NoAddressString {},
    #[snafu(display("Could not find ip in address string"))]
    NoIpString {},
    #[snafu(display("Could not find url in address string"))]
    NoUrlString {},
    #[snafu(display("Could not find pub key in address string"))]
    NoPubKeyString {},
    #[snafu(display("Could not find port in address string"))]
    NoPortString {},
    #[snafu(display("Could not decode pubkey as base64"))]
    PubKeyNotBase64 { source: DecodeError },
}

type Result<T, E = Error> = std::result::Result<T, E>;

fn parse_address(pair: Pair<Rule>) -> Result<MultiserverAddress> {
    let mut protocols = pair.into_inner();
    let mut net = protocols.next().unwrap().into_inner();
    // TODO: Rename `net_data_1`. Which rule is this? Maybe try:
    //   println("{:?}", net_data_1.as_rule());
    let mut net_data_1 = net.next().unwrap().into_inner();
    let _net_name = net_data_1.next().unwrap();
    let mut net_data = net_data_1.next().unwrap().into_inner();
    let net_host = net_data.next().unwrap();
    let net_host_inner = net_host.into_inner().next().unwrap();
    let net_port = net_data.next().unwrap();

    let mut shs = net.next().unwrap().into_inner();
    let _shs_name = shs.next().unwrap();
    let shs_data = shs.next().unwrap();

    let pub_key_str = shs_data.as_str();
    let pub_key_vec = decode(pub_key_str).context(PubKeyNotBase64)?;
    let pub_key_bytes = array_32_from_vec(pub_key_vec);
    let pub_key = Multikey::from_ed25519(&pub_key_bytes);

    let port = u16::from_str(net_port.as_str()).unwrap();
    let address;

    if net_host_inner.as_rule() == Rule::domain_host {
        let url_str = format!("tcp://{}", net_host_inner.as_str());
        let url = Url::parse(&url_str).unwrap();
        address = AddressType::Url(url);
    } else {
        address = AddressType::Ip(net_host_inner.as_str().parse().unwrap());
    }

    Ok(MultiserverAddress {
        address,
        port,
        pub_key: Some(pub_key),
    })
}

impl FromStr for MultiserverAddress {
    type Err = Error;

    fn from_str(st: &str) -> Result<MultiserverAddress> {
        // TODO: Correct variable names below to match grammar
        let multiaddress = AddressParser::parse(Rule::net_multiaddress, st)
            .unwrap_or_else(|e| panic!("{}", e))
            .next()
            .unwrap();

        parse_address(multiaddress)
    }
}

fn array_32_from_vec(vec: Vec<u8>) -> [u8; 32] {
    let mut pub_key_bytes = [0; 32];

    vec.into_iter().enumerate().for_each(|(i, b)| {
        pub_key_bytes[i] = b;
    });

    pub_key_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn multiserver_ipv4_parse_ok() {
        let valid_ms_address =
            "net:192.168.178.17:8008~shs:HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=";

        let address = MultiserverAddress::from_str(valid_ms_address).unwrap();
        assert_eq!(address.port, 8008);
        assert_eq!(
            address.pub_key.unwrap().to_legacy_string(),
            "@HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=.ed25519"
        );
        match address.address {
            AddressType::Ip(add) => assert!(add.is_ipv4()),
            _ => panic!(),
        }
    }
    #[test]
    fn multiserver_ipv6_1_parse_ok() {
        let valid_ms_address = "net:1200:0000:AB00:1234:0000:2552:7777:1313:8008~shs:HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=";
        let address = MultiserverAddress::from_str(valid_ms_address).unwrap();
        assert_eq!(address.port, 8008);
        assert_eq!(
            address.pub_key.unwrap().to_legacy_string(),
            "@HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=.ed25519"
        );
        match address.address {
            AddressType::Ip(add) => assert!(add.is_ipv6()),
            _ => panic!(),
        }
    }
    #[test]
    fn multiserver_ipv6_2_parse_ok() {
        let valid_ms_address = "net:21DA:D3:0:2F3B:2AA:FF:FE28:9C5A:8008~shs:HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=";
        let address = MultiserverAddress::from_str(valid_ms_address).unwrap();
        assert_eq!(address.port, 8008);
        assert_eq!(
            address.pub_key.unwrap().to_legacy_string(),
            "@HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=.ed25519"
        );
        match address.address {
            AddressType::Ip(add) => assert!(add.is_ipv6()),
            _ => panic!(),
        }
    }
    #[test]
    fn multiserver_ipv6_3_parse_ok() {
        let valid_ms_address = "net:FE80:0000:0000:0000:0202:B3FF:FE1E:8329:8008~shs:HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=";
        let address = MultiserverAddress::from_str(valid_ms_address).unwrap();
        assert_eq!(address.port, 8008);
        assert_eq!(
            address.pub_key.unwrap().to_legacy_string(),
            "@HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=.ed25519"
        );
        match address.address {
            AddressType::Ip(add) => assert!(add.is_ipv6()),
            _ => panic!(),
        }
    }
    #[test]
    fn multiserver_url_parse_ok() {
        let valid_ms_address = "net:host.com:8008~shs:HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=";
        let address = MultiserverAddress::from_str(valid_ms_address).unwrap();
        assert_eq!(address.port, 8008);
        assert_eq!(
            address.pub_key.unwrap().to_legacy_string(),
            "@HDOUC17/nBPzbVjT3+nUsLf/4p9lyIChEzMAxrHJQo4=.ed25519"
        );
        match address.address {
            AddressType::Url(_url) => (),
            _ => panic!(),
        };
    }
}
