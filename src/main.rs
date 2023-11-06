use clap::{Parser, Subcommand};
use reqwest::{blocking, Url};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::{fs, mem};

// This function doesn't support raw bytes (only UTF-8 strings)
fn decode_bencoded_value(encoded_value: &str) -> Value {
    fn inner(encoded_value: &str) -> (Value, &str) {
        match encoded_value.chars().next().unwrap() {
            '0'..='9' => {
                // Example: "5:hello" -> "hello"
                let (len, rest) = encoded_value.split_once(':').unwrap();
                let len = len.parse::<usize>().unwrap();
                let (string, rest) = rest.split_at(len);
                (Value::String(string.into()), rest)
            }
            'i' => {
                // Example: "i52e" -> 52
                let (number, rest) = encoded_value[1..].split_once('e').unwrap();
                let number = number.parse::<i64>().unwrap();
                (Value::Number(number.into()), rest)
            }
            'l' => {
                // Example: "l5:helloi52ee" -> ["hello",52]
                let mut values = Vec::new();
                let mut rest = &encoded_value[1..]; // skip 'l'
                while !rest.starts_with('e') {
                    let (value, new_rest) = inner(rest);
                    values.push(value);
                    rest = new_rest;
                }
                rest = &rest[1..]; // skip 'e'
                (Value::Array(values), rest)
            }
            'd' => {
                // Example: "d3:foo3:bar5:helloi52ee" -> {"foo":"bar","hello":52}
                let mut pairs = Vec::new();
                let mut rest = &encoded_value[1..]; // skip 'd'
                while !rest.starts_with('e') {
                    let (key, new_rest) = inner(rest);
                    let Value::String(key) = key else { panic!() };
                    let (value, new_rest) = inner(new_rest);
                    pairs.push((key, value));
                    rest = new_rest;
                }
                rest = &rest[1..]; // skip 'e'
                (Value::Object(pairs.into_iter().collect()), rest)
            }
            _ => panic!("Unhandled encoded value: {}", encoded_value),
        }
    }
    let (decoded_value, rest) = inner(encoded_value);
    assert!(rest.is_empty());
    decoded_value
}

const SHA1_LEN: usize = 20;

type Sha1Bytes = [u8; SHA1_LEN];

#[derive(Deserialize)]
struct Torrent {
    announce: String,

    info: TorrentInfo,
}

#[derive(Deserialize, Serialize)]
struct TorrentInfo {
    length: usize,

    name: String,

    #[serde(rename = "piece length")]
    piece_length: usize,

    #[serde(with = "serde_bytes")]
    pieces: TorrentInfoPieces,
}

struct TorrentInfoPieces(Vec<Sha1Bytes>);

impl<'de> serde_bytes::Deserialize<'de> for TorrentInfoPieces {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::Deserialize::deserialize(deserializer)?;

        if bytes.len() % SHA1_LEN != 0 {
            return Err(de::Error::custom("bad length"));
        }
        let byte_arrays = bytes
            // `array_chunks` is unstable
            .chunks_exact(SHA1_LEN)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();

        Ok(Self(byte_arrays))
    }
}

impl serde_bytes::Serialize for TorrentInfoPieces {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let byte_arrays = &self.0;

        // `slice_flatten` is unstable
        fn flatten<const N: usize>(byte_arrays: &[[u8; N]]) -> &[u8] {
            // cannot overflow because `byte_arrays` is already in the address space
            let len = byte_arrays.len() * N;
            // SAFETY: `[T]` is layout-identical to `[T; N]`
            unsafe { std::slice::from_raw_parts(byte_arrays.as_ptr().cast(), len) }
        }
        let bytes = flatten(byte_arrays);

        serde_bytes::Serialize::serialize(bytes, serializer)
    }
}

impl Torrent {
    const LOCAL_PEER_ID: &'static str = "00112233445566778899";

    fn parse_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let contents = fs::read(path)?;
        serde_bencode::from_bytes(&contents).map_err(Into::into)
    }

    fn info_hash(&self) -> Sha1Bytes {
        let encoded_info = serde_bencode::to_bytes(&self.info).unwrap();
        Sha1::digest(encoded_info).into()
    }

    fn discover_peers(&self) -> anyhow::Result<TrackerResponse> {
        let request = TrackerRequest {
            info_hash: self.info_hash(),
            peer_id: Self::LOCAL_PEER_ID.into(),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: self.info.length,
            compact: 1,
        };
        let mut url = Url::parse(&self.announce)?;
        let mut query = serde_urlencoded::to_string(&request)?;
        query.push_str("&info_hash=");
        for b in &request.info_hash {
            write!(&mut query, "%{:02X}", *b)?;
        }
        url.set_query(Some(&query));

        let response = blocking::get(url)?;
        let response = response.bytes()?;
        let response: TrackerResponse = serde_bencode::from_bytes(&response)?;

        Ok(response)
    }

    fn handshake_peer(&self, peer_addr: SocketAddrV4) -> anyhow::Result<Handshake> {
        let mut tcp_stream = TcpStream::connect(peer_addr)?;

        let pstr = b"BitTorrent protocol";
        let ping = Handshake {
            pstrlen: pstr.len().try_into().unwrap(),
            pstr: *pstr,
            reserved: [0; 8],
            info_hash: self.info_hash(),
            peer_id: Self::LOCAL_PEER_ID.as_bytes().try_into().unwrap(),
        };
        tcp_stream.write_all(ping.as_bytes())?;

        let mut pong = Handshake::default_bytes();
        tcp_stream.read_exact(&mut pong)?;
        let pong = Handshake::from_bytes(pong);

        assert_eq!(pong.pstrlen, ping.pstrlen);
        assert_eq!(pong.pstr, ping.pstr);
        // assert_eq!(pong.reserved, ping.reserved);
        assert_eq!(pong.info_hash, ping.info_hash);

        Ok(pong)
    }
}

#[derive(Serialize)]
struct TrackerRequest {
    #[serde(skip)] // sadly enough, serde_urlencoded doesn't support raw bytes (only UTF-8 strings)
    info_hash: Sha1Bytes,

    peer_id: String,

    port: u16,

    uploaded: usize,

    downloaded: usize,

    left: usize,

    compact: u8,
}

#[derive(Deserialize)]
struct TrackerResponse {
    #[allow(dead_code)]
    interval: usize,

    #[serde(with = "serde_bytes")]
    peers: TrackerResponsePeers,
}

struct TrackerResponsePeers(Vec<SocketAddrV4>);

impl<'de> serde_bytes::Deserialize<'de> for TrackerResponsePeers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::Deserialize::deserialize(deserializer)?;

        const IP_LEN: usize = 4;
        const PORT_LEN: usize = 2;
        const CHUNK_LEN: usize = IP_LEN + PORT_LEN;
        if bytes.len() % CHUNK_LEN != 0 {
            return Err(de::Error::custom("bad length"));
        }
        let socket_addrs = bytes
            // `array_chunks` is unstable
            .chunks_exact(CHUNK_LEN)
            .map(|chunk| {
                let chunk: [u8; CHUNK_LEN] = chunk.try_into().unwrap();
                // `split_array` is unstable
                let (ip, port) = chunk.split_at(IP_LEN);
                let ip: [u8; IP_LEN] = ip.try_into().unwrap();
                let port: [u8; PORT_LEN] = port.try_into().unwrap();
                SocketAddrV4::new(ip.into(), u16::from_be_bytes(port))
            })
            .collect();

        Ok(Self(socket_addrs))
    }
}

#[repr(C, packed)]
struct Handshake {
    pstrlen: u8,
    pstr: [u8; 19],
    reserved: [u8; 8],
    info_hash: Sha1Bytes,
    peer_id: [u8; 20],
}

type HandshakeAsBytes = [u8; mem::size_of::<Handshake>()];

impl Handshake {
    fn as_bytes(&self) -> &HandshakeAsBytes {
        let this: *const _ = self;
        let that = this.cast();
        // SAFETY: `Handshake` has the same layout as `[u8; size_of::<Handshake>()]`
        unsafe { &*that }
    }

    fn default_bytes() -> HandshakeAsBytes {
        [0; mem::size_of::<Self>()]
    }

    fn from_bytes(bytes: HandshakeAsBytes) -> Self {
        // SAFETY: sound because we transmute two types with the same layout
        unsafe { mem::transmute(bytes) }
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Decode {
        encoded_value: String,
    },
    Info {
        torrent_path: PathBuf,
    },
    Peers {
        torrent_path: PathBuf,
    },
    Handshake {
        torrent_path: PathBuf,
        peer_addr: SocketAddrV4,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Decode { encoded_value } => {
            let decoded_value = decode_bencoded_value(&encoded_value);
            println!("{}", decoded_value);
        }
        Commands::Info { torrent_path } => {
            let torrent = Torrent::parse_file(torrent_path).unwrap();
            println!("Tracker URL: {}", torrent.announce);
            println!("Length: {}", torrent.info.length);
            println!("Info Hash: {}", hex::encode(torrent.info_hash()));
            println!("Piece Length: {}", torrent.info.piece_length);
            println!("Piece Hashes:");
            for piece_hash in &torrent.info.pieces.0 {
                println!("{}", hex::encode(piece_hash));
            }
        }
        Commands::Peers { torrent_path } => {
            let torrent = Torrent::parse_file(torrent_path).unwrap();
            let tracker_response = torrent.discover_peers().unwrap();
            for peer_addr in &tracker_response.peers.0 {
                println!("{}", peer_addr);
            }
        }
        Commands::Handshake {
            torrent_path,
            peer_addr,
        } => {
            let torrent = Torrent::parse_file(torrent_path).unwrap();
            let pong = torrent.handshake_peer(peer_addr).unwrap();
            println!("Peer ID: {}", hex::encode(pong.peer_id));
        }
    }
}
