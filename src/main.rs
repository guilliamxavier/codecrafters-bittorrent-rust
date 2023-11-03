use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::path::Path;
use std::{env, fs};

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
    fn parse_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let contents = fs::read(path)?;
        serde_bencode::from_bytes(&contents).map_err(Into::into)
    }

    fn info_hash(&self) -> Sha1Bytes {
        let encoded_info = serde_bencode::to_bytes(&self.info).unwrap();
        Sha1::digest(encoded_info).into()
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    match command.as_str() {
        "decode" => {
            let encoded_value = &args[2];
            let decoded_value = decode_bencoded_value(encoded_value);
            println!("{}", decoded_value);
        }
        "info" => {
            let torrent_path = &args[2];
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
        _ => println!("unknown command: {}", command),
    }
}
