use anyhow::anyhow;
use clap::{Parser, Subcommand};
use reqwest::Url;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::{fs, mem, slice};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

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

    #[serde(skip)]
    cached_info_hash: OnceLock<Sha1Bytes>,
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
            unsafe { slice::from_raw_parts(byte_arrays.as_ptr().cast(), len) }
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
        *self.cached_info_hash.get_or_init(|| {
            let encoded_info = serde_bencode::to_bytes(&self.info).unwrap();
            Sha1::digest(encoded_info).into()
        })
    }

    async fn discover_peers(&self) -> anyhow::Result<TrackerResponse> {
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

        let response = reqwest::get(url).await?;
        let response = response.bytes().await?;
        let response: TrackerResponse = serde_bencode::from_bytes(&response)?;

        Ok(response)
    }

    async fn handshake_peer(
        &self,
        peer_addr: SocketAddrV4,
    ) -> anyhow::Result<(Handshake, PeerConnection<false>)> {
        let mut tcp_stream = TcpStream::connect(peer_addr).await?;

        let pstr = b"BitTorrent protocol";
        let ping = Handshake {
            pstrlen: pstr.len().try_into().unwrap(),
            pstr: *pstr,
            reserved: [0; 8],
            info_hash: self.info_hash(),
            peer_id: Self::LOCAL_PEER_ID.as_bytes().try_into().unwrap(),
        };
        tcp_stream.write_all(ping.as_bytes()).await?;

        let mut pong = Handshake::default_bytes();
        tcp_stream.read_exact(&mut pong).await?;
        let pong = Handshake::from_bytes(pong);

        assert_eq!(pong.pstrlen, ping.pstrlen);
        assert_eq!(pong.pstr, ping.pstr);
        // assert_eq!(pong.reserved, ping.reserved);
        assert_eq!(pong.info_hash, ping.info_hash);

        let mut peer_conn = PeerConnection(tcp_stream);

        let bitfield_message = peer_conn.recv().await?;
        let PeerMessage::Bitfield(_) = bitfield_message else {
            return Err(anyhow!("expected Bitfield message, got {:?}", bitfield_message));
        };
        // The bitfield payload is ignored for this challenge, all peers have all pieces available.

        Ok((pong, peer_conn))
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

const BLOCK_LEN: usize = 1 << 14; // 16 KiB

#[derive(Debug)]
#[non_exhaustive]
#[repr(u8)]
enum PeerMessage {
    Bitfield(Vec<u8>) = 5,
    Interested = 2,
    Unchoke = 1,
    Request(PeerMessageRequest) = 6,
    Piece(PeerMessagePiece) = 7,
}

#[derive(Debug, Copy, Clone)]
struct PeerMessageRequest {
    index: u32,
    begin: u32,
    length: u32,
}

#[derive(Debug, Default)]
struct PeerMessagePiece {
    index: u32,
    begin: u32,
    block: Vec<u8>,
}

impl PeerMessage {
    fn id(&self) -> u8 {
        let this: *const _ = self;
        let that = this.cast();
        // SAFETY: `PeerMessage` is a `repr(u8)` enum
        unsafe { *that }
    }
}

// I = interested
struct PeerConnection<const I: bool>(TcpStream);

impl<const I: bool> PeerConnection<I> {
    const PAYLOAD_LEN_MAX: usize = 1 << 16; // 64 KiB

    async fn recv(&mut self) -> anyhow::Result<PeerMessage> {
        let incoming = &mut self.0;

        const U32_LEN: usize = 4;
        async fn read_u32(incoming: &mut TcpStream) -> anyhow::Result<u32> {
            let mut buf = [0; U32_LEN];
            incoming.read_exact(&mut buf).await?;
            Ok(u32::from_be_bytes(buf))
        }
        let len = read_u32(incoming).await?;
        if len == 0 {
            return Err(anyhow!("zero length"));
        }
        let payload_len = len - 1;
        let payload_len: usize = payload_len.try_into().unwrap();
        if payload_len > Self::PAYLOAD_LEN_MAX {
            return Err(anyhow!("length too large"));
        }

        let mut id = 0;
        incoming.read_exact(slice::from_mut(&mut id)).await?;
        match id {
            x if x == PeerMessage::Bitfield(Vec::new()).id() => {
                let mut payload = vec![0; payload_len];
                incoming.read_exact(&mut payload).await?;

                Ok(PeerMessage::Bitfield(payload))
            }
            x if x == PeerMessage::Unchoke.id() => {
                if payload_len != 0 {
                    return Err(anyhow!("unexpected payload"));
                }

                Ok(PeerMessage::Unchoke)
            }
            x if x == PeerMessage::Piece(PeerMessagePiece::default()).id() => {
                let prefix_len = 2 * U32_LEN;
                if payload_len < prefix_len {
                    return Err(anyhow!("length too small"));
                }
                let block_len = payload_len - prefix_len;

                let index = read_u32(incoming).await?;
                let begin = read_u32(incoming).await?;

                let mut block = vec![0; block_len];
                incoming.read_exact(&mut block).await?;

                Ok(PeerMessage::Piece(PeerMessagePiece {
                    index,
                    begin,
                    block,
                }))
            }
            _ => Err(anyhow!("unhandled id {}", id)),
        }
    }

    async fn send(&mut self, message: &PeerMessage) -> anyhow::Result<()> {
        let outgoing = &mut self.0;

        let id = message.id();
        let payload: Vec<u8> = match *message {
            PeerMessage::Interested => Vec::new(),
            PeerMessage::Request(request) => [
                request.index.to_be_bytes(),
                request.begin.to_be_bytes(),
                request.length.to_be_bytes(),
            ]
            .concat(),

            _ => return Err(anyhow!("unhandled message kind {:?}", message)),
        };
        let payload_len = payload.len();
        assert!(payload_len <= Self::PAYLOAD_LEN_MAX);
        let payload_len: u32 = payload_len.try_into().unwrap();
        let len = payload_len + 1;

        outgoing.write_all(&len.to_be_bytes()).await?;
        outgoing.write_all(slice::from_ref(&id)).await?;
        outgoing.write_all(&payload).await?;

        Ok(())
    }
}

impl PeerConnection<false> {
    async fn send_interested(mut self) -> anyhow::Result<PeerConnection<true>> {
        self.send(&PeerMessage::Interested).await?;

        let unchoke_message = self.recv().await?;
        let PeerMessage::Unchoke = unchoke_message else {
            return Err(anyhow!("expected Unchoke message, got {:?}", unchoke_message));
        };

        Ok(PeerConnection(self.0))
    }
}

impl PeerConnection<true> {
    async fn download_piece(
        &mut self,
        torrent: &Torrent,
        piece_index: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let piece_hash = torrent.info.pieces.0[piece_index];

        fn compute_part_len(base: usize, index: usize, nb: usize, total: usize) -> usize {
            assert!(nb > 0);
            assert!(index < nb);
            if index == nb - 1 {
                let rem = total % base;
                if rem != 0 || total == 0 {
                    return rem;
                }
            }
            base
        }
        let piece_len = compute_part_len(
            torrent.info.piece_length,
            piece_index,
            torrent.info.pieces.0.len(),
            torrent.info.length,
        );
        // div_ceil: `int_roundings` is unstable
        let nb_blocks = piece_len / BLOCK_LEN + usize::from(piece_len % BLOCK_LEN != 0);

        let mut blocks_concat = Vec::with_capacity(piece_len);
        for block_index in 0..nb_blocks {
            let block_len = compute_part_len(BLOCK_LEN, block_index, nb_blocks, piece_len);
            let request = PeerMessageRequest {
                index: piece_index.try_into().unwrap(),
                begin: (block_index * BLOCK_LEN).try_into().unwrap(),
                length: block_len.try_into().unwrap(),
            };
            self.send(&PeerMessage::Request(request)).await?;

            let piece_message = self.recv().await?;
            let PeerMessage::Piece(piece) = piece_message else {
                return Err(anyhow!("expected Piece message, got {:?}", piece_message));
            };
            assert_eq!(piece.index, request.index);
            assert_eq!(piece.begin, request.begin);
            assert_eq!(piece.block.len(), block_len);

            blocks_concat.extend(piece.block);
        }

        assert_eq!(blocks_concat.len(), piece_len);
        let blocks_concat_hash: Sha1Bytes = Sha1::digest(&blocks_concat).into();
        if blocks_concat_hash != piece_hash {
            return Err(anyhow!("hashes differ"));
        }

        Ok(blocks_concat)
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[clap(rename_all = "snake_case")]
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
    DownloadPiece {
        #[arg(short)]
        output: PathBuf,

        torrent_path: PathBuf,
        piece_index: usize,
    },
    Download {
        #[arg(short)]
        output: PathBuf,

        torrent_path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
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
            let tracker_response = torrent.discover_peers().await.unwrap();
            for peer_addr in &tracker_response.peers.0 {
                println!("{}", peer_addr);
            }
        }
        Commands::Handshake {
            torrent_path,
            peer_addr,
        } => {
            let torrent = Torrent::parse_file(torrent_path).unwrap();
            let (pong, _) = torrent.handshake_peer(peer_addr).await.unwrap();
            println!("Peer ID: {}", hex::encode(pong.peer_id));
        }
        Commands::DownloadPiece {
            output,
            torrent_path,
            piece_index,
        } => {
            let torrent = Torrent::parse_file(torrent_path).unwrap();
            let tracker_response = torrent.discover_peers().await.unwrap();
            let peer_addr = tracker_response.peers.0[0];
            let (_, peer_conn) = torrent.handshake_peer(peer_addr).await.unwrap();
            let mut peer_conn = peer_conn.send_interested().await.unwrap();
            let piece = peer_conn
                .download_piece(&torrent, piece_index)
                .await
                .unwrap();
            fs::write(&output, piece).unwrap();
            println!("Piece {} downloaded to {}.", piece_index, output.display());
        }
        Commands::Download {
            output,
            torrent_path,
        } => {
            let torrent = Torrent::parse_file(&torrent_path).unwrap();

            let output_file = File::create(&output).unwrap();
            output_file
                .set_len(torrent.info.length.try_into().unwrap())
                .unwrap();

            let tracker_response = torrent.discover_peers().await.unwrap();
            let peer_addrs = tracker_response.peers.0;
            assert!(!peer_addrs.is_empty());

            let max_concurrent_tasks = 5;
            let nb_pieces = torrent.info.pieces.0.len();
            let nb_concurrent_tasks = nb_pieces.min(peer_addrs.len()).min(max_concurrent_tasks);

            let mut tasks = JoinSet::new();
            let torrent: &'static _ = Box::leak(Box::new(torrent));
            for peer_addr in peer_addrs.into_iter().take(nb_concurrent_tasks) {
                tasks.spawn(async move {
                    let (_, peer_conn) = torrent.handshake_peer(peer_addr).await.unwrap();
                    peer_conn.send_interested().await.unwrap()
                });
            }

            let mut output_file: &'static _ = Box::leak(Box::new(output_file));
            for piece_index in 0..nb_pieces {
                let task_result = tasks.join_next().await.unwrap();
                let mut peer_conn = task_result.unwrap();
                tasks.spawn(async move {
                    let piece = peer_conn
                        .download_piece(torrent, piece_index)
                        .await
                        .unwrap();
                    output_file
                        .seek(SeekFrom::Start(
                            (piece_index * torrent.info.piece_length)
                                .try_into()
                                .unwrap(),
                        ))
                        .unwrap();
                    output_file.write_all(&piece).unwrap();
                    peer_conn
                });
            }
            while let Some(task_result) = tasks.join_next().await {
                task_result.unwrap();
            }

            println!(
                "Downloaded {} to {}.",
                torrent_path.display(),
                output.display()
            );
        }
    }
}
