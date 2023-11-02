use serde_json::Value;
use std::env;

// Available if you need it!
// use serde_bencode

fn decode_bencoded_value(encoded_value: &str) -> Value {
    match encoded_value.chars().next().unwrap() {
        '0'..='9' => {
            // Example: "5:hello" -> "hello"
            let (len, rest) = encoded_value.split_once(':').unwrap();
            let len = len.parse::<usize>().unwrap();
            let string = &rest[..len];
            Value::String(string.into())
        }
        'i' => {
            // Example: "i52e" -> 52
            let (number, _) = encoded_value[1..].split_once('e').unwrap();
            let number = number.parse::<i64>().unwrap();
            Value::Number(number.into())
        }
        _ => panic!("Unhandled encoded value: {}", encoded_value),
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value);
    } else {
        println!("unknown command: {}", command)
    }
}
