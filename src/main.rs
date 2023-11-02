use serde_json::Value;
use std::env;

// Available if you need it!
// use serde_bencode

fn decode_bencoded_value(encoded_value: &str) -> Value {
    let first_char = encoded_value.chars().next().unwrap();
    if first_char.is_ascii_digit() {
        // Example: "5:hello" -> "hello"
        let (len, rest) = encoded_value.split_once(':').unwrap();
        let len = len.parse::<usize>().unwrap();
        let string = &rest[..len];
        Value::String(string.into())
    } else if first_char == 'i' {
        // Example: "i52e" -> 52
        let (number, _) = encoded_value[1..].split_once('e').unwrap();
        let number = number.parse::<i64>().unwrap();
        Value::Number(number.into())
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
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
