use serde_json::Value;
use std::env;

// Available if you need it!
// use serde_bencode

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
            _ => panic!("Unhandled encoded value: {}", encoded_value),
        }
    }
    let (decoded_value, rest) = inner(encoded_value);
    assert!(rest.is_empty());
    decoded_value
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
