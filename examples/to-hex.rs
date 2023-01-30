use hex_utilities::ToHexExt;

fn main() -> Result<(), hex_utilities::StringError> {
    let bytes = vec![0xde,0xad,0xbe,0xef];
    let hexstring = bytes.to_hexstring();
    println!("{}", hexstring);
    Ok(())
}
