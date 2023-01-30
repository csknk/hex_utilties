fn main() -> Result<(), hex_utilities::StringError> {
    let bytes = match hex_utilities::hexstring_to_bytes("deadbeef".to_string()) {
        Ok(bytes) => bytes,
        Err(e) => return Err(e),
    };
    println!("{:?}", bytes);
    Ok(())
}
