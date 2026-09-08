// Frozen encoding from locator::encode_record at
// 5da4b0bc8f3ca6f16f9be1b7430e923baad402b9 (0.1.0-alpha.4).
// Only the old record's input access and infallible test error handling differ.
// Never call the production locator encoder here.
pub fn encode(
    desktop_id: &[u8; 16],
    identity_id: &[u8; 16],
    fingerprint: &[u8; 32],
    desktop: &str,
    replay: &str,
    transport: &str,
) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7).unwrap()
        .u16(3).unwrap()
        .bytes(desktop_id).unwrap()
        .bytes(identity_id).unwrap()
        .bytes(fingerprint).unwrap()
        .str(desktop).unwrap()
        .str(replay).unwrap()
        .str(transport).unwrap();
    encoder.into_writer()
}
