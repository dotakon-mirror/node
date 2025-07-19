use crate::dotakon;
use anyhow::Result;
use primitive_types::H256;
use primitive_types::U256;

const MAX_VARINT_LENGTH: usize = 10;

impl prost::Name for dotakon::Bytes32 {
    const NAME: &'static str = "Bytes32";
    const PACKAGE: &'static str = "dotakon";
}

impl prost::Name for dotakon::BlockDescriptor {
    const NAME: &'static str = "BlockDescriptor";
    const PACKAGE: &'static str = "dotakon";
}

impl prost::Name for dotakon::MerkleProof {
    const NAME: &'static str = "MerkleProof";
    const PACKAGE: &'static str = "dotakon";
}

impl prost::Name for dotakon::node_identity::Payload {
    const NAME: &'static str = "NodeIdentity.Payload";
    const PACKAGE: &'static str = "dotakon";
}

impl prost::Name for dotakon::BoundTransaction {
    const NAME: &'static str = "BoundTransaction";
    const PACKAGE: &'static str = "dotakon";
}

impl prost::Name for dotakon::transaction::Payload {
    const NAME: &'static str = "Transaction.Payload";
    const PACKAGE: &'static str = "dotakon";
}

pub fn u256_to_bytes32(value: U256) -> dotakon::Bytes32 {
    let word_vec: Vec<u64> = value
        .to_little_endian()
        .chunks(8)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            u64::from_le_bytes(bytes)
        })
        .collect();
    let mut words = [0u64; 4];
    words.copy_from_slice(word_vec.as_slice());
    dotakon::Bytes32 {
        w1: Some(words[0]),
        w2: Some(words[1]),
        w3: Some(words[2]),
        w4: Some(words[3]),
    }
}

pub fn u256_from_bytes32(proto: &dotakon::Bytes32) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&proto.w1.unwrap_or(0).to_le_bytes());
    bytes[8..16].copy_from_slice(&proto.w2.unwrap_or(0).to_le_bytes());
    bytes[16..24].copy_from_slice(&proto.w3.unwrap_or(0).to_le_bytes());
    bytes[24..32].copy_from_slice(&proto.w4.unwrap_or(0).to_le_bytes());
    U256::from_little_endian(&bytes)
}

pub fn h256_to_bytes32(value: H256) -> dotakon::Bytes32 {
    let word_vec: Vec<u64> = value
        .to_fixed_bytes()
        .chunks(8)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            u64::from_le_bytes(bytes)
        })
        .collect();
    let mut words = [0u64; 4];
    words.copy_from_slice(word_vec.as_slice());
    dotakon::Bytes32 {
        w1: Some(words[0]),
        w2: Some(words[1]),
        w3: Some(words[2]),
        w4: Some(words[3]),
    }
}

pub fn h256_from_bytes32(proto: &dotakon::Bytes32) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&proto.w1.unwrap_or(0).to_le_bytes());
    bytes[8..16].copy_from_slice(&proto.w2.unwrap_or(0).to_le_bytes());
    bytes[16..24].copy_from_slice(&proto.w3.unwrap_or(0).to_le_bytes());
    bytes[24..32].copy_from_slice(&proto.w4.unwrap_or(0).to_le_bytes());
    H256::from_slice(&bytes)
}

fn encode_varint(buffer: &mut Vec<u8>, mut value: usize) {
    while value > 0x7F {
        buffer.push(0x80 | (value & 0x7F) as u8);
        value >>= 7;
    }
    buffer.push((value & 0x7F) as u8);
}

pub fn encode_any_canonical(any: &prost_types::Any) -> Vec<u8> {
    let type_url_bytes = any.type_url.as_bytes();
    let value_bytes = any.value.as_slice();
    let mut buffer = Vec::<u8>::with_capacity(
        (1 + MAX_VARINT_LENGTH) * 2 + type_url_bytes.len() + value_bytes.len(),
    );
    buffer.push(10);
    encode_varint(&mut buffer, type_url_bytes.len());
    buffer.extend_from_slice(type_url_bytes);
    buffer.push(18);
    encode_varint(&mut buffer, value_bytes.len());
    buffer.extend_from_slice(value_bytes);
    buffer
}

pub fn encode_message_canonical<M: prost::Message + prost::Name>(
    message: &M,
) -> Result<(prost_types::Any, Vec<u8>)> {
    let any = prost_types::Any::from_msg(message)?;
    let buffer = encode_any_canonical(&any);
    Ok((any, buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn test_u256_to_bytes32() {
        let value = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let bytes32 = u256_to_bytes32(value);
        assert_eq!(bytes32.w1, Some(0x0807060504030201u64));
        assert_eq!(bytes32.w2, Some(0x100F0E0D0C0B0A09u64));
        assert_eq!(bytes32.w3, Some(0x1817161514131211u64));
        assert_eq!(bytes32.w4, Some(0x201F1E1D1C1B1A19u64));
        assert_eq!(value, u256_from_bytes32(&bytes32));
    }

    #[test]
    fn test_u256_from_bytes32() {
        let value = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        assert_eq!(value, u256_from_bytes32(&u256_to_bytes32(value)));
    }

    #[test]
    fn test_h256_to_bytes32() {
        let value = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let bytes32 = h256_to_bytes32(value);
        assert_eq!(bytes32.w1, Some(0x0807060504030201u64));
        assert_eq!(bytes32.w2, Some(0x100F0E0D0C0B0A09u64));
        assert_eq!(bytes32.w3, Some(0x1817161514131211u64));
        assert_eq!(bytes32.w4, Some(0x201F1E1D1C1B1A19u64));
        assert_eq!(value, h256_from_bytes32(&bytes32));
    }

    #[test]
    fn test_h256_from_bytes32() {
        let value = H256::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        assert_eq!(value, h256_from_bytes32(&h256_to_bytes32(value)));
    }

    #[test]
    fn test_encode_any_canonical() {
        let value = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let any = prost_types::Any::from_msg(&u256_to_bytes32(value)).unwrap();
        let bytes = encode_any_canonical(&any);
        assert_eq!(prost_types::Any::decode(bytes.as_slice()).unwrap(), any);
        let decoded = any.to_msg::<dotakon::Bytes32>().unwrap();
        assert_eq!(value, u256_from_bytes32(&decoded));
    }

    #[test]
    fn test_encode_message_canonical() {
        let value = U256::from_little_endian(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let (any, bytes) = encode_message_canonical(&u256_to_bytes32(value)).unwrap();
        assert_eq!(prost_types::Any::decode(bytes.as_slice()).unwrap(), any);
        let decoded = any.to_msg::<dotakon::Bytes32>().unwrap();
        assert_eq!(value, u256_from_bytes32(&decoded));
    }
}
