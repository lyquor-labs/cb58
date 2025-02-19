// The original avalanchejs reference implementation is here:
// https://github.com/ava-labs/avalanchejs/blob/master/src/utils/base58.ts

use base58::{FromBase58, ToBase58};
use sha2::{Digest, Sha256};

/// Encode the given binary blob.
pub fn cb58_encode<D: AsRef<[u8]>>(data: D) -> String {
    let mut buffer = data.as_ref().to_vec();
    buffer.extend(&Sha256::digest(data)[28..]);
    buffer.to_base58()
}

/// Decode from the given string and check integrity.
pub fn cb58_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut buffer = encoded.from_base58().ok()?;
    let data_len = buffer.len() - 4;
    let (data, checksum) = buffer.split_at(data_len);
    if checksum == &Sha256::digest(data)[28..] {
        buffer.truncate(data_len);
        return Some(buffer);
    }
    None
}

#[test]
fn test_cb58() {
    let checker = |b: Vec<u8>, enc: &str| {
        let mut encoded = cb58_encode(&b);
        assert_eq!(encoded, enc);
        assert_eq!(Some(b), cb58_decode(&encoded));
        let first = encoded.remove(0);
        // just alter the first letter
        if first == 'a' {
            encoded.insert(0, 'b');
        } else {
            encoded.insert(0, 'a');
        }
        assert_eq!(None, cb58_decode(&encoded));
    };
    let cases = [
        (vec![], "45PJLL"),
        (vec![0], "1c7hwa"),
        (vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255], "1NVSVezva3bAtJesnUj"),
    ];
    for (b, enc) in cases {
        checker(b, enc);
    }
}
