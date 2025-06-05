use std::fs::File;
use std::io::{Read, Error, ErrorKind};
use std::path::Path;

// SHA-256 constants (cube roots of first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// Initial hash values (square roots of first 8 primes)
const H0: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
];

// Rotate right operation
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

// SHA-256 functions
fn sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

fn sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sigma_upper0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn sigma_upper1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Reads a file into a byte vector
pub fn read_file(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Compares two SHA-256 hashes
pub fn compare_hashes(hash1: &[u8; 32], hash2: &[u8; 32]) -> bool {
    hash1 == hash2
}

/// Displays a hash in hexadecimal format
pub fn display_hash(hash: &[u8; 32]) {
    for byte in hash {
        print!("{:02x}", byte);
    }
    println!();
}

/// Creates the message block with padding
fn create_message_block(message: &[u8]) -> Vec<u8> {
    let msg_len = message.len() as u64;
    let bit_len = msg_len * 8;
    
    // Calculate padding length
    let padding_len = 64 - ((msg_len + 1 + 8) % 64);
    let padding_len = if (msg_len + 1 + 8) % 64 == 0 {
        0
    } else {
        padding_len
    };
    
    let new_len = msg_len + 1 + padding_len as u64 + 8;
    let mut block = vec![0u8; new_len as usize];
    
    // Copy original message
    block[..message.len()].copy_from_slice(message);
    
    // Add padding
    block[message.len()] = 0x80;
    
    // Add length in bits at the end
    for i in 0..8 {
        block[new_len as usize - 8 + i as usize] = (bit_len >> (8 * (7 - i))) as u8;
    }
    
    block
}

/// Processes a 512-bit block
fn process_block(block: &[u8], h: &mut [u32; 8]) {
    let mut w = [0u32; 64];
    create_message_schedule(block, &mut w);
    
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_val = h[7];
    
    for i in 0..64 {
        let temp1 = h_val.wrapping_add(sigma_upper1(e))
            .wrapping_add(choice(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let temp2 = sigma_upper0(a).wrapping_add(majority(a, b, c));
        
        h_val = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_val);
}

/// Creates the message schedule
fn create_message_schedule(block: &[u8], w: &mut [u32; 64]) {
    for i in 0..16 {
        w[i] = ((block[i * 4] as u32) << 24)
            | ((block[i * 4 + 1] as u32) << 16)
            | ((block[i * 4 + 2] as u32) << 8)
            | (block[i * 4 + 3] as u32);
    }
    
    for i in 16..64 {
        w[i] = sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }
}

/// Computes the SHA-256 hash of a message
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let blocks = create_message_block(message);
    let mut h = H0;
    
    // Process each 64-byte (512-bit) block
    for chunk in blocks.chunks(64) {
        process_block(chunk, &mut h);
    }
    
    // Convert the hash to byte array
    let mut hash = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        hash[i * 4] = (word >> 24) as u8;
        hash[i * 4 + 1] = (word >> 16) as u8;
        hash[i * 4 + 2] = (word >> 8) as u8;
        hash[i * 4 + 3] = word as u8;
    }
    
    hash
}
