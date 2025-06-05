use rand::Rng;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKey{
    pub e: u64,
    pub n: u64
}

impl PublicKey{
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Self{
        bincode::deserialize(data).unwrap()
    }

}

#[derive(Debug, Clone)]
pub struct PrivateKey{
    pub d: u64,
    pub n: u64
}

pub fn generate_keypair() -> (PublicKey, PrivateKey){
    let (_p, _q, n, tot) = generate_keys();
    let e = choose_random_e(tot);
    let d = modinv(e, tot);

    (
        PublicKey { e, n },  // Chave pública
        PrivateKey { d, n }  // Chave privada
    )
}


//Outras funções
fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

//Exponenciacao modula rapida
pub fn mod_exp(mut base: u64, mut exp: u64, modulo: u64) -> u64 {
    let mut result = 1;
    base = base % modulo;

    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base % modulo;
        }
        base = base * base % modulo;
        exp /= 2;
    }

    result
}

//Escolher P e Q (primos)
pub fn is_prime(n: u64) -> bool{
    if n < 2{
        return false;
    }
    for i in 2..=((n as f64).sqrt() as u64) {
        if n % i == 0 {
            return false;
        }
    }
    true
}

fn generate_small_prime() -> u64 {
    let mut rng = rand::thread_rng();
    loop {
        let n = rng.gen_range(10..100);
        if is_prime(n) {
            return n;
        }
    }
}

pub fn generate_two_distinct_primes() -> (u64, u64) {
    let p = generate_small_prime();
    let mut q = generate_small_prime();

    while q == p {
        q = generate_small_prime();
    }

    (p, q)
}

//Calcular N ( e as outras chaves P e Q tbm)
//Calcular o Tot(N) = (P-1)(Q-1)
pub fn generate_keys() -> (u64, u64, u64, u64) {
    let (p, q) = generate_two_distinct_primes();
    let n = p * q;
    let tot = (p - 1) * (q - 1);
    (p, q, n, tot)
}

//Escolher E para encryptar (Coprimo com tot(N))
pub fn choose_random_e(tot: u64) -> u64 {
    let mut rng = rand::thread_rng();
    loop {
        let e = rng.gen_range(2..tot);
        if gcd(e, tot) == 1 {
            return e;
        }
    }
}

//Calcular D para decryptar (inverso modular de E)
// Algoritmo Estendido de Euclides
fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (gcd, x1, y1) = extended_gcd(b, a % b);
        (gcd, y1, x1 - (a / b) * y1)
    }
}

// Calcula o inverso modular de e mod tot
pub fn modinv(e: u64, tot: u64) -> u64 {
    let (gcd, x, _) = extended_gcd(e as i64, tot as i64);
    if gcd != 1 {
        panic!("E e tot não são coprimos, não existe inverso");
    }
    // Ajusta x para ficar positivo no intervalo mod tot
    ((x % tot as i64 + tot as i64) % tot as i64) as u64
}

//Criptogtrafar e descriptografar
//pub fn encrypt(message: u64, e: u64, n: u64) -> u64 {
//   mod_exp(message, e, n)
//}

pub fn encrypt_string(mensagem: &str, e: u64, n: u64) -> Vec<u64> {
    mensagem.chars().map(|c| {
        let m = c as u8 as u64;
        mod_exp(m, e, n)
    }).collect()
}


//pub fn decrypt(cipher: u64, d: u64, n: u64) -> u64 {
//    mod_exp(cipher, d, n)
//}

pub fn decrypt_string(criptografado: &[u64], d: u64, n: u64) -> String {
    criptografado.iter().map(|&c| {
        let m = mod_exp(c, d, n);
        m as u8 as char
    }).collect()
}



