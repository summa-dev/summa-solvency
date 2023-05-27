use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::circuit::*;
use num_bigint::BigUint;

fn parse_hex(hex_asm: &str) -> Vec<u8> {
  let mut hex_bytes = hex_asm
      .as_bytes()
      .iter()
      .filter_map(|b| match b {
          b'0'..=b'9' => Some(b - b'0'),
          b'a'..=b'f' => Some(b - b'a' + 10),
          b'A'..=b'F' => Some(b - b'A' + 10),
          _ => None,
      })
      .fuse();

  let mut bytes = Vec::new();
  while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
      bytes.push(h << 4 | l)
  }
  bytes
}

pub fn value_f_to_big_uint(v: Value<Fp>) -> BigUint {
    let mut sum = Fp::zero();
    v.as_ref().map(|f| sum = sum.add(f));

    let sum_str = format!("{:?}", sum);
    let (_, splited_sum_str) = sum_str.split_at(2); // remove '0x'

    BigUint::from_bytes_be(parse_hex(splited_sum_str).as_slice())
}

pub fn decompose_bigint_to_ubits(
    e: &BigUint,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<Fp> {
    debug_assert!(bit_len <= 64);

    let mut e = e.iter_u64_digits();
    let mask: u64 = (1u64 << bit_len) - 1u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                Fp::from(limb)
            }
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                Fp::from(limb)
            }
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1 << (bit_len - rem)) - 1)) << rem; // *
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                Fp::from(limb)
            }
        })
        .collect()
}
