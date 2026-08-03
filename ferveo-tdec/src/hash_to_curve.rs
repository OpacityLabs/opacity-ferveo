#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::zero_prefixed_literal)]
#![allow(dead_code)]

use ark_bls12_381::g2::Config;
use ark_ec::{short_weierstrass::Affine, AffineRepr};
use miracl_core::{
    bls12381::{big::BIG, dbig::DBIG, ecp, ecp2::ECP2, fp::FP, fp2::FP2, rom},
    hmac,
};

fn ceil(a: usize, b: usize) -> usize {
    (a - 1) / b + 1
}

fn hash_to_field2_bls12381(
    hash: usize,
    hlen: usize,
    dst: &[u8],
    msg: &[u8],
    ctr: usize,
) -> [miracl_core::bls12381::fp2::FP2; 2] {
    let mut u: [FP2; 2] = [FP2::new(), FP2::new()];

    let q = BIG::new_ints(&rom::MODULUS);
    let k = q.nbits();
    let r = BIG::new_ints(&rom::CURVE_ORDER);
    let m = r.nbits();
    let L = ceil(k + ceil(m, 2), 8);
    let mut okm: [u8; 512] = [0; 512];
    hmac::xmd_expand(hash, hlen, &mut okm, 2 * L * ctr, dst, msg);
    let mut fd: [u8; 256] = [0; 256];
    for i in 0..ctr {
        for j in 0..L {
            fd[j] = okm[2 * i * L + j];
        }
        let mut dx = DBIG::frombytes(&fd[0..L]);
        let w1 = FP::new_big(&dx.dmod(&q));

        for j in 0..L {
            fd[j] = okm[(2 * i + 1) * L + j];
        }
        dx = DBIG::frombytes(&fd[0..L]);
        let w2 = FP::new_big(&dx.dmod(&q));
        u[i].copy(&FP2::new_fps(&w1, &w2));
    }
    u
}

pub fn htp_bls12381_g2(msg: &[u8]) -> ark_bls12_381::G2Affine {
    let dst = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_".as_bytes();
    let u = hash_to_field2_bls12381(hmac::MC_SHA2, ecp::HASH_TYPE, dst, msg, 2);
    let mut P = ECP2::map2point(&u[0]);
    let P1 = ECP2::map2point(&u[1]);
    P.add(&P1);
    P.cfp();
    P.affine();
    /* For arcane reasons, miracl_core uses an extra leading byte,
    which is always set to either 0x02 or 0x03 for compressed representations,
    and set to 0x04 for uncompressed representations.
    Since 2.7.0, miracl_core writes Fp2 as [imaginary BE][real BE]
    (it wrote [real BE][imaginary BE] in 2.3.0), whereas arkworks expects
    [real LE][imaginary LE] — a full byte reversal converts between them. */

    let mut compressed = [0u8; 97];
    P.tobytes(&mut compressed, true);

    let mut compressed_rev = [0u8; 96];
    compressed_rev.clone_from_slice(&compressed[1..]);
    compressed_rev.reverse();

    to_affine(&mut compressed_rev)
}

fn to_affine(compressed_rev: &mut [u8; 96]) -> Affine<Config> {
    // TODO: This is a hack to get around the fact that G2Affine representation produced by miracl_core
    //     is not compatible with the one used by arkworks. The "Unexpected Flag" error is thrown.
    // ark_bls12_381::G2Affine::deserialize_compressed(&compressed_rev[..])
    //     .unwrap()
    // In this workaround we use `from_random_bytes` instead of `deserialize_compressed`, because
    //  the former performs checks that prevent the "Unexpected Flag" error.
    // TODO: Remove expect?
    ark_bls12_381::G2Affine::from_random_bytes(&compressed_rev[..])
        .expect("Failed to convert to affine point")
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Isolated check of the miracl_core -> arkworks byte-order conversion.
    /// Both libraries independently hardcode the standard BLS12-381 G2
    /// generator, so serializing miracl's generator and converting must
    /// reproduce arkworks' generator. The conversion drops miracl's leading
    /// y-parity byte and `to_affine` reconstructs y deterministically, so the
    /// result is the generator up to sign; a byte-order mistake would instead
    /// scramble the x-coordinate entirely.
    #[test]
    fn miracl_serialization_converts_to_arkworks() {
        let mut compressed = [0u8; 97];
        ECP2::generator().tobytes(&mut compressed, true);

        let mut compressed_rev = [0u8; 96];
        compressed_rev.clone_from_slice(&compressed[1..]);
        compressed_rev.reverse();

        let converted = to_affine(&mut compressed_rev);
        let generator = ark_bls12_381::G2Affine::generator();
        assert!(
            converted == generator || converted == -generator,
            "miracl->arkworks byte-order conversion is wrong"
        );
    }

    fn test_hash_to_g2(msg: &[u8], expected_hex_string: &str) {
        let mut expected_compressed = [0u8; 96];
        hex::decode_to_slice(expected_hex_string, &mut expected_compressed)
            .expect("Failed to decode hex");

        let mut expected_compressed_rev = expected_compressed;
        expected_compressed_rev[0] &= (1 << 5) - 1;
        expected_compressed_rev.reverse();

        let expected = to_affine(&mut expected_compressed_rev);
        let res = htp_bls12381_g2(msg);
        assert_eq!(res, expected)
    }

    #[test]
    fn hash_nothing_g2() {
        let msg = b"";
        let expected_hex_string =
            "a5cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a";
        test_hash_to_g2(msg, expected_hex_string)
    }

    #[test]
    fn hash_abc_g2() {
        let msg = b"abc";
        let expected_hex_string =
            "939cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6";
        test_hash_to_g2(msg, expected_hex_string)
    }
}
