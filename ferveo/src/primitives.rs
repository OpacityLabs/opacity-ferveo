use ark_ec::{pairing::Pairing, AffineRepr};

// pub fn batch_to_projective<A: ark_ec::AffineCurve>(
//     p: &[A],
// ) -> Vec<A::Projective> {
//     p.iter().map(|a| a.into_projective()).collect::<Vec<_>>()
// }

pub fn batch_to_projective_g1<E: Pairing>(p: &[E::G1Affine]) -> Vec<E::G1> {
    p.iter().map(|a| a.into_group()).collect::<Vec<_>>()
}

pub fn batch_to_projective_g2<E: Pairing>(p: &[E::G2Affine]) -> Vec<E::G2> {
    p.iter().map(|a| a.into_group()).collect::<Vec<_>>()
}
