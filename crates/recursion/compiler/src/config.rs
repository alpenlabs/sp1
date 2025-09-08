use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_sect_fr::SectFr;
use sp1_stark::{InnerChallenge, InnerVal};

use crate::{circuit::AsmConfig, prelude::Config};

pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;

impl Config for OuterConfig {
    type N = SectFr;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}
