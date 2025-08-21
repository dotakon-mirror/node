use crate::bits;
use crate::utils;
use ff::Field;
use halo2_gadgets::poseidon;
use halo2_poseidon::{ConstantLength, P128Pow5T3};
use halo2_proofs::{circuit, plonk, poly};
use pasta_curves::pallas::Scalar;
use primitive_types::U256;

pub type AssignedCell = circuit::AssignedCell<Scalar, Scalar>;

pub type PoseidonConfig = poseidon::Pow5Config<Scalar, 3, 2>;

/// Makes a configuration for a `PoseidonChip`.
pub fn configure_poseidon(cs: &mut plonk::ConstraintSystem<Scalar>) -> PoseidonConfig {
    let state = std::array::from_fn(|_| cs.advice_column());
    let partial_sbox = cs.advice_column();
    let rc_a = std::array::from_fn(|_| {
        let column = cs.fixed_column();
        cs.enable_constant(column);
        column
    });
    let rc_b = std::array::from_fn(|_| {
        let column = cs.fixed_column();
        cs.enable_constant(column);
        column
    });
    poseidon::Pow5Chip::configure::<P128Pow5T3>(cs, state, partial_sbox, rc_a, rc_b)
}

/// Simple Poseidon hasher with default settings.
#[derive(Debug)]
pub struct PoseidonChip<const L: usize> {
    config: PoseidonConfig,
}

impl<const L: usize> PoseidonChip<L> {
    pub fn configure(cs: &mut plonk::ConstraintSystem<Scalar>) -> PoseidonConfig {
        configure_poseidon(cs)
    }

    pub fn construct(config: PoseidonConfig) -> Self {
        Self { config }
    }

    pub fn assign(
        &self,
        layouter: &mut impl circuit::Layouter<Scalar>,
        inputs: [AssignedCell; L],
    ) -> Result<AssignedCell, plonk::Error> {
        let poseidon = poseidon::Pow5Chip::construct(self.config.clone());
        let hasher = poseidon::Hash::<Scalar, _, P128Pow5T3, ConstantLength<L>, 3, 2>::init(
            poseidon,
            layouter.namespace(|| format!("Poseidon::<{}>::init()", L)),
        )?;
        hasher.hash(
            layouter.namespace(|| format!("Poseidon::<{}>::hash()", L)),
            inputs,
        )
    }
}

#[derive(Debug, Clone)]
pub struct BitDecomposerConfig<const N: usize> {
    value: plonk::Column<plonk::Advice>,
    bit_selector: plonk::Selector,
    sum_selector: plonk::Selector,
}

/// Decomposes a scalar into `N` bits in little-endian order (bit #0 is the LBS, bit #N-1 is the
/// MSB).
///
/// This chip requires N > 0 and will panic if that's not the case.
///
/// WARNING: this chip doesn't check that the resulting decomposition is less than the field order,
/// so it's unsafe if you're trying to decompose 255 or more bits. Decomposing to 254 or less bits
/// is always safe.
///
/// NOTE: to decompose a value into 256 bits you can use the `FullBitDecomposerChip` below.
/// Decomposing into 255 bits is not possible because it would require range-checking against a
/// 256-bit value anyway.
#[derive(Debug)]
pub struct BitDecomposerChip<const N: usize> {
    config: BitDecomposerConfig<N>,
}

impl<const N: usize> BitDecomposerChip<N> {
    pub fn configure(
        cs: &mut plonk::ConstraintSystem<Scalar>,
        value: plonk::Column<plonk::Advice>,
    ) -> BitDecomposerConfig<N> {
        assert!(N > 0);
        cs.enable_equality(value);
        let bit_selector = cs.selector();
        cs.create_gate("bit", |cells| {
            let selector = cells.query_selector(bit_selector);
            let bit1 = cells.query_advice(value, poly::Rotation::cur());
            let bit2 = bit1.clone();
            vec![selector.clone() * bit1 * (plonk::Expression::Constant(1.into()) - bit2)]
        });
        let sum_selector = cs.selector();
        cs.create_gate("sum", |cells| {
            let selector = cells.query_selector(sum_selector);
            let mut total = cells.query_advice(value, poly::Rotation(0));
            let mut power = 1.into();
            for i in 1..=N {
                let bit = cells.query_advice(value, poly::Rotation(i as i32));
                total = total - plonk::Expression::Constant(power) * bit;
                power += power;
            }
            vec![selector * total]
        });
        BitDecomposerConfig {
            value,
            bit_selector,
            sum_selector,
        }
    }

    pub fn construct(config: BitDecomposerConfig<N>) -> Self {
        Self { config }
    }

    pub fn assign(
        &self,
        layouter: &mut impl circuit::Layouter<Scalar>,
        input: AssignedCell,
    ) -> Result<[AssignedCell; N], plonk::Error> {
        assert!(N > 0);
        Ok(layouter
            .assign_region(
                || "decompose",
                |mut region| {
                    self.config.sum_selector.enable(&mut region, 0)?;
                    let value = region.assign_advice(
                        || "load_value",
                        self.config.value,
                        0,
                        || input.value().cloned(),
                    )?;
                    region.constrain_equal(value.cell(), input.cell())?;
                    let mut value = value.value().cloned();
                    Ok((0..N)
                        .map(|i| {
                            self.config.bit_selector.enable(&mut region, i + 1)?;
                            let bit = value.map(bits::and1);
                            value = value.map(bits::shr1);
                            region.assign_advice(|| "extract_bit", self.config.value, i + 1, || bit)
                        })
                        .collect::<Result<Vec<_>, _>>()?)
                },
            )?
            .try_into()
            .unwrap())
    }
}

impl<const N: usize> circuit::Chip<Scalar> for BitDecomposerChip<N> {
    type Config = BitDecomposerConfig<N>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Debug, Clone)]
pub struct BitComparatorConfig<const N: usize> {
    left: plonk::Column<plonk::Advice>,
    right: plonk::Column<plonk::Advice>,
    cmp: plonk::Column<plonk::Advice>,
    half_selector: plonk::Selector,
    full_selector: plonk::Selector,
}

/// Compares two scalars X and Y that have been decomposed into `N` bits each (in little-endian
/// order).
///
/// The output signal is:
///
///   -1 if X < Y,
///    0 if X == Y,
///    1 if X > Y.
///
/// Note that in modular arithmetic -1 is rendered as p-1, with p being the field order.
///
/// This chip requires N > 0 and will panic if that's not the case.
///
/// NOTE: this chip doesn't constrain the booleanity of the input bits, so the outer circuit is in
/// charge of ensuring that. The `BitDecomposerChip` is guaranteed to output boolean bits, so no
/// additional constraints are needed if both inputs come directly from the decomposer.
#[derive(Debug)]
pub struct BitComparatorChip<const N: usize> {
    config: BitComparatorConfig<N>,
}

impl<const N: usize> BitComparatorChip<N> {
    pub fn configure(
        cs: &mut plonk::ConstraintSystem<Scalar>,
        left: plonk::Column<plonk::Advice>,
        right: plonk::Column<plonk::Advice>,
        cmp: plonk::Column<plonk::Advice>,
    ) -> BitComparatorConfig<N> {
        assert!(N > 0);
        cs.enable_equality(left);
        cs.enable_equality(right);
        let half_selector = cs.selector();
        cs.create_gate("half_cmp", |cells| {
            let selector = cells.query_selector(half_selector);
            let left = cells.query_advice(left, poly::Rotation::cur());
            let right = cells.query_advice(right, poly::Rotation::cur());
            let cmp = cells.query_advice(cmp, poly::Rotation::cur());
            vec![selector * (cmp - left + right)]
        });
        let full_selector = cs.selector();
        cs.create_gate("full_cmp", |cells| {
            let selector = cells.query_selector(full_selector);
            let left = cells.query_advice(left, poly::Rotation::cur());
            let right = cells.query_advice(right, poly::Rotation::cur());
            let prev = cells.query_advice(cmp, poly::Rotation::next());
            let curr = cells.query_advice(cmp, poly::Rotation::cur());
            vec![
                selector
                    * (curr
                        - prev.clone()
                        - (plonk::Expression::Constant(1.into()) - prev.square()) * (left - right)),
            ]
        });
        BitComparatorConfig {
            left,
            right,
            cmp,
            half_selector,
            full_selector,
        }
    }

    pub fn construct(config: BitComparatorConfig<N>) -> Self {
        Self { config }
    }

    pub fn assign(
        &self,
        layouter: &mut impl circuit::Layouter<Scalar>,
        left: &[AssignedCell],
        right: &[AssignedCell],
    ) -> Result<AssignedCell, plonk::Error> {
        assert!(N > 0);
        layouter.assign_region(
            || "cmp",
            |mut region| {
                self.config.half_selector.enable(&mut region, N - 1)?;
                let assigned_left = region.assign_advice(
                    || format!("load_left({})", N - 1),
                    self.config.left,
                    N - 1,
                    || left[N - 1].value().cloned(),
                )?;
                region.constrain_equal(assigned_left.cell(), left[N - 1].cell())?;
                let assigned_right = region.assign_advice(
                    || format!("load_right({})", N - 1),
                    self.config.right,
                    N - 1,
                    || right[N - 1].value().cloned(),
                )?;
                region.constrain_equal(assigned_right.cell(), right[N - 1].cell())?;
                let mut out = region.assign_advice(
                    || format!("cmp({})", N - 1),
                    self.config.cmp,
                    N - 1,
                    || assigned_left.value() - assigned_right.value(),
                )?;
                for i in (0..(N - 1)).rev() {
                    self.config.full_selector.enable(&mut region, i)?;
                    let assigned_left = region.assign_advice(
                        || format!("load_left({})", i),
                        self.config.left,
                        i,
                        || left[i].value().cloned(),
                    )?;
                    region.constrain_equal(assigned_left.cell(), left[i].cell())?;
                    let assigned_right = region.assign_advice(
                        || format!("load_right({})", i),
                        self.config.right,
                        i,
                        || right[i].value().cloned(),
                    )?;
                    region.constrain_equal(assigned_right.cell(), right[i].cell())?;
                    let square = out.value().map(|out| out.square());
                    out = region.assign_advice(
                        || format!("cmp({})", i),
                        self.config.cmp,
                        i,
                        || {
                            out.value()
                                + (circuit::Value::known(Scalar::from(1)) - square)
                                    * (assigned_left.value() - assigned_right.value())
                        },
                    )?;
                }
                Ok(out)
            },
        )
    }
}

impl<const N: usize> circuit::Chip<Scalar> for BitComparatorChip<N> {
    type Config = BitComparatorConfig<N>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Debug, Clone)]
pub struct ConstBitComparatorConfig<const N: usize> {
    binary_digits: plonk::Column<plonk::Fixed>,
    value: plonk::Column<plonk::Advice>,
    constant: plonk::Column<plonk::Advice>,
    cmp: plonk::Column<plonk::Advice>,
    half_selector: plonk::Selector,
    full_selector: plonk::Selector,
}

/// A bitwise comparator chip that's optimized for comparisons against a constant value.
///
/// Compared with a regular `BitComparatorChip`, using a `ConstBitComparatorChip` results in `N`
/// less constraints.
///
/// This chip requires N > 0 and will panic if that's not the case.
///
/// NOTE: this chip panics if the decomposition of the provided constant value is larger than `N`
/// bits.
#[derive(Debug)]
pub struct ConstBitComparatorChip<const N: usize> {
    config: ConstBitComparatorConfig<N>,
}

impl<const N: usize> ConstBitComparatorChip<N> {
    pub fn configure(
        cs: &mut plonk::ConstraintSystem<Scalar>,
        binary_digits: plonk::Column<plonk::Fixed>,
        value: plonk::Column<plonk::Advice>,
        constant: plonk::Column<plonk::Advice>,
        cmp: plonk::Column<plonk::Advice>,
    ) -> ConstBitComparatorConfig<N> {
        assert!(N > 0);
        cs.enable_equality(binary_digits);
        cs.enable_equality(value);
        cs.enable_equality(constant);
        let half_selector = cs.selector();
        cs.create_gate("half_cmp", |cells| {
            let selector = cells.query_selector(half_selector);
            let left = cells.query_advice(value, poly::Rotation::cur());
            let right = cells.query_advice(constant, poly::Rotation::cur());
            let cmp = cells.query_advice(cmp, poly::Rotation::cur());
            vec![selector * (cmp - left + right)]
        });
        let full_selector = cs.selector();
        cs.create_gate("full_cmp", |cells| {
            let selector = cells.query_selector(full_selector);
            let left = cells.query_advice(value, poly::Rotation::cur());
            let right = cells.query_advice(constant, poly::Rotation::cur());
            let prev = cells.query_advice(cmp, poly::Rotation::next());
            let curr = cells.query_advice(cmp, poly::Rotation::cur());
            vec![
                selector
                    * (curr
                        - prev.clone()
                        - (plonk::Expression::Constant(1.into()) - prev.square()) * (left - right)),
            ]
        });
        ConstBitComparatorConfig {
            binary_digits,
            value,
            constant,
            cmp,
            half_selector,
            full_selector,
        }
    }

    pub fn construct(config: ConstBitComparatorConfig<N>) -> Self {
        Self { config }
    }

    pub fn assign(
        &self,
        layouter: &mut impl circuit::Layouter<Scalar>,
        input: &[AssignedCell],
        constant: U256,
    ) -> Result<AssignedCell, plonk::Error> {
        assert!(N > 0);
        let (zero, one) = layouter.assign_region(
            || "init_binary_digits",
            |mut region| {
                let zero = region.assign_fixed(
                    || "init_zero",
                    self.config.binary_digits,
                    0,
                    || circuit::Value::known(Scalar::ZERO),
                )?;
                let one = region.assign_fixed(
                    || "init_one",
                    self.config.binary_digits,
                    1,
                    || circuit::Value::known(Scalar::from(1)),
                )?;
                Ok((zero, one))
            },
        )?;
        let const_bits = bits::decompose_bits::<N>(constant);
        layouter.assign_region(
            || "cmp",
            |mut region| {
                self.config.half_selector.enable(&mut region, N - 1)?;
                let assigned_left = region.assign_advice(
                    || format!("load_input({})", N - 1),
                    self.config.value,
                    N - 1,
                    || input[N - 1].value().cloned(),
                )?;
                region.constrain_equal(assigned_left.cell(), input[N - 1].cell())?;
                let assigned_right = region.assign_advice(
                    || format!("load_const({})", N - 1),
                    self.config.constant,
                    N - 1,
                    || circuit::Value::known(const_bits[N - 1]),
                )?;
                if const_bits[N - 1] != Scalar::ZERO {
                    region.constrain_equal(assigned_right.cell(), one.cell())?;
                } else {
                    region.constrain_equal(assigned_right.cell(), zero.cell())?;
                }
                let mut out = region.assign_advice(
                    || format!("cmp({})", N - 1),
                    self.config.cmp,
                    N - 1,
                    || assigned_left.value() - assigned_right.value(),
                )?;
                for i in (0..(N - 1)).rev() {
                    self.config.full_selector.enable(&mut region, i)?;
                    let assigned_left = region.assign_advice(
                        || format!("load_input({})", i),
                        self.config.value,
                        i,
                        || input[i].value().cloned(),
                    )?;
                    region.constrain_equal(assigned_left.cell(), input[i].cell())?;
                    let assigned_right = region.assign_advice(
                        || format!("load_const({})", i),
                        self.config.constant,
                        i,
                        || circuit::Value::known(const_bits[i]),
                    )?;
                    if const_bits[i] != Scalar::ZERO {
                        region.constrain_equal(assigned_right.cell(), one.cell())?;
                    } else {
                        region.constrain_equal(assigned_right.cell(), zero.cell())?;
                    }
                    let square = out.value().map(|out| out.square());
                    out = region.assign_advice(
                        || format!("cmp({})", i),
                        self.config.cmp,
                        i,
                        || {
                            out.value()
                                + (circuit::Value::known(Scalar::from(1)) - square)
                                    * (assigned_left.value() - assigned_right.value())
                        },
                    )?;
                }
                Ok(out)
            },
        )
    }
}

impl<const N: usize> circuit::Chip<Scalar> for ConstBitComparatorChip<N> {
    type Config = ConstBitComparatorConfig<N>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// Decomposes a scalar value into its 256-bit representation.
///
/// To do this securely, the chip not only decomposes the 256 bits, it also performs a bitwise
/// comparison with q (the field order). This prevents aliasing, e.g. it guarantees that 4 gets
/// decomposed into the bit representation of 4 rather than q+4.
#[derive(Debug, Clone)]
pub struct FullBitDecomposerConfig {
    constants: plonk::Column<plonk::Fixed>,
    value: plonk::Column<plonk::Advice>,
    range: plonk::Column<plonk::Advice>,
    cmp: plonk::Column<plonk::Advice>,
    bit_selector: plonk::Selector,
    sum_selector: plonk::Selector,
    half_cmp_selector: plonk::Selector,
    full_cmp_selector: plonk::Selector,
    range_check_selector: plonk::Selector,
}

#[derive(Debug)]
pub struct FullBitDecomposerChip {
    config: FullBitDecomposerConfig,
}

impl FullBitDecomposerChip {
    pub fn configure(
        cs: &mut plonk::ConstraintSystem<Scalar>,
        constants: plonk::Column<plonk::Fixed>,
        value: plonk::Column<plonk::Advice>,
        range: plonk::Column<plonk::Advice>,
        cmp: plonk::Column<plonk::Advice>,
    ) -> FullBitDecomposerConfig {
        cs.enable_equality(constants);
        cs.enable_equality(value);
        cs.enable_equality(range);
        let bit_selector = cs.selector();
        cs.create_gate("bit", |cells| {
            let selector = cells.query_selector(bit_selector);
            let bit1 = cells.query_advice(value, poly::Rotation::cur());
            let bit2 = bit1.clone();
            vec![selector.clone() * bit1 * (plonk::Expression::Constant(1.into()) - bit2)]
        });
        let sum_selector = cs.selector();
        cs.create_gate("sum", |cells| {
            let selector = cells.query_selector(sum_selector);
            let mut total = cells.query_advice(value, poly::Rotation(0));
            let mut power = 1.into();
            for i in 1..=256 {
                let bit = cells.query_advice(value, poly::Rotation(i as i32));
                total = total - plonk::Expression::Constant(power) * bit;
                power += power;
            }
            vec![selector * total]
        });
        let half_cmp_selector = cs.selector();
        cs.create_gate("half_cmp", |cells| {
            let selector = cells.query_selector(half_cmp_selector);
            let left = cells.query_advice(value, poly::Rotation::cur());
            let right = cells.query_advice(range, poly::Rotation::cur());
            let cmp = cells.query_advice(cmp, poly::Rotation::cur());
            vec![selector * (cmp - left + right)]
        });
        let full_cmp_selector = cs.selector();
        cs.create_gate("full_cmp", |cells| {
            let selector = cells.query_selector(full_cmp_selector);
            let left = cells.query_advice(value, poly::Rotation::cur());
            let right = cells.query_advice(range, poly::Rotation::cur());
            let prev = cells.query_advice(cmp, poly::Rotation::next());
            let curr = cells.query_advice(cmp, poly::Rotation::cur());
            vec![
                selector
                    * (curr
                        - prev.clone()
                        - (plonk::Expression::Constant(1.into()) - prev.square()) * (left - right)),
            ]
        });
        let range_check_selector = cs.selector();
        cs.create_gate("check_range", |cells| {
            let selector = cells.query_selector(range_check_selector);
            let cmp = cells.query_advice(cmp, poly::Rotation::cur());
            vec![selector * (cmp + plonk::Expression::Constant(1.into()))]
        });
        FullBitDecomposerConfig {
            constants,
            value,
            range,
            cmp,
            bit_selector,
            sum_selector,
            half_cmp_selector,
            full_cmp_selector,
            range_check_selector,
        }
    }

    pub fn construct(config: FullBitDecomposerConfig) -> Self {
        Self { config }
    }

    pub fn assign(
        &self,
        layouter: &mut impl circuit::Layouter<Scalar>,
        input: AssignedCell,
    ) -> Result<[AssignedCell; 256], plonk::Error> {
        let (zero, one) = layouter.assign_region(
            || "init_constants",
            |mut region| {
                let zero = region.assign_fixed(
                    || "init_zero",
                    self.config.constants,
                    0,
                    || circuit::Value::known(Scalar::ZERO),
                )?;
                let one = region.assign_fixed(
                    || "init_one",
                    self.config.constants,
                    1,
                    || circuit::Value::known(Scalar::from(1)),
                )?;
                Ok((zero, one))
            },
        )?;
        let range_bits = bits::decompose_bits::<256>(utils::pallas_scalar_modulus());
        Ok(layouter
            .assign_region(
                || "decompose",
                |mut region| {
                    self.config.sum_selector.enable(&mut region, 0)?;
                    self.config.range_check_selector.enable(&mut region, 1)?;
                    let value = region.assign_advice(
                        || "load_value",
                        self.config.value,
                        0,
                        || input.value().cloned(),
                    )?;
                    region.constrain_equal(value.cell(), input.cell())?;
                    let mut value = value.value().cloned();
                    let bits = (0..256)
                        .map(|i| {
                            self.config.bit_selector.enable(&mut region, i + 1)?;
                            let bit = value.map(bits::and1);
                            value = value.map(bits::shr1);
                            region.assign_advice(|| "extract_bit", self.config.value, i + 1, || bit)
                        })
                        .collect::<Result<Vec<_>, plonk::Error>>()?;
                    let range_bit_cells = (0..256)
                        .map(|i| {
                            let bit = region.assign_advice(
                                || "init_range_bit",
                                self.config.range,
                                i + 1,
                                || circuit::Value::known(range_bits[i]),
                            )?;
                            if range_bits[i] != Scalar::ZERO {
                                region.constrain_equal(bit.cell(), one.cell())?;
                            } else {
                                region.constrain_equal(bit.cell(), zero.cell())?;
                            }
                            Ok(bit)
                        })
                        .collect::<Result<Vec<_>, plonk::Error>>()?;
                    self.config.half_cmp_selector.enable(&mut region, 256)?;
                    let mut cmp = region.assign_advice(
                        || "cmp",
                        self.config.cmp,
                        256,
                        || bits[255].value() - range_bit_cells[255].value(),
                    )?;
                    for i in (0..255).rev() {
                        self.config.full_cmp_selector.enable(&mut region, i + 1)?;
                        let square = cmp.value().map(|cmp| cmp.square());
                        cmp = region.assign_advice(
                            || "cmp",
                            self.config.cmp,
                            i + 1,
                            || {
                                cmp.value()
                                    + (circuit::Value::known(Scalar::from(1)) - square)
                                        * (bits[i].value() - range_bit_cells[i].value())
                            },
                        )?;
                    }
                    Ok(bits)
                },
            )?
            .try_into()
            .unwrap())
    }
}

impl circuit::Chip<Scalar> for FullBitDecomposerChip {
    type Config = FullBitDecomposerConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[derive(Debug, Clone)]
    struct PoseidonCircuitConfig<const L: usize> {
        message: [plonk::Column<plonk::Instance>; L],
        inputs: [plonk::Column<plonk::Advice>; L],
        hash: plonk::Column<plonk::Instance>,
        output: plonk::Column<plonk::Advice>,
        chip: PoseidonConfig,
    }

    #[derive(Debug, Default)]
    struct PoseidonCircuit<const L: usize> {}

    impl<const L: usize> PoseidonCircuit<L> {
        fn verify(&self, inputs: [Scalar; L], hash: Scalar) -> Result<()> {
            utils::test::verify_circuit(
                6,
                self,
                inputs
                    .iter()
                    .map(|input| vec![*input])
                    .chain(std::iter::once(vec![hash]))
                    .collect(),
            )
        }
    }

    impl<const L: usize> plonk::Circuit<Scalar> for PoseidonCircuit<L> {
        type Config = PoseidonCircuitConfig<L>;
        type FloorPlanner = circuit::floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut plonk::ConstraintSystem<Scalar>) -> Self::Config {
            let message = std::array::from_fn(|_| {
                let column = cs.instance_column();
                cs.enable_equality(column);
                column
            });
            let inputs = std::array::from_fn(|_| {
                let column = cs.advice_column();
                cs.enable_equality(column);
                column
            });
            let hash = cs.instance_column();
            cs.enable_equality(hash);
            let output = cs.advice_column();
            cs.enable_equality(output);
            let chip = PoseidonChip::<L>::configure(cs);
            PoseidonCircuitConfig {
                message,
                inputs,
                hash,
                output,
                chip,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl circuit::Layouter<Scalar>,
        ) -> std::result::Result<(), plonk::Error> {
            let inputs = layouter
                .assign_region(
                    || "load_inputs",
                    |mut region| {
                        Ok((0..L)
                            .map(|i| {
                                region.assign_advice_from_instance(
                                    || format!("load_input[{}]", i),
                                    config.message[i],
                                    0,
                                    config.inputs[i],
                                    0,
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()?)
                    },
                )?
                .try_into()
                .unwrap();
            let chip = PoseidonChip::<L>::construct(config.chip);
            let hash = chip.assign(&mut layouter.namespace(|| "poseidon"), inputs)?;
            layouter.assign_region(
                || "check_hash",
                |mut region| {
                    let expected = region.assign_advice_from_instance(
                        || "load_hash",
                        config.hash,
                        0,
                        config.output,
                        0,
                    )?;
                    region.constrain_equal(hash.cell(), expected.cell())
                },
            )
        }
    }

    #[test]
    fn test_poseidon_one_input() {
        let circuit = PoseidonCircuit::<1>::default();
        assert!(
            circuit
                .verify(
                    [utils::parse_pallas_scalar(
                        "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    )],
                    utils::parse_pallas_scalar(
                        "0x1a6c849cc37ba32855d46a031f4a460fdb0ebb4ffad67e6466529700f9d1a49d"
                    )
                )
                .is_ok()
        );
        assert!(
            circuit
                .verify(
                    [utils::parse_pallas_scalar(
                        "0x1a6c849cc37ba32855d46a031f4a460fdb0ebb4ffad67e6466529700f9d1a49d"
                    )],
                    utils::parse_pallas_scalar(
                        "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    )
                )
                .is_err()
        );
    }

    #[test]
    fn test_poseidon_two_inputs() {
        let circuit = PoseidonCircuit::<2>::default();
        assert!(
            circuit
                .verify(
                    [
                        utils::parse_pallas_scalar(
                            "0x1a6c849cc37ba32855d46a031f4a460fdb0ebb4ffad67e6466529700f9d1a49d"
                        ),
                        utils::parse_pallas_scalar(
                            "0x0e2f050699b68c307604c2065d89e16f9ffffc5b6121a6c330fbb9fddd45abe0"
                        )
                    ],
                    utils::parse_pallas_scalar(
                        "0x1577d68ba6b7aec999b345a8dda59dab4a68a7b5b491174121a8e60b7d1f69bc"
                    )
                )
                .is_ok()
        );
        assert!(
            circuit
                .verify(
                    [
                        utils::parse_pallas_scalar(
                            "0x1a6c849cc37ba32855d46a031f4a460fdb0ebb4ffad67e6466529700f9d1a49d"
                        ),
                        utils::parse_pallas_scalar(
                            "0x0e2f050699b68c307604c2065d89e16f9ffffc5b6121a6c330fbb9fddd45abe0"
                        )
                    ],
                    utils::parse_pallas_scalar(
                        "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                    )
                )
                .is_err()
        );
    }

    #[derive(Debug, Clone)]
    struct BitDecomposerCircuitConfig<const N: usize> {
        value: plonk::Column<plonk::Instance>,
        bits: plonk::Column<plonk::Instance>,
        chip: BitDecomposerConfig<N>,
    }

    #[derive(Debug, Default)]
    struct BitDecomposerCircuit<const N: usize> {}

    impl<const N: usize> BitDecomposerCircuit<N> {
        fn verify(&self, value: Scalar, bits: [Scalar; N]) -> Result<()> {
            utils::test::verify_circuit(10, self, vec![vec![value], bits.to_vec()])
        }
    }

    impl<const N: usize> plonk::Circuit<Scalar> for BitDecomposerCircuit<N> {
        type Config = BitDecomposerCircuitConfig<N>;
        type FloorPlanner = circuit::floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut plonk::ConstraintSystem<Scalar>) -> Self::Config {
            let value_instance = cs.instance_column();
            let bits_instance = cs.instance_column();
            let value = cs.advice_column();
            cs.enable_equality(value_instance);
            cs.enable_equality(bits_instance);
            cs.enable_equality(value);
            BitDecomposerCircuitConfig {
                value: value_instance,
                bits: bits_instance,
                chip: BitDecomposerChip::configure(cs, value),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl circuit::Layouter<Scalar>,
        ) -> Result<(), plonk::Error> {
            let value = layouter.assign_region(
                || "load",
                |mut region| {
                    region.assign_advice_from_instance(
                        || "load_value",
                        config.value,
                        0,
                        config.chip.value,
                        0,
                    )
                },
            )?;
            let chip = BitDecomposerChip::<N>::construct(config.chip.clone());
            let out = chip.assign(&mut layouter.namespace(|| "decompose"), value)?;
            layouter.assign_region(
                || "check",
                |mut region| {
                    let bits = (0..N)
                        .map(|i| {
                            region.assign_advice_from_instance(
                                || "load_bits",
                                config.bits,
                                i,
                                config.chip.value,
                                i,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    for i in 0..N {
                        region.constrain_equal(out[i].cell(), bits[i].cell())?;
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_one_bit() {
        let circuit = BitDecomposerCircuit::<1>::default();
        assert!(circuit.verify(0.into(), [0.into()]).is_ok());
        assert!(circuit.verify(0.into(), [1.into()]).is_err());
        assert!(circuit.verify(0.into(), [2.into()]).is_err());
        assert!(circuit.verify(0.into(), [3.into()]).is_err());
        assert!(circuit.verify(1.into(), [0.into()]).is_err());
        assert!(circuit.verify(1.into(), [1.into()]).is_ok());
        assert!(circuit.verify(1.into(), [2.into()]).is_err());
        assert!(circuit.verify(1.into(), [3.into()]).is_err());
        assert!(circuit.verify(2.into(), [0.into()]).is_err());
        assert!(circuit.verify(2.into(), [1.into()]).is_err());
        assert!(circuit.verify(3.into(), [0.into()]).is_err());
        assert!(circuit.verify(3.into(), [1.into()]).is_err());
        assert!(circuit.verify(4.into(), [0.into()]).is_err());
        assert!(circuit.verify(4.into(), [1.into()]).is_err());
        assert!(circuit.verify(5.into(), [0.into()]).is_err());
        assert!(circuit.verify(5.into(), [1.into()]).is_err());
    }

    #[test]
    fn test_two_bits() {
        let circuit = BitDecomposerCircuit::<2>::default();
        assert!(circuit.verify(0.into(), [0.into(), 0.into()]).is_ok());
        assert!(circuit.verify(0.into(), [0.into(), 1.into()]).is_err());
        assert!(circuit.verify(0.into(), [0.into(), 2.into()]).is_err());
        assert!(circuit.verify(0.into(), [1.into(), 0.into()]).is_err());
        assert!(circuit.verify(0.into(), [1.into(), 1.into()]).is_err());
        assert!(circuit.verify(0.into(), [1.into(), 2.into()]).is_err());
        assert!(circuit.verify(0.into(), [2.into(), 0.into()]).is_err());
        assert!(circuit.verify(0.into(), [2.into(), 1.into()]).is_err());
        assert!(circuit.verify(0.into(), [2.into(), 2.into()]).is_err());
        assert!(circuit.verify(1.into(), [0.into(), 0.into()]).is_err());
        assert!(circuit.verify(1.into(), [0.into(), 1.into()]).is_err());
        assert!(circuit.verify(1.into(), [0.into(), 2.into()]).is_err());
        assert!(circuit.verify(1.into(), [1.into(), 0.into()]).is_ok());
        assert!(circuit.verify(1.into(), [1.into(), 1.into()]).is_err());
        assert!(circuit.verify(1.into(), [1.into(), 2.into()]).is_err());
        assert!(circuit.verify(1.into(), [2.into(), 0.into()]).is_err());
        assert!(circuit.verify(1.into(), [2.into(), 1.into()]).is_err());
        assert!(circuit.verify(1.into(), [2.into(), 2.into()]).is_err());
        assert!(circuit.verify(2.into(), [0.into(), 0.into()]).is_err());
        assert!(circuit.verify(2.into(), [0.into(), 1.into()]).is_ok());
        assert!(circuit.verify(2.into(), [0.into(), 2.into()]).is_err());
        assert!(circuit.verify(2.into(), [1.into(), 0.into()]).is_err());
        assert!(circuit.verify(2.into(), [1.into(), 1.into()]).is_err());
        assert!(circuit.verify(2.into(), [1.into(), 2.into()]).is_err());
        assert!(circuit.verify(2.into(), [2.into(), 0.into()]).is_err());
        assert!(circuit.verify(2.into(), [2.into(), 1.into()]).is_err());
        assert!(circuit.verify(2.into(), [2.into(), 2.into()]).is_err());
        assert!(circuit.verify(3.into(), [0.into(), 0.into()]).is_err());
        assert!(circuit.verify(3.into(), [0.into(), 1.into()]).is_err());
        assert!(circuit.verify(3.into(), [0.into(), 2.into()]).is_err());
        assert!(circuit.verify(3.into(), [1.into(), 0.into()]).is_err());
        assert!(circuit.verify(3.into(), [1.into(), 1.into()]).is_ok());
        assert!(circuit.verify(3.into(), [1.into(), 2.into()]).is_err());
        assert!(circuit.verify(3.into(), [2.into(), 0.into()]).is_err());
        assert!(circuit.verify(3.into(), [2.into(), 1.into()]).is_err());
        assert!(circuit.verify(3.into(), [2.into(), 2.into()]).is_err());
        assert!(circuit.verify(4.into(), [0.into(), 0.into()]).is_err());
        assert!(circuit.verify(4.into(), [0.into(), 1.into()]).is_err());
        assert!(circuit.verify(4.into(), [0.into(), 2.into()]).is_err());
        assert!(circuit.verify(4.into(), [1.into(), 0.into()]).is_err());
        assert!(circuit.verify(4.into(), [1.into(), 1.into()]).is_err());
        assert!(circuit.verify(4.into(), [1.into(), 2.into()]).is_err());
        assert!(circuit.verify(4.into(), [2.into(), 0.into()]).is_err());
        assert!(circuit.verify(4.into(), [2.into(), 1.into()]).is_err());
        assert!(circuit.verify(4.into(), [2.into(), 2.into()]).is_err());
        assert!(circuit.verify(5.into(), [0.into(), 0.into()]).is_err());
        assert!(circuit.verify(5.into(), [0.into(), 1.into()]).is_err());
        assert!(circuit.verify(5.into(), [0.into(), 2.into()]).is_err());
        assert!(circuit.verify(5.into(), [1.into(), 0.into()]).is_err());
        assert!(circuit.verify(5.into(), [1.into(), 1.into()]).is_err());
        assert!(circuit.verify(5.into(), [1.into(), 2.into()]).is_err());
        assert!(circuit.verify(5.into(), [2.into(), 0.into()]).is_err());
        assert!(circuit.verify(5.into(), [2.into(), 1.into()]).is_err());
        assert!(circuit.verify(5.into(), [2.into(), 2.into()]).is_err());
    }

    #[test]
    fn test_more_than_one_byte() {
        let circuit = BitDecomposerCircuit::<10>::default();
        assert!(
            circuit
                .verify(256.into(), bits::decompose_bits(256.into()))
                .is_ok()
        );
        assert!(
            circuit
                .verify(257.into(), bits::decompose_bits(257.into()))
                .is_ok()
        );
        assert!(
            circuit
                .verify(258.into(), bits::decompose_bits(258.into()))
                .is_ok()
        );
        assert!(
            circuit
                .verify(259.into(), bits::decompose_bits(259.into()))
                .is_ok()
        );
    }

    #[test]
    fn test_256_bits() {
        let circuit = BitDecomposerCircuit::<256>::default();
        let value = utils::parse_pallas_scalar(
            "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        assert!(circuit.verify(value, bits::decompose_scalar(value)).is_ok());
        let value = Scalar::ZERO - Scalar::from(1);
        assert!(circuit.verify(value, bits::decompose_scalar(value)).is_ok());
    }

    #[derive(Debug, Clone)]
    struct BitComparatorCircuitConfig<const N: usize> {
        left: plonk::Column<plonk::Instance>,
        right: plonk::Column<plonk::Instance>,
        expected: plonk::Column<plonk::Instance>,
        cmp: plonk::Column<plonk::Advice>,
        chip: BitComparatorConfig<N>,
    }

    #[derive(Debug, Default)]
    struct BitComparatorCircuit<const N: usize> {}

    impl<const N: usize> BitComparatorCircuit<N> {
        fn verify(&self, left: Scalar, right: Scalar, out: Scalar) -> Result<()> {
            utils::test::verify_circuit(
                10,
                self,
                vec![
                    bits::decompose_scalar::<N>(left).to_vec(),
                    bits::decompose_scalar::<N>(right).to_vec(),
                    vec![out],
                ],
            )
        }
    }

    impl<const N: usize> plonk::Circuit<Scalar> for BitComparatorCircuit<N> {
        type Config = BitComparatorCircuitConfig<N>;
        type FloorPlanner = circuit::floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut plonk::ConstraintSystem<Scalar>) -> Self::Config {
            let left_instance = cs.instance_column();
            cs.enable_equality(left_instance);
            let left = cs.advice_column();
            cs.enable_equality(left);
            let right_instance = cs.instance_column();
            cs.enable_equality(right_instance);
            let right = cs.advice_column();
            cs.enable_equality(right);
            let expected = cs.instance_column();
            cs.enable_equality(expected);
            let cmp = cs.advice_column();
            cs.enable_equality(cmp);
            let chip = BitComparatorChip::<N>::configure(cs, left, right, cmp);
            BitComparatorCircuitConfig {
                left: left_instance,
                right: right_instance,
                expected,
                cmp,
                chip,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl circuit::Layouter<Scalar>,
        ) -> std::result::Result<(), plonk::Error> {
            let (left, right) = layouter.assign_region(
                || "load",
                |mut region| {
                    let left = (0..N)
                        .map(|i| {
                            region.assign_advice_from_instance(
                                || "load_left",
                                config.left,
                                i,
                                config.chip.left,
                                i,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let right = (0..N)
                        .map(|i| {
                            region.assign_advice_from_instance(
                                || "load_right",
                                config.right,
                                i,
                                config.chip.right,
                                i,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((left, right))
                },
            )?;
            let chip = BitComparatorChip::<N>::construct(config.chip);
            let out = chip.assign(
                &mut layouter.namespace(|| "cmp"),
                left.as_slice(),
                right.as_slice(),
            )?;
            layouter.assign_region(
                || "check",
                |mut region| {
                    let expected = region.assign_advice_from_instance(
                        || "load_expected",
                        config.expected,
                        0,
                        config.cmp,
                        0,
                    )?;
                    region.constrain_equal(out.cell(), expected.cell())
                },
            )
        }
    }

    #[test]
    fn test_bit_comparator_one_bit() {
        let circuit = BitComparatorCircuit::<1>::default();
        let lt = Scalar::ZERO - Scalar::from(1);
        let eq = Scalar::ZERO;
        let gt = Scalar::from(1);
        let xx = Scalar::from(2);
        assert!(circuit.verify(0.into(), 0.into(), lt).is_err());
        assert!(circuit.verify(0.into(), 0.into(), eq).is_ok());
        assert!(circuit.verify(0.into(), 0.into(), gt).is_err());
        assert!(circuit.verify(0.into(), 0.into(), xx).is_err());
        assert!(circuit.verify(0.into(), 1.into(), lt).is_ok());
        assert!(circuit.verify(0.into(), 1.into(), eq).is_err());
        assert!(circuit.verify(0.into(), 1.into(), gt).is_err());
        assert!(circuit.verify(0.into(), 1.into(), xx).is_err());
        assert!(circuit.verify(1.into(), 0.into(), lt).is_err());
        assert!(circuit.verify(1.into(), 0.into(), eq).is_err());
        assert!(circuit.verify(1.into(), 0.into(), gt).is_ok());
        assert!(circuit.verify(1.into(), 0.into(), xx).is_err());
        assert!(circuit.verify(1.into(), 1.into(), lt).is_err());
        assert!(circuit.verify(1.into(), 1.into(), eq).is_ok());
        assert!(circuit.verify(1.into(), 1.into(), gt).is_err());
        assert!(circuit.verify(1.into(), 1.into(), xx).is_err());
    }

    #[test]
    fn test_bit_comparator_two_bits() {
        let circuit = BitComparatorCircuit::<2>::default();
        let lt = Scalar::ZERO - Scalar::from(1);
        let eq = Scalar::ZERO;
        let gt = Scalar::from(1);
        assert!(circuit.verify(0.into(), 0.into(), lt).is_err());
        assert!(circuit.verify(0.into(), 0.into(), eq).is_ok());
        assert!(circuit.verify(0.into(), 0.into(), gt).is_err());
        assert!(circuit.verify(0.into(), 1.into(), lt).is_ok());
        assert!(circuit.verify(0.into(), 1.into(), eq).is_err());
        assert!(circuit.verify(0.into(), 1.into(), gt).is_err());
        assert!(circuit.verify(0.into(), 2.into(), lt).is_ok());
        assert!(circuit.verify(0.into(), 2.into(), eq).is_err());
        assert!(circuit.verify(0.into(), 2.into(), gt).is_err());
        assert!(circuit.verify(0.into(), 3.into(), lt).is_ok());
        assert!(circuit.verify(0.into(), 3.into(), eq).is_err());
        assert!(circuit.verify(0.into(), 3.into(), gt).is_err());
        assert!(circuit.verify(1.into(), 0.into(), lt).is_err());
        assert!(circuit.verify(1.into(), 0.into(), eq).is_err());
        assert!(circuit.verify(1.into(), 0.into(), gt).is_ok());
        assert!(circuit.verify(1.into(), 1.into(), lt).is_err());
        assert!(circuit.verify(1.into(), 1.into(), eq).is_ok());
        assert!(circuit.verify(1.into(), 1.into(), gt).is_err());
        assert!(circuit.verify(1.into(), 2.into(), lt).is_ok());
        assert!(circuit.verify(1.into(), 2.into(), eq).is_err());
        assert!(circuit.verify(1.into(), 2.into(), gt).is_err());
        assert!(circuit.verify(1.into(), 3.into(), lt).is_ok());
        assert!(circuit.verify(1.into(), 3.into(), eq).is_err());
        assert!(circuit.verify(1.into(), 3.into(), gt).is_err());
        assert!(circuit.verify(2.into(), 0.into(), lt).is_err());
        assert!(circuit.verify(2.into(), 0.into(), eq).is_err());
        assert!(circuit.verify(2.into(), 0.into(), gt).is_ok());
        assert!(circuit.verify(2.into(), 1.into(), lt).is_err());
        assert!(circuit.verify(2.into(), 1.into(), eq).is_err());
        assert!(circuit.verify(2.into(), 1.into(), gt).is_ok());
        assert!(circuit.verify(2.into(), 2.into(), lt).is_err());
        assert!(circuit.verify(2.into(), 2.into(), eq).is_ok());
        assert!(circuit.verify(2.into(), 2.into(), gt).is_err());
        assert!(circuit.verify(2.into(), 3.into(), lt).is_ok());
        assert!(circuit.verify(2.into(), 3.into(), eq).is_err());
        assert!(circuit.verify(2.into(), 3.into(), gt).is_err());
        assert!(circuit.verify(3.into(), 0.into(), lt).is_err());
        assert!(circuit.verify(3.into(), 0.into(), eq).is_err());
        assert!(circuit.verify(3.into(), 0.into(), gt).is_ok());
        assert!(circuit.verify(3.into(), 1.into(), lt).is_err());
        assert!(circuit.verify(3.into(), 1.into(), eq).is_err());
        assert!(circuit.verify(3.into(), 1.into(), gt).is_ok());
        assert!(circuit.verify(3.into(), 2.into(), lt).is_err());
        assert!(circuit.verify(3.into(), 2.into(), eq).is_err());
        assert!(circuit.verify(3.into(), 2.into(), gt).is_ok());
        assert!(circuit.verify(3.into(), 3.into(), lt).is_err());
        assert!(circuit.verify(3.into(), 3.into(), eq).is_ok());
        assert!(circuit.verify(3.into(), 3.into(), gt).is_err());
    }

    #[test]
    fn test_bit_comparator_large_values() {
        let circuit = BitComparatorCircuit::<256>::default();
        let lt = Scalar::ZERO - Scalar::from(1);
        let eq = Scalar::ZERO;
        let gt = Scalar::from(1);
        let v1 = utils::parse_pallas_scalar(
            "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        let v2 = Scalar::ZERO - Scalar::from(1);
        assert!(circuit.verify(v1, v1, lt).is_err());
        assert!(circuit.verify(v1, v1, eq).is_ok());
        assert!(circuit.verify(v1, v1, gt).is_err());
        assert!(circuit.verify(v1, v2, lt).is_ok());
        assert!(circuit.verify(v1, v2, eq).is_err());
        assert!(circuit.verify(v1, v2, gt).is_err());
        assert!(circuit.verify(v2, v1, lt).is_err());
        assert!(circuit.verify(v2, v1, eq).is_err());
        assert!(circuit.verify(v2, v1, gt).is_ok());
        assert!(circuit.verify(v2, v2, lt).is_err());
        assert!(circuit.verify(v2, v2, eq).is_ok());
        assert!(circuit.verify(v2, v2, gt).is_err());
    }

    #[derive(Debug, Clone)]
    struct ConstBitComparatorCircuitConfig<const N: usize> {
        input: plonk::Column<plonk::Instance>,
        expected: plonk::Column<plonk::Instance>,
        cmp: plonk::Column<plonk::Advice>,
        chip: ConstBitComparatorConfig<N>,
    }

    #[derive(Debug, Default)]
    struct ConstBitComparatorCircuit<const N: usize> {
        constant: Scalar,
    }

    impl<const N: usize> ConstBitComparatorCircuit<N> {
        fn verify(left: Scalar, right: Scalar, out: Scalar) -> Result<()> {
            let circuit = Self { constant: right };
            utils::test::verify_circuit(
                10,
                &circuit,
                vec![bits::decompose_scalar::<N>(left).to_vec(), vec![out]],
            )
        }
    }

    impl<const N: usize> plonk::Circuit<Scalar> for ConstBitComparatorCircuit<N> {
        type Config = ConstBitComparatorCircuitConfig<N>;
        type FloorPlanner = circuit::floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut plonk::ConstraintSystem<Scalar>) -> Self::Config {
            let input = cs.instance_column();
            cs.enable_equality(input);
            let binary_digits = cs.fixed_column();
            let value = cs.advice_column();
            cs.enable_equality(value);
            let constant = cs.advice_column();
            let expected = cs.instance_column();
            cs.enable_equality(expected);
            let cmp = cs.advice_column();
            cs.enable_equality(cmp);
            let chip =
                ConstBitComparatorChip::<N>::configure(cs, binary_digits, value, constant, cmp);
            ConstBitComparatorCircuitConfig {
                input,
                expected,
                cmp,
                chip,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl circuit::Layouter<Scalar>,
        ) -> std::result::Result<(), plonk::Error> {
            let input = layouter.assign_region(
                || "load",
                |mut region| {
                    (0..N)
                        .map(|i| {
                            region.assign_advice_from_instance(
                                || "load_input",
                                config.input,
                                i,
                                config.chip.value,
                                i,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()
                },
            )?;
            let chip = ConstBitComparatorChip::<N>::construct(config.chip);
            let out = chip.assign(
                &mut layouter.namespace(|| "cmp"),
                input.as_slice(),
                utils::pallas_scalar_to_u256(self.constant),
            )?;
            layouter.assign_region(
                || "check",
                |mut region| {
                    let expected = region.assign_advice_from_instance(
                        || "load_expected",
                        config.expected,
                        0,
                        config.cmp,
                        0,
                    )?;
                    region.constrain_equal(out.cell(), expected.cell())
                },
            )
        }
    }

    #[test]
    fn test_const_bit_comparator_one_bit() {
        let lt = Scalar::ZERO - Scalar::from(1);
        let eq = Scalar::ZERO;
        let gt = Scalar::from(1);
        let xx = Scalar::from(2);
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 0.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 0.into(), eq).is_ok());
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 0.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 0.into(), xx).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 1.into(), lt).is_ok());
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 1.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 1.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(0.into(), 1.into(), xx).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 0.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 0.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 0.into(), gt).is_ok());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 0.into(), xx).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 1.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 1.into(), eq).is_ok());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 1.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<1>::verify(1.into(), 1.into(), xx).is_err());
    }

    #[test]
    fn test_const_bit_comparator_two_bits() {
        let lt = Scalar::ZERO - Scalar::from(1);
        let eq = Scalar::ZERO;
        let gt = Scalar::from(1);
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 0.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 0.into(), eq).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 0.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 1.into(), lt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 1.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 1.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 2.into(), lt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 2.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 2.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 3.into(), lt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 3.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(0.into(), 3.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 0.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 0.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 0.into(), gt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 1.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 1.into(), eq).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 1.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 2.into(), lt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 2.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 2.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 3.into(), lt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 3.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(1.into(), 3.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 0.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 0.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 0.into(), gt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 1.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 1.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 1.into(), gt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 2.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 2.into(), eq).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 2.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 3.into(), lt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 3.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(2.into(), 3.into(), gt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 0.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 0.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 0.into(), gt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 1.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 1.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 1.into(), gt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 2.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 2.into(), eq).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 2.into(), gt).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 3.into(), lt).is_err());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 3.into(), eq).is_ok());
        assert!(ConstBitComparatorCircuit::<2>::verify(3.into(), 3.into(), gt).is_err());
    }

    #[test]
    fn test_const_bit_comparator_large_values() {
        let lt = Scalar::ZERO - Scalar::from(1);
        let eq = Scalar::ZERO;
        let gt = Scalar::from(1);
        let v1 = utils::parse_pallas_scalar(
            "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        let v2 = Scalar::ZERO - Scalar::from(1);
        assert!(ConstBitComparatorCircuit::<256>::verify(v1, v1, lt).is_err());
        assert!(ConstBitComparatorCircuit::<256>::verify(v1, v1, eq).is_ok());
        assert!(ConstBitComparatorCircuit::<256>::verify(v1, v1, gt).is_err());
        assert!(ConstBitComparatorCircuit::<256>::verify(v1, v2, lt).is_ok());
        assert!(ConstBitComparatorCircuit::<256>::verify(v1, v2, eq).is_err());
        assert!(ConstBitComparatorCircuit::<256>::verify(v1, v2, gt).is_err());
        assert!(ConstBitComparatorCircuit::<256>::verify(v2, v1, lt).is_err());
        assert!(ConstBitComparatorCircuit::<256>::verify(v2, v1, eq).is_err());
        assert!(ConstBitComparatorCircuit::<256>::verify(v2, v1, gt).is_ok());
        assert!(ConstBitComparatorCircuit::<256>::verify(v2, v2, lt).is_err());
        assert!(ConstBitComparatorCircuit::<256>::verify(v2, v2, eq).is_ok());
        assert!(ConstBitComparatorCircuit::<256>::verify(v2, v2, gt).is_err());
    }

    #[derive(Debug, Clone)]
    struct FullBitDecomposerCircuitConfig {
        value: plonk::Column<plonk::Instance>,
        bits: plonk::Column<plonk::Instance>,
        chip: FullBitDecomposerConfig,
    }

    #[derive(Debug, Default)]
    struct FullBitDecomposerCircuit {}

    impl FullBitDecomposerCircuit {
        fn verify(&self, value: Scalar, decomposition: U256) -> Result<()> {
            utils::test::verify_circuit(
                10,
                self,
                vec![
                    vec![value],
                    bits::decompose_bits::<256>(decomposition).to_vec(),
                ],
            )
        }
    }

    impl plonk::Circuit<Scalar> for FullBitDecomposerCircuit {
        type Config = FullBitDecomposerCircuitConfig;
        type FloorPlanner = circuit::floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut plonk::ConstraintSystem<Scalar>) -> Self::Config {
            let value_instance = cs.instance_column();
            cs.enable_equality(value_instance);
            let bits_instance = cs.instance_column();
            cs.enable_equality(bits_instance);
            let constants = cs.fixed_column();
            let value = cs.advice_column();
            cs.enable_equality(value);
            let range = cs.advice_column();
            let cmp = cs.advice_column();
            FullBitDecomposerCircuitConfig {
                value: value_instance,
                bits: bits_instance,
                chip: FullBitDecomposerChip::configure(cs, constants, value, range, cmp),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl circuit::Layouter<Scalar>,
        ) -> Result<(), plonk::Error> {
            let (value, bits) = layouter.assign_region(
                || "load",
                |mut region| {
                    let value = region.assign_advice_from_instance(
                        || "load_value",
                        config.value,
                        0,
                        config.chip.value,
                        0,
                    )?;
                    let bits = (0..256)
                        .map(|i| {
                            region.assign_advice_from_instance(
                                || "load_bits",
                                config.bits,
                                i,
                                config.chip.value,
                                i + 1,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((value, bits))
                },
            )?;
            let chip = FullBitDecomposerChip::construct(config.chip);
            let out = chip.assign(&mut layouter.namespace(|| "decompose"), value)?;
            layouter.assign_region(
                || "check",
                |mut region| {
                    for i in 0..256 {
                        region.constrain_equal(out[i].cell(), bits[i].cell())?;
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_full_decomposer_zero() {
        let circuit = FullBitDecomposerCircuit::default();
        assert!(circuit.verify(Scalar::ZERO, 0.into()).is_ok());
        assert!(circuit.verify(Scalar::ZERO, 1.into()).is_err());
        assert!(circuit.verify(Scalar::ZERO, 2.into()).is_err());
        assert!(circuit.verify(Scalar::ZERO, 3.into()).is_err());
        assert!(circuit.verify(Scalar::ZERO, 4.into()).is_err());
        let q = utils::pallas_scalar_modulus();
        assert!(circuit.verify(Scalar::ZERO, q - 2).is_err());
        assert!(circuit.verify(Scalar::ZERO, q - 1).is_err());
        assert!(circuit.verify(Scalar::ZERO, q).is_err());
        assert!(circuit.verify(Scalar::ZERO, q + 1).is_err());
        assert!(circuit.verify(Scalar::ZERO, q + 2).is_err());
    }

    #[test]
    fn test_full_decomposer_one() {
        let circuit = FullBitDecomposerCircuit::default();
        assert!(circuit.verify(1.into(), 0.into()).is_err());
        assert!(circuit.verify(1.into(), 1.into()).is_ok());
        assert!(circuit.verify(1.into(), 2.into()).is_err());
        assert!(circuit.verify(1.into(), 3.into()).is_err());
        assert!(circuit.verify(1.into(), 4.into()).is_err());
        let q = utils::pallas_scalar_modulus();
        assert!(circuit.verify(Scalar::ZERO, q - 2).is_err());
        assert!(circuit.verify(Scalar::ZERO, q - 1).is_err());
        assert!(circuit.verify(Scalar::ZERO, q).is_err());
        assert!(circuit.verify(Scalar::ZERO, q + 1).is_err());
        assert!(circuit.verify(Scalar::ZERO, q + 2).is_err());
    }

    #[test]
    fn test_full_decomposer_two() {
        let circuit = FullBitDecomposerCircuit::default();
        assert!(circuit.verify(2.into(), 0.into()).is_err());
        assert!(circuit.verify(2.into(), 1.into()).is_err());
        assert!(circuit.verify(2.into(), 2.into()).is_ok());
        assert!(circuit.verify(2.into(), 3.into()).is_err());
        assert!(circuit.verify(2.into(), 4.into()).is_err());
        let q = utils::pallas_scalar_modulus();
        assert!(circuit.verify(Scalar::ZERO, q - 3).is_err());
        assert!(circuit.verify(Scalar::ZERO, q - 2).is_err());
        assert!(circuit.verify(Scalar::ZERO, q - 1).is_err());
        assert!(circuit.verify(Scalar::ZERO, q).is_err());
        assert!(circuit.verify(Scalar::ZERO, q + 1).is_err());
        assert!(circuit.verify(Scalar::ZERO, q + 2).is_err());
        assert!(circuit.verify(Scalar::ZERO, q + 3).is_err());
    }

    #[test]
    fn test_full_decomposer_with_large_value() {
        let circuit = FullBitDecomposerCircuit::default();
        let value = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let scalar = utils::parse_pallas_scalar(value);
        let value = value.parse::<U256>().unwrap();
        assert!(circuit.verify(scalar, value - 1).is_err());
        assert!(circuit.verify(scalar, value).is_ok());
        assert!(circuit.verify(scalar, value + 1).is_err());
        let q = utils::pallas_scalar_modulus();
        assert!(circuit.verify(scalar, q + value - 1).is_err());
        assert!(circuit.verify(scalar, q + value).is_err());
        assert!(circuit.verify(scalar, q + value + 1).is_err());
    }

    #[test]
    fn test_full_decomposer_with_q_minus_one() {
        let circuit = FullBitDecomposerCircuit::default();
        let value = Scalar::ZERO - Scalar::from(1);
        let q = utils::pallas_scalar_modulus();
        assert!(circuit.verify(value, 0.into()).is_err());
        assert!(circuit.verify(value, 1.into()).is_err());
        assert!(circuit.verify(value, 2.into()).is_err());
        assert!(circuit.verify(value, q - 3).is_err());
        assert!(circuit.verify(value, q - 2).is_err());
        assert!(circuit.verify(value, q - 1).is_ok());
        assert!(circuit.verify(value, q).is_err());
        assert!(circuit.verify(value, q + 1).is_err());
        assert!(circuit.verify(value, q + 2).is_err());
    }
}
