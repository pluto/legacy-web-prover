use acvm::{
  acir::{
    self,
    acir_field::GenericFieldElement,
    circuit::{brillig::BrilligBytecode, Circuit, Opcode, Program},
    native_types::{Witness, WitnessMap},
  },
  blackbox_solver::StubbedBlackBoxSolver,
  pwg::ACVM,
  AcirField,
};
use ark_bn254::Fr;
use bellpepper_core::{
  num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use ff::PrimeField;

use super::*;

#[cfg(test)] mod tests;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirProgram {
  #[serde(
    serialize_with = "Program::serialize_program_base64",
    deserialize_with = "Program::deserialize_program_base64"
  )]
  pub bytecode: Program<GenericFieldElement<Fr>>,
  pub witness:  Option<Vec<F<G1>>>,
  // TODO: To make this more efficient, we could just store an option of the `&mut CS` inside of
  // here so we don't actually need to rebuild it always, though the enforcement for the public
  // inputs is tougher
}

impl NoirProgram {
  pub fn new(bin: &[u8]) -> Self { serde_json::from_slice(bin).unwrap() }

  pub fn arity(&self) -> usize { dbg!(self.circuit().public_parameters.0.len()) }

  pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> { &self.bytecode.functions[0] }

  pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
    &self.bytecode.unconstrained_functions
  }

  pub fn set_private_inputs(&mut self, inputs: Vec<F<G1>>) { self.witness = Some(inputs); }

  // TODO: we now need to shift this to use the `z` values as the sole public inputs, the struct
  // should only hold witness
  // tell clippy to shut up
  #[allow(clippy::too_many_lines)]
  pub fn vanilla_synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<Vec<AllocatedNum<F<G1>>>, SynthesisError> {
    let mut acvm = if self.witness.is_some() {
      Some(ACVM::new(
        &StubbedBlackBoxSolver(false),
        &self.circuit().opcodes,
        WitnessMap::new(),
        self.unconstrained_functions(),
        &[],
      ))
    } else {
      None
    };
    dbg!(self.circuit().private_parameters.len());
    dbg!(self.circuit().public_parameters.0.len());
    dbg!(self.circuit().return_values.0.len());

    // For folding in particular:
    assert_eq!(self.circuit().return_values.0.len(), self.circuit().public_parameters.0.len());

    // TODO: we could probably avoid this but i'm lazy
    // Create a map to track allocated variables for the cs
    let mut allocated_vars: HashMap<Witness, AllocatedNum<F<G1>>> = HashMap::new();

    // Set up public inputs
    self.circuit().public_parameters.0.iter().for_each(|witness| {
      println!("public instance: {witness:?}");
      if let Some(inputs) = &self.witness {
        let f = z[witness.as_usize()].clone();
        acvm
          .as_mut()
          .unwrap()
          .overwrite_witness(*witness, convert_to_acir_field(f.get_value().unwrap()));
      }
      // TODO: Fix unwrap
      // Alloc 1 for now and update later as needed
      let var = AllocatedNum::alloc(&mut *cs, || Ok(F::<G1>::ONE)).unwrap();
      println!("AllocatedNum pub input: {var:?}");
      allocated_vars.insert(*witness, var);
    });

    // Set up private inputs
    self.circuit().private_parameters.iter().for_each(|witness| {
      println!("private instance: {witness:?}");
      if let Some(inputs) = &self.witness {
        let f = convert_to_acir_field(inputs[witness.as_usize()]);
        acvm.as_mut().unwrap().overwrite_witness(*witness, f);
      }
      let var = AllocatedNum::alloc(&mut *cs, || Ok(F::<G1>::ONE)).unwrap();
      allocated_vars.insert(*witness, var);
    });

    let acir_witness_map = if self.witness.is_some() {
      let _status = acvm.as_mut().unwrap().solve();
      Some(acvm.unwrap().finalize())
    } else {
      None
    };

    let get_witness_value = |witness: &Witness| -> F<G1> {
      acir_witness_map.as_ref().map_or(F::<G1>::ONE, |map| {
        map.get(witness).map_or(F::<G1>::ONE, |value| convert_to_halo2_field(*value))
      })
    };

    // Helper to get or create a variable for a witness
    let get_var = |witness: &Witness,
                   allocated_vars: &mut HashMap<Witness, AllocatedNum<F<G1>>>,
                   cs: &mut CS,
                   gate_idx: usize|
     -> Result<Variable, SynthesisError> {
      if let Some(var) = allocated_vars.get(witness) {
        Ok(var.get_variable())
      } else {
        let var = AllocatedNum::alloc(cs.namespace(|| format!("aux_{gate_idx}")), || {
          Ok(get_witness_value(witness))
        })?;
        allocated_vars.insert(*witness, var.clone());
        Ok(var.get_variable())
      }
    };

    // Process gates
    for (gate_idx, opcode) in self.circuit().opcodes.iter().enumerate() {
      if let Opcode::AssertZero(gate) = opcode {
        // Initialize empty linear combinations for each part of our R1CS constraint
        let mut left_terms = LinearCombination::zero();
        let mut right_terms = LinearCombination::zero();
        let mut final_terms = LinearCombination::zero();

        // Process multiplication terms (these form the A and B matrices in R1CS)
        for mul_term in &gate.mul_terms {
          // Convert coefficient from ACIR field to Halo2 field representation
          let coeff = convert_to_halo2_field(mul_term.0);

          // Get or create variables for both sides of multiplication
          // If we've seen this witness before, we'll reuse its variable
          // If not, we'll allocate a new one
          let left_var = get_var(&mul_term.1, &mut allocated_vars, cs, gate_idx)?;
          let right_var = get_var(&mul_term.2, &mut allocated_vars, cs, gate_idx)?;

          // Build Az (left terms) with coefficient
          left_terms = left_terms + (coeff, left_var);
          // Build Bz (right terms) with coefficient 1
          right_terms = right_terms + (F::<G1>::one(), right_var);
        }

        // Process addition terms (these contribute to the C matrix in R1CS)
        for add_term in &gate.linear_combinations {
          // Convert coefficient as before
          let coeff = convert_to_halo2_field(add_term.0);

          // Get or create variable for this term
          let var = get_var(&add_term.1, &mut allocated_vars, cs, gate_idx)?;

          // Add to final terms (Cz) with appropriate coefficient
          final_terms = final_terms + (coeff, var);
        }

        // Handle constant term if present
        if !gate.q_c.is_zero() {
          // Convert constant coefficient
          let const_coeff = convert_to_halo2_field(gate.q_c);
          // Subtract constant term using the ONE input (index 0)
          // We subtract because we're moving it to the other side of equation
          final_terms = final_terms - (const_coeff, Variable::new_unchecked(Index::Input(0)));
        }

        // Enforce the R1CS constraint: Az ∘ Bz = Cz
        // This represents our equation in the form: (left_terms) * (right_terms) = final_terms
        cs.enforce(
          || format!("gate_{gate_idx}"),
          |_| left_terms.clone(),
          |_| right_terms.clone(),
          |_| final_terms,
        );
      }
    }

    let mut z_out = vec![];
    // if let Some(wmap) = acir_witness_map {
    for ret in &self.circuit().return_values.0 {
      dbg!(&ret);
      // dbg!(wmap.get(ret));
      // let output_witness = wmap.get(ret).unwrap();
      z_out.push(allocated_vars.get(ret).unwrap().clone());
    }
    // }

    // TODO: We need to make a list of the range of the public inputs
    for public_input in &self.circuit().public_parameters.0 {
      cs.enforce(
        || format!("pub input enforce {}", public_input.as_usize()),
        |lc| {
          lc + z[public_input.as_usize() - self.circuit().private_parameters.len()].get_variable()
        },
        |lc| lc + CS::one(),
        |lc| lc + allocated_vars.get(public_input).unwrap().get_variable(),
      );
    }
    Ok(dbg!(z_out))
  }
}

fn convert_to_halo2_field(f: GenericFieldElement<Fr>) -> F<G1> {
  let bytes = f.to_be_bytes();
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&bytes[..32]);
  arr.reverse();
  F::<G1>::from_repr(arr).unwrap()
}

// why the fuck is this fucking big endian?
fn convert_to_acir_field(f: F<G1>) -> GenericFieldElement<Fr> {
  let mut bytes = f.to_bytes();
  bytes.reverse();
  GenericFieldElement::from_be_bytes_reduce(&bytes)
}
