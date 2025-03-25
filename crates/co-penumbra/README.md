# co-penumbra

We created a [fork](https://github.com/TaceoLabs/penumbra/tree/co-penumbra) to serialize the witnesses and a,b,c matrices for the `SpendCircuit`, `OutputCircuit` and `DelegatorVodeCircuit`.
The `co-penumbra` branch contains a new crate with a binary that serializes the necessary data.
The circuit setups were taken from the tests [here](https://github.com/TaceoLabs/penumbra/blob/co-penumbra/crates/bin/pcli/tests/proof.rs).
The proving and verifying keys were taken from [here](https://github.com/TaceoLabs/penumbra/tree/co-penumbra/crates/crypto/proof-params/src/gen).

We updated `co-circom` to allow the use of `ark-groth16` `ProvingKey`s and `VerifyingKey`s instead of the types used by `circom`.
Additionally, we implemented the libsnark reduction for `co-circom` and added support for the `bls12-377` curve.
These changes, including script to run the proof examples can be found on the [co-penumbra](https://github.com/TaceoLabs/co-snarks/tree/co-penumbra) branch.

# Benchmarks

The `groth16` times are determined with the benches in this repo.
To get comparable numbers, we subtracted the constraint synthesis and inlining LCs times, because those steps do not happen in the `co-circom` prove step.

machine: m7a.4xlarge

## spend
groth16:     428ms
co-groth16:  539ms

## output
groth16:     141ms
co-groth16:  202ms

## delegator_vote
groth16:     475ms
co-groth16:  569ms
