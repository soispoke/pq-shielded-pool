"""Generates ../contracts/src/PoseidonBN254.sol from poseidon_bn254_constants.json.

After regenerating, run ../contracts/split_poseidon.py: the committed layout
is the PoseidonT3/PoseidonT4 split (each half fits the hegota devnet's 2^24
per-tx deploy budget) with PoseidonBN254.sol as a thin facade.

The committed Solidity is generated from the exact constants the circuit uses
(exported from circomlibjs by ../tooling/export_vectors.js) and differentially
tested against vectors from the same source. The core is Yul, loop-based (the
round constants stream from a bytes blob, the small mix matrices are inlined
as literals), implementing poseidon_reference.js's naive algorithm:
state = [0, in...]; per round: add constants, x^5 S-box (all lanes in the 4
initial and 4 terminal rounds, lane 0 otherwise), then
new_state[i] = sum_j M[i][j] * state[j]; output state[0].

    python3 gen_poseidon_sol.py && (cd ../contracts && forge test)
"""
import json
from pathlib import Path

HERE = Path(__file__).parent
CONST = json.loads((HERE / "poseidon_bn254_constants.json").read_text())
P = int(CONST["prime"])


def blob(c):
    return b"".join(int(x).to_bytes(32, "big") for x in c)


def hexlines(b, per=3):
    """bytes -> Solidity hex"..." literal lines, `per` 32-byte words per line."""
    step = 32 * per
    return "\n".join(f'        hex"{b[i:i + step].hex()}"' for i in range(0, len(b), step))


def mix(t, M, indent):
    """Yul for new_state = M * state with inlined matrix literals.

    Lazy reduction: each term mulmod-reduces its (possibly unreduced) input,
    so the row sum of t terms < t*P fits a word without addmod ((t+1)*P must
    stay < 2^256, which holds for t = 3 and t = 4 over BN254; a t = 5 blob
    would overflow and need the addmod form back).
    """
    pad = " " * indent
    lines = []
    for i in range(t):
        terms = [f"mulmod({int(M[i][j])}, s{j}, {P})" for j in range(t)]
        expr = terms[0]
        for term in terms[1:]:
            expr = f"add({expr}, {term})"
        lines.append(f"{pad}n{i} := {expr}")
    for i in range(t):
        lines.append(f"{pad}s{i} := n{i}")
    return "\n".join(lines)


def sbox(i, indent):
    """Inline x^5 for one lane, using n0 (dead until the mix rewrites it) as
    the x^2 scratch: a fresh local would be one stack slot too many for
    legacy codegen in hash3 (the devnet libsmall profile), and a Yul
    function call costs ~25 gas per invocation. Reduces the lane mod P as a
    side effect, which the lazy-reduction invariant uses."""
    pad = " " * indent
    return (f"{pad}n0 := mulmod(s{i}, s{i}, {P})\n"
            f"{pad}s{i} := mulmod(mulmod(n0, n0, {P}), s{i}, {P})")


def hash_fn(t):
    """The hashN function body for t = nInputs + 1."""
    cfg = CONST[f"t{t}"]
    rf, rp = int(cfg["rounds_f"]), int(cfg["rounds_p"])
    rounds = rf + rp
    half = rf // 2
    n = t - 1
    args = ", ".join(f"uint256 x{i}" for i in range(n))
    # reduce inputs once at entry: the lazy-reduction bound needs state < t*P,
    # and callers may pass any uint256 (addmod used to absorb that implicitly)
    inits = "\n".join(f"            let s{i + 1} := mod(x{i}, {P})" for i in range(n))
    decls = " ".join(f"let n{i} := 0" for i in range(t))
    arks = "\n".join(
        f"                s{i} := add(s{i}, mload(add(cp, {32 * i})))" for i in range(t))
    extra_sbox = "\n".join(sbox(i, 20) for i in range(1, t))
    return f"""    /// @notice circomlib Poseidon({n}): state [0, inputs...], output state[0].
    /// @dev    public, so the library deploys once and the pool stays under
    ///         the EIP-170 code-size limit (via-IR inlines internal copies).
    ///         Lazily reduced: between the entry mod and the s-boxes, state
    ///         words carry values up to t*P and only mulmod reduces; the ark
    ///         and mix use plain add (sums bounded by (t+1)*P < 2^256, which
    ///         holds for t <= 4 over BN254), and the output takes one final
    ///         mod. Lane 0 passes the s-box every round; lanes 1..{n} only in
    ///         the {half} initial and {rf - half} terminal full rounds.
    function hash{n}({args}) public pure returns (uint256 out) {{
        bytes memory c = C{t};
        assembly ("memory-safe") {{
            let cp := add(c, 32)
            let s0 := 0
{inits}
            {decls}
            for {{ let r := 0 }} lt(r, {rounds}) {{ r := add(r, 1) }} {{
{arks}
                cp := add(cp, {32 * t})
{sbox(0, 16)}
                if or(lt(r, {half}), gt(r, {half + rp - 1})) {{
{extra_sbox}
                }}
{mix(t, cfg["M"], 16)}
            }}
            s0 := mod(s0, {P})
            out := s0
        }}
    }}"""


def main():
    c3, c4 = blob(CONST["t3"]["C"]), blob(CONST["t4"]["C"])
    sol = f"""// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title PoseidonBN254 — circomlib's Poseidon, on-chain
/// @notice Poseidon over the BN254 scalar field
///         (p = {P}),
///         x^5 S-box, 8 full rounds + 57 (t=3) / 56 (t=4) partial rounds,
///         state initialised as [0, inputs...], output state[0], with
///         new_state[i] = sum_j M[i][j] * state[j]. Constants exported from
///         circomlibjs (the package the spend circuit's poseidon.circom pairs
///         with); differentially tested against vectors from the same source,
///         see ../test/PoseidonVectors.t.sol and ../../reference/poseidon_bn254.py.
/// @dev    GENERATED by ../../reference/gen_poseidon_sol.py — edit that, not this.
library PoseidonBN254 {{
    uint256 internal constant P = {P};

    /// {len(CONST["t3"]["C"])} t=3 round constants, 32 bytes each, big-endian.
    bytes internal constant C3 =
{hexlines(c3)};

    /// {len(CONST["t4"]["C"])} t=4 round constants, 32 bytes each, big-endian.
    bytes internal constant C4 =
{hexlines(c4)};

{hash_fn(3)}

{hash_fn(4)}
}}
"""
    out = HERE.parent / "contracts" / "src" / "PoseidonBN254.sol"
    out.write_text(sol)
    print(f"wrote {out} ({len(sol)} bytes)")


if __name__ == "__main__":
    main()
