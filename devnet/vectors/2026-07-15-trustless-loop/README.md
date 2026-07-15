# Authenticated-payer trustless loop — live ethrex run

Date: 2026-07-15
Chain: Hegotá ethrex devnet, chain ID `3151908`
Endpoint: `https://rpc1.hegota.ethrex.xyz`
Pool source: hardness `00016c47894b175646999ef3ac64cad565ab5f73`
(`fd39057096a1f4a311a7ba79ba4906ab9a24dbbd` in the standalone repository)

This is the fresh integration run for authenticated payer routing through
`TXPARAM(0x11)`. It closes the pool-side trust loop with real Groth16 proofs
and real value: deposit, permissionless private transfer, permissionless
withdrawal, payer reimbursement, recipient claim, and protocol replay
rejection all executed against the public RPC.

The outer signer for both spends was the unrelated, zero-balance test account
`0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A`. It did not deploy the pool,
own either note, or pay gas. The spend sender was the pool itself, and the
payment-scoped `APPROVE` selected the proof paymaster authenticated by
ethrex. Settlement read that payer through `TXPARAM(0x11)` and credited the
proof-bound fee to it; no fee recipient was supplied in calldata.

## Fresh deployment

- Pool / dispatcher: `0x1275d096b9dbf2347bd2a131fb6bdab0b4882487`
- Logic: `0xC6bA8C3233eCF65B761049ef63466945c362EdD2`
- Envelope probe: `0x948b3c65b89df0b4894abe91e6d02fe579834f8f`
- Groth16 verifier: `0x712516e61C8B383dF4A63CFe83d7701Bce54B03e`
- Poseidon T3: `0xbCF26943C0197d2eE0E5D05c716Be60cc2761508`
- Poseidon T4: `0x59F2f1fCfE2474fD5F0b9BA1E73ca90b143Eb8d0`
- Paymaster A: `0x05aa229aec102f78ce0e852a812a388f076aa555`
- Paymaster B: `0x0b48af34f4c854f5ae1a3d587da471fea45bad52`
- Source ID: `0xac0fa496a40fac1513acdf85b30965fdca4781b609f17171295c0b0dbae259ff`
- Domain: `0x1ad2700b387b424cd721561fe7077d7c9578fec130c96f1fe467efade24ee417`

The smoke values were scaled for the remaining disposable-devnet funds:
`0.10 ETH` shielded, `0.06 ETH` privately transferred, and a `0.04 ETH`
fee on each spend. The withdrawal therefore created `0.02 ETH` of public
recipient credit. Each paymaster started with `0.04 ETH`.

## Successful lifecycle

| Action | Transaction | Block | Gas used | Authenticated payer |
|---|---|---:|---:|---|
| Shield | `0x799725a46fa8c4af163383b722bc2dcd7e1f944757d756c77a97d1c6a1130b68` | 189110 | 1,083,142 | depositor `0x7099…79C8` |
| Private transfer | `0x4d4c0c997d8e680d040ed8af240bb09613d30a729aca5d5cf18f3adece33ec78` | 189135 | 1,500,769 | paymaster A |
| Withdrawal | `0x91051bdb5730b0221f1f79e5cbc63c750954c4da883573b7764e4696d0e7e919` | 189151 | 1,641,008 | paymaster B |
| Claim fee A | `0xeb7fc2292ab2e3d3a047f806eb48998b836f7dbfab6fd2fe16bd6f954dcd5e3e` | 189160 | 35,639 | ordinary claim caller |
| Claim fee B | `0x3231c01326c1d6ff28a35aaa642305f3fdef2289a480e2b148483ee692e02615` | 189163 | 35,639 | ordinary claim caller |
| Claim withdrawal | `0x28e53689b767df1eaa963f0ed17e8e9ca1c1284feffc47bd27f039c03f1e073a` | 189166 | 35,538 | ordinary claim caller |

The valid transfer simulation resolved payer A and completed all frames:

```text
valid=True  shape=OnlyVerifyPay
payer=0x05aa229aec102f78ce0e852a812a388f076aa555
gas=1,500,769  (verify=246,337, pay=42,301, settle=1,168,896)
max_cost=10,443,235,146,205,290 wei
```

The withdrawal independently resolved payer B and completed all frames:

```text
valid=True  shape=OnlyVerifyPay
payer=0x0b48af34f4c854f5ae1a3d587da471fea45bad52
gas=1,641,008  (verify=246,396, pay=42,318, settle=1,308,667)
max_cost=10,443,627,146,210,778 wei
```

Immediately after the transfer, `feeCredit(paymasterA)` was exactly `0.04
ETH`, the Merkle tree had three leaves, and its root was byte-equal to the
withdrawal proof's root. Immediately after the withdrawal, the tree had five
leaves, `feeCredit(paymasterB)` was exactly `0.04 ETH`,
`withdrawalCredit(0x…cafebabe)` was exactly `0.02 ETH`, and the pool held
exactly `0.10 ETH`: full backing for those three pull credits.

After all claims:

```text
nextIndex                                      5
currentRoot  0x02f2f42870535a327fce02178b6e68606a28aab9a3b72f2c7ce88282a26dd47f
feeCredit(paymasterA)                          0
feeCredit(paymasterB)                          0
withdrawalCredit(recipient)                    0
pool balance                                   0
paymaster A balance            78,499,230,989,494,617 wei
paymaster B balance            78,358,991,988,512,944 wei
recipient balance           2,770,000,000,000,000,000 wei
outer submitter balance                         0
```

Each paymaster's final balance is its unspent prefund plus its exact `0.04
ETH` pool credit. The submitter remained at zero before and after both spends.

## Negative controls and replay

All controls were simulated before the valid transfer consumed either
nullifier. The under-fee envelope, one-bit-corrupted proof, wrong nonce-key
set, and down-gassed settlement envelope each returned:

```text
valid=False  shape=OnlyVerifyPay  payer=None
violation=validation prefix frame reverted
```

The valid baseline still passed immediately afterward, so these are not
replay or stale-state artifacts. The signed raw controls are archived beside
this file.

Re-publishing the exact mined transfer and withdrawal bytes was rejected by
the public RPC at admission:

```text
Frame transaction validation-prefix simulation failed:
Invalid Transaction: Nonce mismatch: expected 1, got 0
```

That is protocol keyed-nonce consumption, not a pool-local spent-set check.

## Artifacts

- `deploy_config.json`: addresses plus the root-publication blocks threaded
  into EIP-8272 references.
- `smoke_fixture.json`: deployment-bound proofs and public signals.
- `transfer.raw`, `withdraw.raw`: exact mined type-`0x06` transactions.
- `transfer-valid.raw`: the valid pre-send baseline.
- `transfer-underfee.raw`, `transfer-bad-proof.raw`,
  `transfer-wrong-keys.raw`, `transfer-down-gas.raw`: rejected controls.
- `SHA256SUMS`: integrity hashes for every signed transaction, configuration,
  and proof fixture in this bundle.

This run proves the trustless pool loop and ordinary public-mempool admission
on this ethrex configuration. It does not claim that a FOCIL inclusion list
actually carried the transaction; inclusion-list enforcement and omission
proofs remain a separate ethrex/consensus integration milestone.
