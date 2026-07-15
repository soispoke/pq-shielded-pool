# Self-paying two-frame flow: live ethrex run

Date: 2026-07-15
Chain: Hegotá ethrex devnet, chain ID `3151908`
Endpoint: `https://rpc1.hegota.ethrex.xyz`
Source: uncommitted working tree based on hardness commit `00016c4`

This is the fresh live integration run for the native-ETH self-paying path.
It executed a shield, private transfer, private withdrawal, recipient claim,
and exact-byte replay checks through the public RPC. No paymaster was deployed
or referenced. The pool was both frame-transaction sender and authenticated
gas payer.

The outer signer for both private spends was the unrelated zero-balance test
account `0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A`. It did not deploy the
pool, own either note, or fund either transaction. Its balance was zero before
and after both spends.

## Deployment

- Pool / dispatcher: `0x0d4ff719551e23185aeb16ffbf2abebb90635942`
- Logic: `0x5C7c905B505f0Cf40Ab6600d05e677F717916F6B`
- Envelope probe: `0xe6b98f104c1bef218f3893adab4160dc73eb8367`
- Groth16 verifier: `0x712516e61C8B383dF4A63CFe83d7701Bce54B03e`
- Poseidon T3: `0xbCF26943C0197d2eE0E5D05c716Be60cc2761508`
- Poseidon T4: `0x59F2f1fCfE2474fD5F0b9BA1E73ca90b143Eb8d0`
- Source ID: `0x0b02548f77daefd492dc83dc25cd5289bbaa4b3360d1a54256afe8cb86473c7b`
- Application domain: `0x10c96d6658ae3abe6189dbc063e7b93dda88cc4527850d43cb12e344b1aa755c`
- Paymaster: none

The probe, logic, and dispatcher were freshly deployed. The immutable verifier
and Poseidon libraries were reused from the preceding live deployment to
conserve the disposable devnet account's ETH. The verifier's onchain runtime
matched the current generated verifier byte for byte. These same immutable
Poseidon deployments had already completed the full proof lifecycle in the
authenticated-payer run earlier that day.

The run shielded `0.10 ETH`, privately transferred `0.06 ETH`, and charged a
proof-bound `0.04 ETH` fee on each spend. The withdrawal created `0.02 ETH`
of public credit for `0x00000000000000000000000000000000cafebabe`.

## Successful lifecycle

| Action | Transaction | Block | Gas used | Authenticated payer |
|---|---|---:|---:|---|
| Shield | `0xa27972a14917d7da5efdbe094974c48a85cc08ace4c10d123d81d63d70d1f93b` | 191883 | 1,083,142 | depositor `0x7099…79C8` |
| Private transfer | `0xe3ea153c0eb413b44e88311f9a5a3be40a2e51f06d534c76a24fd89ef0e63c54` | 191889 | 1,385,529 | pool |
| Private withdrawal | `0xe8f2b57ea3c55298279f2fa9da5f64bdbd645dbc509f88df4f974364e85110c5` | 191899 | 1,525,556 | pool |
| Claim withdrawal | `0x32b460ef0538c541dc0d6165aa13a8a1433333e53fe97b9818d3b3b314378cb2` | 191907 | 35,538 | ordinary claim caller |

The transfer simulation resolved the pool as payer and completed both frames:

```text
valid  shape=SelfVerify
payer=0x0d4ff719551e23185aeb16ffbf2abebb90635942
gas=1,385,529  (verify=286,375, settle=1,064,566)
max_cost=10,384,588,145,384,232 wei
```

After the transfer, the tree had three leaves and root
`0x25046d44b2ba3caa79830a7577348773b7f14c5e0504d0332dc02222bb44930d`,
byte-equal to the root bound by the withdrawal proof. `feeCredit(pool)` was
zero. The pool paid exactly `1,385,529,009,698,703 wei` of transfer gas.

The withdrawal independently resolved the pool as payer:

```text
valid  shape=SelfVerify
payer=0x0d4ff719551e23185aeb16ffbf2abebb90635942
gas=1,525,556  (verify=286,407, settle=1,204,313)
max_cost=10,384,836,145,387,704 wei
```

After the withdrawal, the tree had five leaves, `feeCredit(pool)` remained
zero, and the recipient's withdrawal credit was exactly `0.02 ETH`. The pool
paid exactly `1,525,556,010,678,892 wei` of withdrawal gas.

The ordinary claim then increased the recipient balance from `2.77 ETH` to
`2.79 ETH` and cleared the withdrawal credit. Final pool accounting was exact:

```text
initial shield                                  100,000,000,000,000,000 wei
transfer gas debit                                1,385,529,009,698,703 wei
withdrawal gas debit                              1,525,556,010,678,892 wei
recipient claim                                  20,000,000,000,000,000 wei
final pool balance                               77,088,914,979,622,405 wei
```

The two proof-bound fees remained in the pool. They were not routed to a
paymaster or turned into a self-credit.

## Exact frame shape and replay

Decoding both signed type-`0x06` transactions gives exactly two frames:

```text
0. VERIFY(pool, flags = execution + payment, gas = 350,000)
1. SENDER(pool, flags = 0, gas = 10,000,000)
```

There is no paymaster frame. The transfer settlement calldata is 548 bytes;
the withdrawal settlement calldata is 580 bytes.

Re-publishing either exact mined transaction was rejected by the public RPC
at admission:

```text
Nonce mismatch: expected 1, got 0
```

This is EIP-8250 keyed-nonce consumption by the combined payment approval,
not a pool-local spent-set rejection.

## Artifacts

- `deploy_config.json`: addresses and root-publication blocks.
- `smoke_fixture.json`: deployment-bound proofs and public signals.
- `transfer.raw`, `withdraw.raw`: exact mined type-`0x06` transactions.
- `SHA256SUMS`: integrity hashes for the configuration, fixture, and signed
  transactions.

This run proves the default self-paying ETH path on this ethrex configuration.
It does not prove carriage by a FOCIL inclusion list; inclusion-list
enforcement and omission validation remain a separate consensus integration
milestone.
