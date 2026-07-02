"""Reference model of the immutable PQ shielded-pool contract.

The whole contract is three pieces of state and three operations. Nothing else:
no token, no governance, no admin key, no upgrade path, no compliance hook.

State:
  - an append-only Merkle tree of note commitments (plus a leaf set for
    duplicate-commitment handling);
  - a ring buffer of recent roots (the EIP-8272 "recent roots" shape: a bounded
    window a proof may reference, so wallets need not chase the very latest root);
  - a set of spent nullifiers (the EIP-8250 keyed-nonce shape: one key per
    nullifier, consumed exactly once). On the devnet this set is the protocol's
    NONCE_MANAGER, whose key domains are per sender; it is a global spent set
    only because every spend is submitted from the pool's single pinned
    POOL_SENDER (see envelope.py).

Operations:
  - shield(cm): deposit one denomination, append the commitment. No proof.
  - transfer(spend): consume a nullifier, append the recipient's new note.
  - withdraw(spend): consume a nullifier, pay one denomination to a recipient.

On a real devnet the `proof` passed to transfer/withdraw is a leanVM STARK; here
it is the opening, and the pool re-runs the spend relation (note.spend_relation)
to validate it. That Python check is exactly what the circuit proves on-chain,
minus the zero-knowledge hiding.
"""
from dataclasses import dataclass, field

import note


@dataclass
class Spend:
    """What a wallet submits. `claim` is the single public value the proof
    exposes (the contract recomputes it from the publics and compares). `proof`
    stands in for the leanVM proof: on a real devnet it is the STARK and the
    opening fields are hidden; here it carries the opening so the reference pool
    can validate without a prover."""
    root: bytes
    nf: bytes
    out_cm: bytes
    ctx: bytes
    claim: bytes
    proof: dict = field(default_factory=dict)   # opening: spend_key, rho, siblings, bits


class PoolError(Exception):
    pass


class Pool:
    def __init__(self, depth=32, recent_roots=64, denomination=1):
        self.depth = depth
        self.denomination = denomination
        # precompute zero subtree hashes, one per level
        self.zero = [note.ZERO]
        for _ in range(depth):
            self.zero.append(note._h(self.zero[-1], self.zero[-1]))
        self.leaves = []
        self.leaf_set = set()            # for O(1) duplicate-commitment rejection
        self.nullifiers = set()
        self.recent = []                 # ring buffer of recent roots
        self.recent_cap = recent_roots
        self.balance = 0                 # denominations held in the pool
        self.payouts = []                # (recipient_ctx, amount) for withdrawals
        self._publish_root()

    # ---- Merkle tree ----
    def _levels(self):
        level = list(self.leaves) if self.leaves else [self.zero[0]]
        levels = [level]
        for d in range(self.depth):
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else self.zero[d]
                nxt.append(note._h(left, right))
            level = nxt
            levels.append(level)
        return levels

    def root(self):
        return self._levels()[self.depth][0]

    def auth_path(self, idx):
        """Siblings and bits for the leaf at `idx`, in the circuit's convention
        (bit = idx&1 at each level; bit 0 means the node is the left child)."""
        levels = self._levels()
        siblings, bits = [], []
        for d in range(self.depth):
            level = levels[d]
            bit = idx & 1
            sib_idx = idx ^ 1
            sib = level[sib_idx] if sib_idx < len(level) else self.zero[d]
            siblings.append(sib)
            bits.append(bit)
            idx >>= 1
        return siblings, bits

    def _publish_root(self):
        r = self.root()
        if not self.recent or self.recent[-1] != r:
            self.recent.append(r)
            if len(self.recent) > self.recent_cap:
                self.recent.pop(0)

    # ---- operations ----
    def shield(self, cm):
        """Deposit one denomination and append its note commitment."""
        if cm in self.leaf_set:
            # a duplicate commitment shares one nullifier, so the second deposit
            # would be permanently unspendable; reject it (wallets use a fresh rho)
            raise PoolError("duplicate commitment")
        idx = len(self.leaves)
        self.leaves.append(cm)
        self.leaf_set.add(cm)
        self.balance += self.denomination
        self._publish_root()
        return idx

    def _consume(self, spend: Spend):
        # 1. the referenced root must be within the recent window (EIP-8272)
        if spend.root not in self.recent:
            raise PoolError("root not in recent window")
        # 2. the nullifier must be unspent (EIP-8250: one key per nullifier)
        if spend.nf in self.nullifiers:
            raise PoolError("nullifier already spent (double-spend)")
        # 3. recompute the claim from the publics and compare (the contract's
        #    recompute-and-compare; on devnet the proof's public input must equal it)
        if spend.claim != note.claim(spend.root, spend.nf, spend.out_cm, spend.ctx):
            raise PoolError("claim does not bind the publics")
        # 4. the proof must satisfy the spend relation (leanVM STARK on devnet)
        op = spend.proof
        ok = note.spend_relation(
            spend.claim, spend.root, spend.nf, spend.out_cm, spend.ctx,
            op["spend_key"], op["rho"], op["siblings"], op["bits"],
        )
        if not ok:
            raise PoolError("invalid spend proof")
        # 5. consume the nullifier
        self.nullifiers.add(spend.nf)

    def transfer(self, spend: Spend):
        """Consume a note, create the recipient's new note. Value stays shielded."""
        if spend.out_cm == note.ZERO:
            raise PoolError("transfer must carry an output note")
        if spend.ctx != note.ZERO:
            raise PoolError("transfer must have zero context")
        self._consume(spend)
        if spend.out_cm in self.leaf_set:
            # A duplicate append is a no-op, not a revert. On the devnet the
            # nullifier is consumed at payment approval, which persists through
            # later-frame reverts (EIP-8250), and out_cm is visible in mempool
            # calldata, so a revert here would let an attacker front-run
            # shield(out_cm) to burn the spent note for nothing. The no-op has
            # the same end state (nullifier consumed, nothing appended, the
            # earlier copy stays spendable by whoever holds its secrets) with
            # one fewer post-approval revert path.
            return None
        idx = len(self.leaves)
        self.leaves.append(spend.out_cm)
        self.leaf_set.add(spend.out_cm)
        self._publish_root()
        return idx

    def withdraw(self, spend: Spend):
        """Consume a note, pay one denomination to the public recipient in ctx."""
        if spend.out_cm != note.ZERO:
            raise PoolError("withdraw must not create a note")
        if spend.ctx == note.ZERO:
            raise PoolError("withdraw must name a recipient in ctx")
        self._consume(spend)
        self.balance -= self.denomination
        self.payouts.append((spend.ctx, self.denomination))
        self._publish_root()
