"""Devnet envelope model: EIP-8250 keyed nonces + EIP-8272 recent roots + the
pool's pinned-sender VERIFY logic, in plain Python.

pool.py models the application (tree, spent set, claim). This module models the
envelope the devnet wraps around it, at the level of detail where the
integration bugs live:

  - EIP-8250 keyed-nonce domains are PER SENDER: the protocol stores a key's
    sequence at slot(sender, key), so the same key is fresh under two different
    senders ("replay protection is scoped to (sender, nonce_keys, nonce_seq)").
    "Nullifier as nonce key" is therefore a global spent set only if every
    spend is submitted from one pinned sender. The pool's VERIFY logic MUST
    require tx.sender == POOL_SENDER; without that check the same note can be
    spent once per sender, which main() demonstrates.
  - Nonce consumption happens at payment approval and persists through later
    frame reverts (EIP-8250), so any pool-frame revert burns the spent note.
    The pool therefore keeps its post-approval frame revert-free (see the
    duplicate-append no-op in pool.py).
  - A recent root is a (source_id, slot, root) reference in the signed envelope
    that the protocol checks against a bounded window (EIP-8272); the pool must
    additionally bind the reference to its own source and to the root the proof
    anchored, and pick exactly one reference to bind.

`python3 envelope.py` runs the devnet test plan's envelope-level attacks
(cross-sender double-spend, lifted proof, extra nonce keys, foreign root
source, stale root, transfer+withdraw in one spend) and asserts each is
refused. Every rejection happens in the VERIFY logic or protocol checks,
before payment approval, so nothing is consumed by a refused frame.
"""
from dataclasses import dataclass

import note
from pool import Pool, Spend
from demo import Wallet

# The pool's single pinned sender. Pinning is a soundness requirement, not an
# operational choice: it collapses the per-sender EIP-8250 key domains into the
# one domain (POOL_SENDER, nf) that acts as the pool's global spent set. The
# natural instantiation is the pool's own EIP-8141 account, whose authorization
# is the proof-verifying VERIFY frame itself.
POOL_SENDER = "pool-sender"

RECENT_ROOT_USABLE_WINDOW = 8191   # EIP-8272: RECENT_ROOT_LENGTH - 1


class EnvelopeError(Exception):
    pass


class NonceManager:
    """EIP-8250 NONCE_MANAGER: per-sender keyed-nonce storage.

    slot(sender, key) holds the key's sequence; an absent slot reads as 0, so a
    fresh key is spendable only at nonce_seq = 0. Consumption writes seq + 1 at
    payment approval. The (sender, key) pairing is the point: it is why the
    pool must pin one sender.
    """
    def __init__(self):
        self.seq = {}

    def current(self, sender, key):
        return self.seq.get((sender, key), 0)

    def check(self, sender, keys, nonce_seq):
        return all(self.current(sender, k) == nonce_seq for k in keys)

    def consume(self, sender, keys, nonce_seq):
        for k in keys:
            self.seq[(sender, k)] = nonce_seq + 1


class RecentRoots:
    """EIP-8272 RECENT_ROOT_ADDRESS: (source_id, slot) -> root.

    A root written in slot S is referenceable from S + 1 through
    S + RECENT_ROOT_USABLE_WINDOW.
    """
    def __init__(self):
        self.entries = {}

    def write(self, source_id, slot, root):
        self.entries[(source_id, slot)] = root

    def valid(self, source_id, slot, root, current_slot):
        if not (1 <= current_slot - slot <= RECENT_ROOT_USABLE_WINDOW):
            return False
        return self.entries.get((source_id, slot)) == root


@dataclass
class FrameTx:
    """The envelope fields the pool's VERIFY logic must bind. nonce_keys,
    nonce_seq, and recent_root_references are transaction-level signed fields
    (EIP-8250 / EIP-8272); spend carries the VERIFY-frame proof and the pool
    calldata (out_cm, ctx)."""
    sender: str
    nonce_keys: list
    nonce_seq: int
    recent_root_references: list   # [(source_id, slot, root)]
    spend: Spend


class Devnet:
    """One pool riding the protocol. submit() is the whole pipeline: protocol
    checks, the pool's VERIFY logic, payment approval, then the pool call."""

    def __init__(self, depth=8):
        self.pool = Pool(depth=depth)
        self.nonces = NonceManager()
        self.roots = RecentRoots()
        self.source_id = "pool-source"
        self.current_slot = 1
        self._publish()

    def _publish(self):
        self.roots.write(self.source_id, self.current_slot, self.pool.root())
        self.current_slot += 1   # a root written in slot S is usable from S+1

    def shield(self, cm):
        idx = self.pool.shield(cm)
        self._publish()
        return idx

    def reference(self):
        """A wallet's (source_id, slot, root) pick: the newest published root."""
        slot = self.current_slot - 1
        return (self.source_id, slot, self.roots.entries[(self.source_id, slot)])

    def _pool_verify(self, tx):
        """The pool's on-chain VERIFY logic. Static: rejects the frame before
        payment approval, so a refused frame consumes nothing."""
        s = tx.spend
        # 1. the proof, against the claim recomputed from the publics
        if s.claim != note.claim(s.root, s.nf, s.out_cm, s.ctx):
            raise EnvelopeError("claim does not bind the publics")
        op = s.proof
        if not note.spend_relation(s.claim, s.root, s.nf, s.out_cm, s.ctx,
                                   op["spend_key"], op["rho"],
                                   op["siblings"], op["bits"]):
            raise EnvelopeError("invalid spend proof")
        # 2. pinned sender: EIP-8250 key domains are per sender, so the spent
        #    set is (POOL_SENDER, nf) and no other sender may consume a key
        if tx.sender != POOL_SENDER:
            raise EnvelopeError("sender is not the pool's pinned sender")
        # 3. the consumed key set is exactly the proven nullifier, at the fresh
        #    sequence (a lifted proof rides a frame that consumes another key)
        if tx.nonce_keys != [s.nf]:
            raise EnvelopeError("consumed nonce key set is not exactly [nf]")
        if tx.nonce_seq != 0:
            raise EnvelopeError("nonce_seq must be 0 for a fresh key")
        if s.nf == note.ZERO:
            raise EnvelopeError("zero nullifier cannot be a nonce key")
        # 4. exactly one reference carries the pool's own source, and it names
        #    the root the proof anchored
        refs = [r for r in tx.recent_root_references if r[0] == self.source_id]
        if len(refs) != 1:
            raise EnvelopeError("need exactly one reference to the pool's source")
        if refs[0][2] != s.root:
            raise EnvelopeError("referenced root is not the proven root")
        # 5. a spend is exactly one of transfer/withdraw; accepting both
        #    (out_cm and ctx nonzero) would mint one denomination per nullifier
        if (s.out_cm == note.ZERO) == (s.ctx == note.ZERO):
            raise EnvelopeError("spend must be exactly one of transfer/withdraw")

    def submit(self, tx):
        # protocol, EIP-8250: every selected key at the selected sequence
        if not self.nonces.check(tx.sender, tx.nonce_keys, tx.nonce_seq):
            raise EnvelopeError("nonce_seq does not match a selected key's sequence")
        # protocol, EIP-8272: every declared reference valid in the window
        for (sid, slot, root) in tx.recent_root_references:
            if not self.roots.valid(sid, slot, root, self.current_slot):
                raise EnvelopeError("recent root not valid in window")
        # the pool's VERIFY logic (static, pre-approval)
        self._pool_verify(tx)
        # payment approval: consumption persists through later frame reverts
        self.nonces.consume(tx.sender, tx.nonce_keys, tx.nonce_seq)
        # the pool call frame (revert-free by construction, see pool.py)
        s = tx.spend
        if s.out_cm != note.ZERO:
            self.pool.transfer(s)
        else:
            self.pool.withdraw(s)
        self._publish()


def refused(net, tx, why):
    before = dict(net.nonces.seq)
    try:
        net.submit(tx)
        raise AssertionError(f"accepted a frame that must be refused: {why}")
    except EnvelopeError as e:
        assert net.nonces.seq == before, "a refused frame must consume nothing"
        print(f"   refused ({why}): {e}")


def main():
    line = "=" * 62
    print(line)
    print("PQ shielded pool - devnet envelope model (EIP-8250 / 8272)")
    print(line)
    net = Devnet(depth=8)
    alice, bob = Wallet(net.pool, "Alice"), Wallet(net.pool, "Bob")

    sk_a, rho_a, cm_a = alice.fresh_commitment()
    alice.remember(net.shield(cm_a), sk_a, rho_a, cm_a)

    def frame(spend, sender=POOL_SENDER, keys=None, seq=0, refs=None):
        return FrameTx(sender=sender,
                       nonce_keys=[spend.nf] if keys is None else keys,
                       nonce_seq=seq,
                       recent_root_references=[net.reference()] if refs is None else refs,
                       spend=spend)

    # 1. honest transfer through the pinned sender
    sk_b, rho_b, cm_b = bob.fresh_commitment()
    spend = alice.build_spend(0, out_cm=cm_b, ctx=note.ZERO)
    net.submit(frame(spend))
    bob.remember(1, sk_b, rho_b, cm_b)
    nf = spend.nf
    print(f"\n1. transfer accepted via POOL_SENDER; key ({POOL_SENDER!r}, nf) consumed")
    assert net.nonces.current(POOL_SENDER, nf) == 1

    # 2. protocol-level double-spend: same nullifier, same sender
    print("\n2. replay from the pinned sender:")
    refused(net, frame(spend), "same sender, key already used")

    # 3. cross-sender double-spend: the attack pinning exists to stop.
    #    The protocol alone would accept it, because ('eve', nf) is a fresh
    #    per-sender slot; only the pinned-sender check refuses the frame.
    print("\n3. replay from a different sender:")
    assert net.nonces.check("eve", [nf], 0), \
        "per-sender domains: the protocol alone treats ('eve', nf) as fresh"
    refused(net, frame(spend, sender="eve"), "sender not pinned")

    # 4. lifted proof: valid proof in a frame that consumes a different key
    sk_c, rho_c = note.new_note()
    spend = bob.build_spend(1, out_cm=note.ZERO, ctx=note._h(b"recipient:0xBOB"))
    print("\n4-6. envelope attacks on Bob's valid withdraw proof:")
    refused(net, frame(spend, keys=[note._h(b"other key")]), "key != nf")
    refused(net, frame(spend, keys=[spend.nf, note._h(b"extra")]), "extra key rides along")
    refused(net, frame(spend, seq=1), "nonce_seq != 0")

    # 5. root-source attacks
    _, slot, _ = net.reference()
    foreign = ("foreign-source", slot, spend.root)
    refused(net, frame(spend, refs=[foreign]), "foreign source_id, never written")
    net.roots.write("foreign-source", slot, spend.root)   # attacker publishes our root
    refused(net, frame(spend, refs=[foreign]), "foreign source even if root matches")
    stale = net.reference()
    net.current_slot += RECENT_ROOT_USABLE_WINDOW + 1
    refused(net, frame(spend, refs=[stale]), "root older than the window")
    net.current_slot -= RECENT_ROOT_USABLE_WINDOW + 1

    # 6. transfer+withdraw in one spend would mint one denomination
    both = bob.build_spend(1, out_cm=note.commitment(sk_c, rho_c),
                           ctx=note._h(b"recipient:0xBOB"))
    refused(net, frame(both), "out_cm and ctx both nonzero")

    # 7. the honest withdraw still goes through
    spend = bob.build_spend(1, out_cm=note.ZERO, ctx=note._h(b"recipient:0xBOB"))
    net.submit(frame(spend))
    print(f"\n7. withdraw accepted; pool balance = {net.pool.balance}")
    assert net.pool.balance == 0

    print(f"\n{line}\nAll envelope checks passed: the protocol supplies per-sender")
    print("spent-once keys and windowed roots; the pool's VERIFY logic pins the")
    print("sender and binds key, root source, and operation shape to the proof.")
    print(line)


if __name__ == "__main__":
    main()
