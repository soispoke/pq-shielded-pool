"""End-to-end walkthrough: shield -> private transfer -> withdraw.

Runs the whole protocol against the reference pool, plus the two attacks the
design must refuse (double-spend and a forged/stale root). Every step asserts,
so `python3 demo.py` is a self-checking test of the protocol logic.

Alice shields one denomination, privately transfers the note to Bob, Bob
withdraws it to a public address. No amounts, balances, or links are ever
revealed on-chain: the pool only sees commitments, nullifiers, and one claim
digest per spend.
"""
import note
from pool import Pool, Spend, PoolError


class Wallet:
    """Holds note secrets and builds spends. The `proof` it attaches is the
    opening; on a devnet this is replaced by a leanVM STARK that hides it."""
    def __init__(self, pool, name):
        self.pool, self.name = pool, name
        self.notes = {}          # idx -> (spend_key, rho, cm)

    def fresh_commitment(self):
        sk, rho = note.new_note()
        cm = note.commitment(sk, rho)
        return sk, rho, cm

    def remember(self, idx, sk, rho, cm):
        self.notes[idx] = (sk, rho, cm)

    def build_spend(self, idx, out_cm, ctx):
        sk, rho, cm = self.notes[idx]
        siblings, bits = self.pool.auth_path(idx)
        nf = note.nullifier(sk, cm)
        root = self.pool.root()
        claim = note.claim(root, nf, out_cm, ctx)
        return Spend(root=root, nf=nf, out_cm=out_cm, ctx=ctx, claim=claim,
                     proof={"spend_key": sk, "rho": rho, "siblings": siblings, "bits": bits})


def main():
    pool = Pool(depth=8, denomination=1)
    alice, bob = Wallet(pool, "Alice"), Wallet(pool, "Bob")
    line = "=" * 62
    print(line); print("PQ shielded pool - end-to-end demo (reference model)"); print(line)

    # 1. Alice shields one denomination
    sk_a, rho_a, cm_a = alice.fresh_commitment()
    idx_a = pool.shield(cm_a)
    alice.remember(idx_a, sk_a, rho_a, cm_a)
    print(f"\n1. Alice shields 1 denom -> note at index {idx_a}")
    print(f"   pool balance = {pool.balance}, leaves = {len(pool.leaves)}")
    assert pool.balance == 1

    # 2. Alice privately transfers the note to Bob.
    #    Bob generates a fresh note and gives Alice only its commitment.
    sk_b, rho_b, cm_b = bob.fresh_commitment()
    spend = alice.build_spend(idx_a, out_cm=cm_b, ctx=note.ZERO)
    idx_b = pool.transfer(spend)
    bob.remember(idx_b, sk_b, rho_b, cm_b)
    print(f"\n2. Alice -> Bob private transfer")
    print(f"   nullifier consumed: {spend.nf.hex()[:16]}...")
    print(f"   Bob's new note at index {idx_b}; balance unchanged = {pool.balance}")
    assert pool.balance == 1 and spend.nf in pool.nullifiers

    # 3. Double-spend attempt: Alice replays her spent note. Must be refused.
    replay = alice.build_spend(idx_a, out_cm=note.commitment(*note.new_note()[:2]), ctx=note.ZERO)
    try:
        pool.transfer(replay)
        assert False, "double-spend was accepted!"
    except PoolError as e:
        print(f"\n3. Double-spend refused: {e}")

    # 4. Forged-root attempt: a spend that points at a root the pool never had.
    forged = bob.build_spend(idx_b, out_cm=note.ZERO, ctx=note._h(b"recipient:0xBOB"))
    forged.root = note._h(b"not a real root")
    try:
        pool.withdraw(forged)
        assert False, "forged root was accepted!"
    except PoolError as e:
        print(f"4. Forged root refused: {e}")

    # 4b. Tampered-claim attempt: valid opening, but the public claim is swapped
    #     for one over a different recipient. The recompute-and-compare rejects it
    #     (rejection touches no state, so Bob's note stays spendable below).
    tampered = bob.build_spend(idx_b, out_cm=note.ZERO, ctx=note._h(b"recipient:0xBOB"))
    tampered.claim = note.claim(tampered.root, tampered.nf, note.ZERO, note._h(b"recipient:0xEVE"))
    try:
        pool.withdraw(tampered)
        assert False, "tampered claim was accepted!"
    except PoolError as e:
        print(f"4b. Tampered claim refused: {e}")

    # 5. Bob withdraws to a public address.
    recipient = note._h(b"recipient:0xBOB")
    spend = bob.build_spend(idx_b, out_cm=note.ZERO, ctx=recipient)
    pool.withdraw(spend)
    print(f"\n5. Bob withdraws 1 denom to {recipient.hex()[:16]}...")
    print(f"   pool balance = {pool.balance}, payouts = {len(pool.payouts)}")
    assert pool.balance == 0 and len(pool.payouts) == 1

    # 6. Bob cannot withdraw the same note twice.
    try:
        pool.withdraw(bob.build_spend(idx_b, out_cm=note.ZERO, ctx=recipient))
        assert False, "double-withdraw was accepted!"
    except PoolError as e:
        print(f"6. Double-withdraw refused: {e}")

    # 7. Duplicate-output front-run: Dana transfers to Carol, but Eve saw cm_C
    #    in the mempool and shielded a copy first. The append is a no-op, not a
    #    revert: on a devnet the nullifier is consumed at payment approval and
    #    survives later-frame reverts (EIP-8250), so a revert here would let Eve
    #    burn Dana's note; the no-op reaches the same end state with no revert
    #    path. The attack stays negative-sum: Eve's own denomination is what
    #    Carol ends up spending, and Dana's stays locked in the pool.
    dana, carol = Wallet(pool, "Dana"), Wallet(pool, "Carol")
    sk_d, rho_d, cm_d = dana.fresh_commitment()
    idx_d = pool.shield(cm_d)
    dana.remember(idx_d, sk_d, rho_d, cm_d)
    sk_c, rho_c, cm_c = carol.fresh_commitment()
    idx_eve = pool.shield(cm_c)                      # Eve front-runs with Carol's cm
    carol.remember(idx_eve, sk_c, rho_c, cm_c)
    spend = dana.build_spend(idx_d, out_cm=cm_c, ctx=note.ZERO)
    leaves_before = len(pool.leaves)
    assert pool.transfer(spend) is None and spend.nf in pool.nullifiers
    assert len(pool.leaves) == leaves_before
    pool.withdraw(carol.build_spend(idx_eve, out_cm=note.ZERO,
                                    ctx=note._h(b"recipient:0xCAROL")))
    print(f"\n7. Front-run duplicate output: append is a no-op, Carol spends Eve's")
    print(f"   copy, Dana's denomination stays locked (balance = {pool.balance})")
    assert pool.balance == 1

    print(f"\n{line}\nAll steps passed. In the pool's state the spend exposed a nullifier,")
    print("a new commitment (or a withdraw recipient), and a claim digest, never an")
    print("amount (fixed) or which deposit it consumed. On a real devnet every spend")
    print("is submitted from the pool's single pinned sender (a soundness requirement,")
    print("see envelope.py, and also what decorrelates users); the deposit funding")
    print("address is still on-chain, and privacy requires a large enough anonymity set.")
    print(line)


if __name__ == "__main__":
    main()
