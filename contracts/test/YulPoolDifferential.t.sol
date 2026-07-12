// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MockEnvelopeProbe} from "./ShieldedPool.t.sol";
import {PoseidonT3Shim, PoseidonT4Shim} from "./YulShieldedPool.t.sol";

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
    function roll(uint256) external;
    function assume(bool) external pure;
    function etch(address, bytes calldata) external;
    function readFile(string calldata) external view returns (string memory);
    function parseBytes(string calldata) external pure returns (bytes memory);
}

/// Differential harness: the Solidity pool and the Yul pool deployed side by
/// side with the same probe, verifier, and Poseidon, driven with IDENTICAL
/// raw calldata, comparing (success, returndata) byte-for-byte and storage
/// state word-for-word. This is what backs the ABI-parity claim beyond the
/// ported example-based suite: the Solidity implementation is the spec, and
/// any divergence in decoder strictness (argument lengths, address
/// canonicity, callvalue guards, bounds checks), error selection, or tree
/// state is a failure here.
///
/// Out of scope, by construction: values derived from the contract's own
/// address (sourceId, domain, POOL_SENDER) legitimately differ between the
/// two instances and are compared only for success/failure; the frame-opcode
/// path (empty calldata) does not exist on Forge and is validated live.
contract YulPoolDifferentialTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ShieldedPool sol;
    address yul;
    MockEnvelopeProbe probe;
    Groth16Verifier verifier;

    address constant POOL_SENDER = address(0x5EEDED); // the Solidity pool's pin
    address constant T3_SHIM = address(0xA3);
    address constant T4_SHIM = address(0xA4);
    string constant INIT_HEX = "../devnet/build/shielded_pool_init.hex";
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // every selector the Yul pool dispatches, for structured raw fuzzing
    bytes4[23] SELECTORS = [
        bytes4(0x26123548), // shield
        bytes4(0x751a8fc5), // transfer
        bytes4(0x215ae4c7), // withdraw
        bytes4(0x8cc8fe8d), // verifyProofOnly
        bytes4(0xa3066aab), // claimWithdrawal
        bytes4(0x6ebc51e1), // claimFee
        bytes4(0xfdab463d), // currentRoot
        bytes4(0xd069aab9), // sourceId (address-derived)
        bytes4(0xc2fb26a6), // domain (address-derived)
        bytes4(0xfc7e9c6f), // nextIndex
        bytes4(0xb83b3026), // isLeaf
        bytes4(0x0a5570fa), // withdrawalCredit
        bytes4(0x5c584c88), // feeCredit
        bytes4(0xf178e47c), // filledSubtrees
        bytes4(0x02f36d86), // ctxFor
        bytes4(0x7bb5421b), // domainFor
        bytes4(0xb74af5a9), // probe
        bytes4(0x2b7ac3f3), // verifier
        bytes4(0x98366e35), // DEPTH
        bytes4(0xba9a91a5), // SALT
        bytes4(0xe32e13eb), // DOMAIN_TAG
        bytes4(0x94e5fa12), // RECENT_ROOT_PREDEPLOY
        bytes4(0xa8a5337b) // POOL_SENDER (address-derived)
    ];

    function setUp() public {
        vm.roll(1000);
        probe = new MockEnvelopeProbe();
        verifier = new Groth16Verifier();
        sol = new ShieldedPool(POOL_SENDER, address(probe), verifier);
        vm.etch(T3_SHIM, type(PoseidonT3Shim).runtimeCode);
        vm.etch(T4_SHIM, type(PoseidonT4Shim).runtimeCode);
        bytes memory initcode = bytes.concat(
            vm.parseBytes(vm.readFile(INIT_HEX)), abi.encode(T3_SHIM, T4_SHIM, address(verifier), address(probe))
        );
        address deployed;
        assembly {
            deployed := create(0, add(initcode, 32), mload(initcode))
        }
        require(deployed != address(0), "yul pool deploy failed");
        yul = deployed;
        // enough to shield at and beyond the 2^128 circuit range bound
        vm.deal(address(this), 1 << 132);
    }

    function _isAddressDerived(bytes4 sel) internal pure returns (bool) {
        return sel == bytes4(0xd069aab9) || sel == bytes4(0xc2fb26a6) || sel == bytes4(0xa8a5337b);
    }

    /// Drive both pools with the same calldata and value; require identical
    /// (success, returndata) unless the selector's return is address-derived,
    /// in which case success alone must match.
    function _both(bytes memory data, uint256 value) internal returns (bool ok) {
        bytes memory dS;
        bytes memory dY;
        bool okY;
        (ok, dS) = address(sol).call{value: value}(data);
        (okY, dY) = yul.call{value: value}(data);
        assertTrue(ok == okY, "success/failure diverged");
        bytes4 sel = data.length >= 4 ? bytes4(data) : bytes4(0);
        if (!(ok && _isAddressDerived(sel))) {
            assertTrue(keccak256(dS) == keccak256(dY), "returndata diverged");
        }
    }

    function _assertStateParity() internal view {
        assertTrue(sol.currentRoot() == _root(yul), "currentRoot diverged");
        assertTrue(sol.nextIndex() == _nextIndex(yul), "nextIndex diverged");
        for (uint256 l = 0; l <= 20; l++) {
            assertTrue(sol.filledSubtrees(l) == _subtree(yul, l), "filledSubtrees diverged");
        }
    }

    function _root(address pool) internal view returns (bytes32 r) {
        (, bytes memory d) = pool.staticcall(abi.encodeWithSignature("currentRoot()"));
        r = abi.decode(d, (bytes32));
    }

    function _nextIndex(address pool) internal view returns (uint32 n) {
        (, bytes memory d) = pool.staticcall(abi.encodeWithSignature("nextIndex()"));
        n = abi.decode(d, (uint32));
    }

    function _subtree(address pool, uint256 l) internal view returns (bytes32 r) {
        (, bytes memory d) = pool.staticcall(abi.encodeWithSignature("filledSubtrees(uint256)", l));
        r = abi.decode(d, (bytes32));
    }

    // ---- 1. raw ABI-boundary fuzz: selector + arbitrary tail + value ----

    /// Arbitrary argument bytes after a real selector, with and without
    /// callvalue. Catches decoder divergence: minimum lengths, dirty address
    /// words, callvalue on non-payables, bounds checks, error selection.
    function testFuzz_raw_selector_tail(uint8 selIdx, bytes calldata tail, uint96 value) public {
        bytes4 sel = SELECTORS[selIdx % SELECTORS.length];
        _both(bytes.concat(sel, tail), value);
        _assertStateParity();
    }

    /// Fully arbitrary calldata (unknown selectors land in both fallbacks).
    /// Empty calldata is excluded: on the Yul pool it is the frame-opcode
    /// VERIFY path, which does not exist on Forge.
    function testFuzz_raw_arbitrary(bytes calldata data, uint96 value) public {
        vm.assume(data.length > 0);
        _both(data, value);
        _assertStateParity();
    }

    // ---- 2. shield sequences: state lockstep across the tree ----

    /// Derived sequences of shields, mixing fresh commitments, duplicates,
    /// noncanonical inners, zero and over-range values, then word-for-word
    /// tree state comparison. 24 leaves crosses several frontier levels.
    function testFuzz_shield_sequence(bytes32 seed) public {
        bytes32 lastInner = bytes32(uint256(1));
        for (uint256 i = 0; i < 24; i++) {
            bytes32 r = keccak256(abi.encode(seed, i));
            uint256 kind = uint256(r) % 8;
            bytes32 inner = lastInner;
            uint256 value = (uint256(r) >> 16) % 4 ether + 1;
            if (kind < 4) {
                inner = bytes32(uint256(r) % P); // fresh canonical
                lastInner = inner;
            } else if (kind == 4) {
                value = 0; // ZeroValueShield
            } else if (kind == 5) {
                inner = bytes32(P + (uint256(r) % 1000)); // NotCanonical
            } else if (kind == 6) {
                value = (1 << 128) + (uint256(r) % 1000); // ValueTooLarge
            }
            // kind == 7 reuses lastInner at a derived value: duplicate when the
            // value repeats, fresh leaf otherwise — both sides must agree.
            _both(abi.encodeWithSignature("shield(bytes32)", inner), value);
            _assertStateParity();
        }
    }

    // ---- 3. spend revert-cascade parity ----

    /// One garbage Spend, mutated field by field, driven through both pools
    /// with each pool's own pin and probe arming. Calldata differs only in
    /// the domain field (bound to each pool's address), so the comparison is
    /// on the revert selector: both implementations must fail the SAME check
    /// first, all the way down the cascade to the shared verifier.
    function testFuzz_spend_cascade_parity(uint8 mutation, bytes32 junk) public {
        mutation = mutation % 8;
        ShieldedPool.Spend memory s;
        s.root = bytes32(uint256(junk) % P);
        s.nf1 = bytes32(uint256(keccak256(abi.encode(junk, "nf1"))) % P);
        s.nf2 = bytes32(uint256(keccak256(abi.encode(junk, "nf2"))) % P);
        s.outCm1 = bytes32(uint256(keccak256(abi.encode(junk, "o1"))) % P);
        s.outCm2 = bytes32(uint256(keccak256(abi.encode(junk, "o2"))) % P);
        s.publicAmount = 0;
        s.fee = 1;
        s.ctx = bytes32(0);

        bool halt = mutation == 1;
        if (mutation == 2) s.nf1 = bytes32(0); // ZeroNullifier
        if (mutation == 3) s.root = bytes32(P + 1); // NotCanonical root
        if (mutation == 4) s.publicAmount = 1; // TransferShape
        if (mutation == 5) s.fee = 1 << 128; // ValueTooLarge
        bool wrongKeys = mutation == 6;
        bool wrongRef = mutation == 7;
        // mutation == 0: everything plausible -> shared verifier says ProofInvalid

        bytes4 errS = _spendRevert(address(sol), POOL_SENDER, s, halt, wrongKeys, wrongRef);
        bytes4 errY = _spendRevert(yul, yul, s, halt, wrongKeys, wrongRef);
        assertTrue(errS == errY, "revert cascade diverged");
    }

    function _spendRevert(
        address pool,
        address pin,
        ShieldedPool.Spend memory s,
        bool halt,
        bool wrongKeys,
        bool wrongRef
    ) internal returns (bytes4 e) {
        // bind the domain to THIS pool so the cascade reaches past the domain
        // check; arm the probe with this pool's faithful envelope, then break
        // the selected binding.
        (, bytes memory dom) = pool.staticcall(abi.encodeWithSignature("domain()"));
        s.domain = abi.decode(dom, (bytes32));
        (, bytes memory src) = pool.staticcall(abi.encodeWithSignature("sourceId()"));
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        if (wrongKeys) (lo, hi) = (hi, lo);
        probe.set(3, 2, 2, 0, lo, hi, 1, wrongRef ? bytes32(uint256(1)) : abi.decode(src, (bytes32)), s.root, pool);
        if (halt) probe.setHalted();
        vm.prank(pin);
        (bool ok, bytes memory ret) = pool.call(abi.encodeWithSelector(bytes4(0x751a8fc5), s, POOL_SENDER));
        assertTrue(!ok, "garbage spend settled");
        assertTrue(ret.length == 4, "expected a bare error selector");
        e = bytes4(ret);
    }

    // ---- 4. pinned boundary checks the fuzz might not hit ----

    /// bytes32[DEPTH + 1] has 21 slots: index 20 valid, 21 out of bounds,
    /// with identical revert encoding.
    function test_filledSubtrees_bounds_parity() public {
        assertTrue(_both(abi.encodeWithSignature("filledSubtrees(uint256)", 20), 0), "index 20 must be readable");
        _both(abi.encodeWithSignature("filledSubtrees(uint256)", 21), 0);
        _both(abi.encodeWithSignature("filledSubtrees(uint256)", type(uint256).max), 0);
    }

    /// Dirty high bits on an address argument revert in the Solidity decoder;
    /// masking them instead would let two encodings name one account.
    function test_dirty_address_word_parity() public {
        bytes memory dirty =
            abi.encodePacked(bytes4(0x5c584c88), bytes32(uint256(uint160(address(0xBEEF))) | (1 << 200)));
        _both(dirty, 0);
        bytes memory clean = abi.encodePacked(bytes4(0x5c584c88), bytes32(uint256(uint160(address(0xBEEF)))));
        assertTrue(_both(clean, 0), "canonical address must succeed");
    }

    /// Short calldata reverts in the Solidity decoder; zero-padded reads
    /// would silently misinterpret it.
    function test_short_calldata_parity() public {
        _both(abi.encodePacked(bytes4(0xb83b3026), bytes16(0)), 0); // isLeaf, 16 of 32 bytes
        _both(abi.encodePacked(bytes4(0x26123548)), 1 ether); // shield, no argument
        _both(abi.encodePacked(bytes4(0x751a8fc5), new bytes(100)), 0); // transfer, truncated Spend
    }

    /// Value on a non-payable function reverts in Solidity; accepting it
    /// would break the pool's solvency accounting.
    function test_value_on_nonpayable_parity() public {
        _both(abi.encodeWithSignature("currentRoot()"), 1 ether);
        _both(abi.encodeWithSignature("claimFee(address)", address(0xBEEF)), 1 wei);
    }

    // minimal assert
    function assertTrue(bool c, string memory m) internal pure {
        require(c, m);
    }
}
