// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 20419890405506180329559508193458330316511544904427481170832058312918293522472;
    uint256 constant alphay = 20174317911205823235583287050718372832884531449566581874841152587960030936755;
    uint256 constant betax1 = 17796954663731275773817438295494867606966057551447117592381446445740493650875;
    uint256 constant betax2 = 2944798094907719793528691695869731706263038835007993150836008717319153430842;
    uint256 constant betay1 = 9099596250481393784263882662652085186401433744764119850129493170572840409469;
    uint256 constant betay2 = 15170935833317389182247469670345451663558669855933343275812614857168856382528;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 10501898965275626446408572222450628073085688676051016274005030245460252218949;
    uint256 constant deltax2 = 12277360484929976329484734330714532586356447105829487052071122477773755203585;
    uint256 constant deltay1 = 16386991564781975085738552110096672731724699152756185046731638972821963300172;
    uint256 constant deltay2 = 1421473026913620334184154440613749326520535338706262157494184663119818866598;

    uint256 constant IC0x = 10923484859297456727043533469797335772811042066933119688485840164977221880275;
    uint256 constant IC0y = 18714785024115248975873870072288128749132902822328598839212720808512807996651;

    uint256 constant IC1x = 16130732960183415270990510420168596081584638106439454261776610494203102580438;
    uint256 constant IC1y = 15549071335331563559408364915652695938646541457804482840730840195837232212558;

    uint256 constant IC2x = 11367529868262564209473030592514073111809572647152498315562705189785285795187;
    uint256 constant IC2y = 5824407200447773444961100216030112256703810919087403439144092038902053901755;

    uint256 constant IC3x = 17774818818497643306556431770100585846911724462271347979621015061979647545812;
    uint256 constant IC3y = 5626994705204146981228798808306379598674337157850830188230194025520154159737;

    uint256 constant IC4x = 3139551070913465469093751464642568532875513446464474995800906696683272378175;
    uint256 constant IC4y = 16099869340272840084488004516888330947696935185631638850799561675132892712617;

    uint256 constant IC5x = 7693802805716014373472498009312303535050884848875430706387426735420459314511;
    uint256 constant IC5y = 15721499939560809967687817290987643526710056781382231999906814754195422904763;

    uint256 constant IC6x = 21415499686174127282791110859644227470533763267808828971483521223016797374037;
    uint256 constant IC6y = 11736842473061160586074789169828636861770714789760691144925969457299961682802;

    uint256 constant IC7x = 19365206184052934790042297359349829110994402174341052696322440938575980974775;
    uint256 constant IC7y = 16159484946515727728626755042772603817083598691120206298957100638695216415134;

    uint256 constant IC8x = 2615965099764986302108276996601804312647571790114079360962021720411307824073;
    uint256 constant IC8y = 7166062460911174592167066698397628090073052773170105480925562952464468802205;

    uint256 constant IC9x = 1749633757826742314654473201773085982201907041159411688666765833403951413998;
    uint256 constant IC9y = 10904818905362087182500117460955485266692619380331131261657706360082286163260;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[9] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(500000, 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(500000, 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(500000, 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
