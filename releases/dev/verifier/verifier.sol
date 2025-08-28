// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

contract Halo2Verifier {
    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) { revert(0, 0) }

            let success := true
            let f_p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            let f_q := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            function validate_ec_point(x, y) -> valid {
                {
                    let x_lt_p := lt(x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let y_lt_p := lt(y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    valid := and(x_lt_p, y_lt_p)
                }
                {
                    let y_square := mulmod(y, y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_square := mulmod(x, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_cube :=
                        mulmod(x_square, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_cube_plus_3 :=
                        addmod(x_cube, 3, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let is_affine := eq(x_cube_plus_3, y_square)
                    valid := and(valid, is_affine)
                }
            }
            mstore(0xa0, mod(calldataload(0x0), f_q))
            mstore(0xc0, mod(calldataload(0x20), f_q))
            mstore(0xe0, mod(calldataload(0x40), f_q))
            mstore(0x100, mod(calldataload(0x60), f_q))
            mstore(0x120, mod(calldataload(0x80), f_q))
            mstore(0x140, mod(calldataload(0xa0), f_q))
            mstore(0x160, mod(calldataload(0xc0), f_q))
            mstore(0x180, mod(calldataload(0xe0), f_q))
            mstore(0x1a0, mod(calldataload(0x100), f_q))
            mstore(0x1c0, mod(calldataload(0x120), f_q))
            mstore(0x1e0, mod(calldataload(0x140), f_q))
            mstore(0x200, mod(calldataload(0x160), f_q))
            mstore(0x220, mod(calldataload(0x180), f_q))
            mstore(0x240, mod(calldataload(0x1a0), f_q))
            mstore(0x260, mod(calldataload(0x1c0), f_q))
            mstore(0x280, mod(calldataload(0x1e0), f_q))
            mstore(0x2a0, mod(calldataload(0x200), f_q))
            mstore(0x2c0, mod(calldataload(0x220), f_q))
            mstore(0x2e0, mod(calldataload(0x240), f_q))
            mstore(0x300, mod(calldataload(0x260), f_q))
            mstore(0x320, mod(calldataload(0x280), f_q))
            mstore(0x340, mod(calldataload(0x2a0), f_q))
            mstore(0x360, mod(calldataload(0x2c0), f_q))
            mstore(0x380, mod(calldataload(0x2e0), f_q))
            mstore(0x3a0, mod(calldataload(0x300), f_q))
            mstore(0x3c0, mod(calldataload(0x320), f_q))
            mstore(0x3e0, mod(calldataload(0x340), f_q))
            mstore(0x400, mod(calldataload(0x360), f_q))
            mstore(0x420, mod(calldataload(0x380), f_q))
            mstore(0x440, mod(calldataload(0x3a0), f_q))
            mstore(0x460, mod(calldataload(0x3c0), f_q))
            mstore(0x480, mod(calldataload(0x3e0), f_q))
            mstore(0x4a0, mod(calldataload(0x400), f_q))
            mstore(0x4c0, mod(calldataload(0x420), f_q))
            mstore(0x4e0, mod(calldataload(0x440), f_q))
            mstore(0x500, mod(calldataload(0x460), f_q))
            mstore(0x520, mod(calldataload(0x480), f_q))
            mstore(0x540, mod(calldataload(0x4a0), f_q))
            mstore(0x560, mod(calldataload(0x4c0), f_q))
            mstore(0x580, mod(calldataload(0x4e0), f_q))
            mstore(0x5a0, mod(calldataload(0x500), f_q))
            mstore(0x5c0, mod(calldataload(0x520), f_q))
            mstore(0x5e0, mod(calldataload(0x540), f_q))
            mstore(0x600, mod(calldataload(0x560), f_q))
            mstore(0x620, mod(calldataload(0x580), f_q))
            mstore(0x640, mod(calldataload(0x5a0), f_q))
            mstore(0x80, 9514323097321245931419041477139106601771148851610395955023397192525359125626)

            {
                let x := calldataload(0x5c0)
                mstore(0x660, x)
                let y := calldataload(0x5e0)
                mstore(0x680, y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(0x6a0, keccak256(0x80, 1568))
            {
                let hash := mload(0x6a0)
                mstore(0x6c0, mod(hash, f_q))
                mstore(0x6e0, hash)
            }

            {
                let x := calldataload(0x600)
                mstore(0x700, x)
                let y := calldataload(0x620)
                mstore(0x720, y)
                success := and(validate_ec_point(x, y), success)
            }

            {
                let x := calldataload(0x640)
                mstore(0x740, x)
                let y := calldataload(0x660)
                mstore(0x760, y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(0x780, keccak256(0x6e0, 160))
            {
                let hash := mload(0x780)
                mstore(0x7a0, mod(hash, f_q))
                mstore(0x7c0, hash)
            }
            mstore8(2016, 1)
            mstore(0x7e0, keccak256(0x7c0, 33))
            {
                let hash := mload(0x7e0)
                mstore(0x800, mod(hash, f_q))
                mstore(0x820, hash)
            }

            {
                let x := calldataload(0x680)
                mstore(0x840, x)
                let y := calldataload(0x6a0)
                mstore(0x860, y)
                success := and(validate_ec_point(x, y), success)
            }

            {
                let x := calldataload(0x6c0)
                mstore(0x880, x)
                let y := calldataload(0x6e0)
                mstore(0x8a0, y)
                success := and(validate_ec_point(x, y), success)
            }

            {
                let x := calldataload(0x700)
                mstore(0x8c0, x)
                let y := calldataload(0x720)
                mstore(0x8e0, y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(0x900, keccak256(0x820, 224))
            {
                let hash := mload(0x900)
                mstore(0x920, mod(hash, f_q))
                mstore(0x940, hash)
            }

            {
                let x := calldataload(0x740)
                mstore(0x960, x)
                let y := calldataload(0x760)
                mstore(0x980, y)
                success := and(validate_ec_point(x, y), success)
            }

            {
                let x := calldataload(0x780)
                mstore(0x9a0, x)
                let y := calldataload(0x7a0)
                mstore(0x9c0, y)
                success := and(validate_ec_point(x, y), success)
            }

            {
                let x := calldataload(0x7c0)
                mstore(0x9e0, x)
                let y := calldataload(0x7e0)
                mstore(0xa00, y)
                success := and(validate_ec_point(x, y), success)
            }

            {
                let x := calldataload(0x800)
                mstore(0xa20, x)
                let y := calldataload(0x820)
                mstore(0xa40, y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(0xa60, keccak256(0x940, 288))
            {
                let hash := mload(0xa60)
                mstore(0xa80, mod(hash, f_q))
                mstore(0xaa0, hash)
            }
            mstore(0xac0, mod(calldataload(0x840), f_q))
            mstore(0xae0, mod(calldataload(0x860), f_q))
            mstore(0xb00, mod(calldataload(0x880), f_q))
            mstore(0xb20, mod(calldataload(0x8a0), f_q))
            mstore(0xb40, mod(calldataload(0x8c0), f_q))
            mstore(0xb60, mod(calldataload(0x8e0), f_q))
            mstore(0xb80, mod(calldataload(0x900), f_q))
            mstore(0xba0, mod(calldataload(0x920), f_q))
            mstore(0xbc0, mod(calldataload(0x940), f_q))
            mstore(0xbe0, mod(calldataload(0x960), f_q))
            mstore(0xc00, mod(calldataload(0x980), f_q))
            mstore(0xc20, mod(calldataload(0x9a0), f_q))
            mstore(0xc40, mod(calldataload(0x9c0), f_q))
            mstore(0xc60, mod(calldataload(0x9e0), f_q))
            mstore(0xc80, mod(calldataload(0xa00), f_q))
            mstore(0xca0, mod(calldataload(0xa20), f_q))
            mstore(0xcc0, mod(calldataload(0xa40), f_q))
            mstore(0xce0, mod(calldataload(0xa60), f_q))
            mstore(0xd00, mod(calldataload(0xa80), f_q))
            mstore(0xd20, keccak256(0xaa0, 640))
            {
                let hash := mload(0xd20)
                mstore(0xd40, mod(hash, f_q))
                mstore(0xd60, hash)
            }
            mstore8(3456, 1)
            mstore(0xd80, keccak256(0xd60, 33))
            {
                let hash := mload(0xd80)
                mstore(0xda0, mod(hash, f_q))
                mstore(0xdc0, hash)
            }

            {
                let x := calldataload(0xaa0)
                mstore(0xde0, x)
                let y := calldataload(0xac0)
                mstore(0xe00, y)
                success := and(validate_ec_point(x, y), success)
            }
            mstore(0xe20, keccak256(0xdc0, 96))
            {
                let hash := mload(0xe20)
                mstore(0xe40, mod(hash, f_q))
                mstore(0xe60, hash)
            }

            {
                let x := calldataload(0xae0)
                mstore(0xe80, x)
                let y := calldataload(0xb00)
                mstore(0xea0, y)
                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(0xa0)
                x := add(x, shl(88, mload(0xc0)))
                x := add(x, shl(176, mload(0xe0)))
                mstore(3776, x)
                let y := mload(0x100)
                y := add(y, shl(88, mload(0x120)))
                y := add(y, shl(176, mload(0x140)))
                mstore(3808, y)

                success := and(validate_ec_point(x, y), success)
            }
            {
                let x := mload(0x160)
                x := add(x, shl(88, mload(0x180)))
                x := add(x, shl(176, mload(0x1a0)))
                mstore(3840, x)
                let y := mload(0x1c0)
                y := add(y, shl(88, mload(0x1e0)))
                y := add(y, shl(176, mload(0x200)))
                mstore(3872, y)

                success := and(validate_ec_point(x, y), success)
            }
            mstore(0xf40, mulmod(mload(0xa80), mload(0xa80), f_q))
            mstore(0xf60, mulmod(mload(0xf40), mload(0xf40), f_q))
            mstore(0xf80, mulmod(mload(0xf60), mload(0xf60), f_q))
            mstore(0xfa0, mulmod(mload(0xf80), mload(0xf80), f_q))
            mstore(0xfc0, mulmod(mload(0xfa0), mload(0xfa0), f_q))
            mstore(0xfe0, mulmod(mload(0xfc0), mload(0xfc0), f_q))
            mstore(0x1000, mulmod(mload(0xfe0), mload(0xfe0), f_q))
            mstore(0x1020, mulmod(mload(0x1000), mload(0x1000), f_q))
            mstore(0x1040, mulmod(mload(0x1020), mload(0x1020), f_q))
            mstore(0x1060, mulmod(mload(0x1040), mload(0x1040), f_q))
            mstore(0x1080, mulmod(mload(0x1060), mload(0x1060), f_q))
            mstore(0x10a0, mulmod(mload(0x1080), mload(0x1080), f_q))
            mstore(0x10c0, mulmod(mload(0x10a0), mload(0x10a0), f_q))
            mstore(0x10e0, mulmod(mload(0x10c0), mload(0x10c0), f_q))
            mstore(0x1100, mulmod(mload(0x10e0), mload(0x10e0), f_q))
            mstore(0x1120, mulmod(mload(0x1100), mload(0x1100), f_q))
            mstore(0x1140, mulmod(mload(0x1120), mload(0x1120), f_q))
            mstore(0x1160, mulmod(mload(0x1140), mload(0x1140), f_q))
            mstore(0x1180, mulmod(mload(0x1160), mload(0x1160), f_q))
            mstore(0x11a0, mulmod(mload(0x1180), mload(0x1180), f_q))
            mstore(0x11c0, mulmod(mload(0x11a0), mload(0x11a0), f_q))
            mstore(0x11e0, mulmod(mload(0x11c0), mload(0x11c0), f_q))
            mstore(
                0x1200,
                addmod(
                    mload(0x11e0), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q
                )
            )
            mstore(
                0x1220,
                mulmod(
                    mload(0x1200), 21888237653275510688422624196183639687472264873923820041627027729598873448513, f_q
                )
            )
            mstore(
                0x1240,
                mulmod(
                    mload(0x1220), 13225785879531581993054172815365636627224369411478295502904397545373139154045, f_q
                )
            )
            mstore(
                0x1260,
                addmod(mload(0xa80), 8662456992307693229192232929891638461323994988937738840793806641202669341572, f_q)
            )
            mstore(
                0x1280,
                mulmod(
                    mload(0x1220), 10939663269433627367777756708678102241564365262857670666700619874077960926249, f_q
                )
            )
            mstore(
                0x12a0,
                addmod(mload(0xa80), 10948579602405647854468649036579172846983999137558363676997584312497847569368, f_q)
            )
            mstore(
                0x12c0,
                mulmod(
                    mload(0x1220), 11016257578652593686382655500910603527869149377564754001549454008164059876499, f_q
                )
            )
            mstore(
                0x12e0,
                addmod(mload(0xa80), 10871985293186681535863750244346671560679215022851280342148750178411748619118, f_q)
            )
            mstore(
                0x1300,
                mulmod(
                    mload(0x1220), 15402826414547299628414612080036060696555554914079673875872749760617770134879, f_q
                )
            )
            mstore(
                0x1320,
                addmod(mload(0xa80), 6485416457291975593831793665221214391992809486336360467825454425958038360738, f_q)
            )
            mstore(
                0x1340,
                mulmod(
                    mload(0x1220), 21710372849001950800533397158415938114909991150039389063546734567764856596059, f_q
                )
            )
            mstore(
                0x1360,
                addmod(mload(0xa80), 177870022837324421713008586841336973638373250376645280151469618810951899558, f_q)
            )
            mstore(
                0x1380,
                mulmod(mload(0x1220), 2785514556381676080176937710880804108647911392478702105860685610379369825016, f_q)
            )
            mstore(
                0x13a0,
                addmod(mload(0xa80), 19102728315457599142069468034376470979900453007937332237837518576196438670601, f_q)
            )
            mstore(
                0x13c0,
                mulmod(mload(0x1220), 8734126352828345679573237859165904705806588461301144420590422589042130041188, f_q)
            )
            mstore(
                0x13e0,
                addmod(mload(0xa80), 13154116519010929542673167886091370382741775939114889923107781597533678454429, f_q)
            )
            mstore(0x1400, mulmod(mload(0x1220), 1, f_q))
            mstore(
                0x1420,
                addmod(mload(0xa80), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q)
            )
            mstore(
                0x1440,
                mulmod(
                    mload(0x1220), 11211301017135681023579411905410872569206244553457844956874280139879520583390, f_q
                )
            )
            mstore(
                0x1460,
                addmod(mload(0xa80), 10676941854703594198666993839846402519342119846958189386823924046696287912227, f_q)
            )
            mstore(
                0x1480,
                mulmod(mload(0x1220), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q)
            )
            mstore(
                0x14a0,
                addmod(mload(0xa80), 20461838439117790833741043996939313553025008529160428886800406442142042007110, f_q)
            )
            mstore(
                0x14c0,
                mulmod(
                    mload(0x1220), 12619617507853212586156872920672483948819476989779550311307282715684870266992, f_q
                )
            )
            mstore(
                0x14e0,
                addmod(mload(0xa80), 9268625363986062636089532824584791139728887410636484032390921470890938228625, f_q)
            )
            mstore(
                0x1500,
                mulmod(
                    mload(0x1220), 19032961837237948602743626455740240236231119053033140765040043513661803148152, f_q
                )
            )
            mstore(
                0x1520,
                addmod(mload(0xa80), 2855281034601326619502779289517034852317245347382893578658160672914005347465, f_q)
            )
            mstore(
                0x1540,
                mulmod(mload(0x1220), 915149353520972163646494413843788069594022902357002628455555785223409501882, f_q)
            )
            mstore(
                0x1560,
                addmod(mload(0xa80), 20973093518318303058599911331413487018954341498059031715242648401352398993735, f_q)
            )
            mstore(
                0x1580,
                mulmod(mload(0x1220), 3766081621734395783232337525162072736827576297943013392955872170138036189193, f_q)
            )
            mstore(
                0x15a0,
                addmod(mload(0xa80), 18122161250104879439014068220095202351720788102473020950742332016437772306424, f_q)
            )
            mstore(
                0x15c0,
                mulmod(mload(0x1220), 4245441013247250116003069945606352967193023389718465410501109428393342802981, f_q)
            )
            mstore(
                0x15e0,
                addmod(mload(0xa80), 17642801858592025106243335799650922121355341010697568933197094758182465692636, f_q)
            )
            mstore(
                0x1600,
                mulmod(mload(0x1220), 5854133144571823792863860130267644613802765696134002830362054821530146160770, f_q)
            )
            mstore(
                0x1620,
                addmod(mload(0xa80), 16034109727267451429382545614989630474745598704282031513336149365045662334847, f_q)
            )
            mstore(
                0x1640,
                mulmod(mload(0x1220), 5980488956150442207659150513163747165544364597008566989111579977672498964212, f_q)
            )
            mstore(
                0x1660,
                addmod(mload(0xa80), 15907753915688833014587255232093527923003999803407467354586624208903309531405, f_q)
            )
            mstore(
                0x1680,
                mulmod(
                    mload(0x1220), 14557038802599140430182096396825290815503940951075961210638273254419942783582, f_q
                )
            )
            mstore(
                0x16a0,
                addmod(mload(0xa80), 7331204069240134792064309348431984273044423449340073133059930932155865712035, f_q)
            )
            mstore(
                0x16c0,
                mulmod(
                    mload(0x1220), 13553911191894110065493137367144919847521088405945523452288398666974237857208, f_q
                )
            )
            mstore(
                0x16e0,
                addmod(mload(0xa80), 8334331679945165156753268378112355241027275994470510891409805519601570638409, f_q)
            )
            mstore(
                0x1700,
                mulmod(mload(0x1220), 9697063347556872083384215826199993067635178715531258559890418744774301211662, f_q)
            )
            mstore(
                0x1720,
                addmod(mload(0xa80), 12191179524282403138862189919057282020913185684884775783807785441801507283955, f_q)
            )
            mstore(
                0x1740,
                mulmod(
                    mload(0x1220), 10807735674816066981985242612061336605021639643453679977988966079770672437131, f_q
                )
            )
            mstore(
                0x1760,
                addmod(mload(0xa80), 11080507197023208240261163133195938483526724756962354365709238106805136058486, f_q)
            )
            mstore(
                0x1780,
                mulmod(
                    mload(0x1220), 12459868075641381822485233712013080087763946065665469821362892189399541605692, f_q
                )
            )
            mstore(
                0x17a0,
                addmod(mload(0xa80), 9428374796197893399761172033244195000784418334750564522335311997176266889925, f_q)
            )
            mstore(
                0x17c0,
                mulmod(
                    mload(0x1220), 16038300751658239075779628684257016433412502747804121525056508685985277092575, f_q
                )
            )
            mstore(
                0x17e0,
                addmod(mload(0xa80), 5849942120181036146466777061000258655135861652611912818641695500590531403042, f_q)
            )
            mstore(
                0x1800,
                mulmod(mload(0x1220), 6955697244493336113861667751840378876927906302623587437721024018233754910398, f_q)
            )
            mstore(
                0x1820,
                addmod(mload(0xa80), 14932545627345939108384737993416896211620458097792446905977180168342053585219, f_q)
            )
            mstore(
                0x1840,
                mulmod(
                    mload(0x1220), 13498745591877810872211159461644682954739332524336278910448604883789771736885, f_q
                )
            )
            mstore(
                0x1860,
                addmod(mload(0xa80), 8389497279961464350035246283612592133809031876079755433249599302786036758732, f_q)
            )
            mstore(
                0x1880,
                mulmod(
                    mload(0x1220), 20345677989844117909528750049476969581182118546166966482506114734614108237981, f_q
                )
            )
            mstore(
                0x18a0,
                addmod(mload(0xa80), 1542564881995157312717655695780305507366245854249067861192089451961700257636, f_q)
            )
            mstore(
                0x18c0,
                mulmod(mload(0x1220), 790608022292213379425324383664216541739009722347092850716054055768832299157, f_q)
            )
            mstore(
                0x18e0,
                addmod(mload(0xa80), 21097634849547061842821081361593058546809354678068941492982150130806976196460, f_q)
            )
            mstore(
                0x1900,
                mulmod(mload(0x1220), 5289443209903185443361862148540090689648485914368835830972895623576469023722, f_q)
            )
            mstore(
                0x1920,
                addmod(mload(0xa80), 16598799661936089778884543596717184398899878486047198512725308562999339471895, f_q)
            )
            mstore(
                0x1940,
                mulmod(
                    mload(0x1220), 15161189183906287273290738379431332336600234154579306802151507052820126345529, f_q
                )
            )
            mstore(
                0x1960,
                addmod(mload(0xa80), 6727053687932987948955667365825942751948130245836727541546697133755682150088, f_q)
            )
            mstore(
                0x1980,
                mulmod(mload(0x1220), 557567375339945239933617516585967620814823575807691402619711360028043331811, f_q)
            )
            mstore(
                0x19a0,
                addmod(mload(0xa80), 21330675496499329982312788228671307467733540824608342941078492826547765163806, f_q)
            )
            mstore(
                0x19c0,
                mulmod(
                    mload(0x1220), 16611719114775828483319365659907682366622074960672212059891361227499450055959, f_q
                )
            )
            mstore(
                0x19e0,
                addmod(mload(0xa80), 5276523757063446738927040085349592721926289439743822283806842959076358439658, f_q)
            )
            mstore(
                0x1a00,
                mulmod(mload(0x1220), 4509404676247677387317362072810231899718070082381452255950861037254608304934, f_q)
            )
            mstore(
                0x1a20,
                addmod(mload(0xa80), 17378838195591597834929043672447043188830294318034582087747343149321200190683, f_q)
            )
            mstore(
                0x1a40,
                mulmod(mload(0x1220), 6866457077948847028333856457654941632900463970069876241424363695212127143359, f_q)
            )
            mstore(
                0x1a60,
                addmod(mload(0xa80), 15021785793890428193912549287602333455647900430346158102273840491363681352258, f_q)
            )
            mstore(
                0x1a80,
                mulmod(
                    mload(0x1220), 20169013865622130318472103510465966222180994822334426398191891983290742724178, f_q
                )
            )
            mstore(
                0x1aa0,
                addmod(mload(0xa80), 1719229006217144903774302234791308866367369578081607945506312203285065771439, f_q)
            )
            mstore(
                0x1ac0,
                mulmod(
                    mload(0x1220), 14874205783542236433261764022044465911656512639684999678853651860683757650009, f_q
                )
            )
            mstore(
                0x1ae0,
                addmod(mload(0xa80), 7014037088297038788984641723212809176891851760731034664844552325892050845608, f_q)
            )
            mstore(
                0x1b00,
                mulmod(mload(0x1220), 2579947959091681244170407980400327834520881737801886423874592072501514087543, f_q)
            )
            mstore(
                0x1b20,
                addmod(mload(0xa80), 19308294912747593978075997764856947254027482662614147919823612114074294408074, f_q)
            )
            mstore(
                0x1b40,
                mulmod(
                    mload(0x1220), 17011225028452114973964561549541821925778010085385130152192105634715080939230, f_q
                )
            )
            mstore(
                0x1b60,
                addmod(mload(0xa80), 4877017843387160248281844195715453162770354315030904191506098551860727556387, f_q)
            )
            mstore(
                0x1b80,
                mulmod(mload(0x1220), 1881761935718519990121799628252273658786792458106649887437395059872945867717, f_q)
            )
            mstore(
                0x1ba0,
                addmod(mload(0xa80), 20006480936120755232124606117005001429761571942309384456260809126702862627900, f_q)
            )
            mstore(
                0x1bc0,
                mulmod(
                    mload(0x1220), 21662285561588145310352318480822402603888953131447478827940284064946709915517, f_q
                )
            )
            mstore(
                0x1be0,
                addmod(mload(0xa80), 225957310251129911894087264434872484659411268968555515757920121629098580100, f_q)
            )
            mstore(
                0x1c00,
                mulmod(
                    mload(0x1220), 21846745818185811051373434299876022191132089169516983080959277716660228899818, f_q
                )
            )
            mstore(
                0x1c20,
                addmod(mload(0xa80), 41497053653464170872971445381252897416275230899051262738926469915579595799, f_q)
            )
            mstore(
                0x1c40,
                mulmod(
                    mload(0x1220), 11770617947510597378885200406447716404126404817511323735042103519754393416137, f_q
                )
            )
            mstore(
                0x1c60,
                addmod(mload(0xa80), 10117624924328677843361205338809558684421959582904710608656100666821415079480, f_q)
            )
            mstore(
                0x1c80,
                mulmod(
                    mload(0x1220), 13018529307372270489258244406856841315962482733096074798317807775255504614069, f_q
                )
            )
            mstore(
                0x1ca0,
                addmod(mload(0xa80), 8869713564467004732988161338400433772585881667319959545380396411320303881548, f_q)
            )
            mstore(
                0x1cc0,
                mulmod(mload(0x1220), 5276270562549512946272803945594037128265390012927669941530122528135796334063, f_q)
            )
            mstore(
                0x1ce0,
                addmod(mload(0xa80), 16611972309289762275973601799663237960282974387488364402168081658440012161554, f_q)
            )
            mstore(
                0x1d00,
                mulmod(mload(0x1220), 1459528961030896569807206253631725410868595642414057264270714861278164633285, f_q)
            )
            mstore(
                0x1d20,
                addmod(mload(0xa80), 20428713910808378652439199491625549677679768758001977079427489325297643862332, f_q)
            )
            mstore(
                0x1d40,
                mulmod(mload(0x1220), 3194789416964050406424265110350613664596286587119568977604859939037397011192, f_q)
            )
            mstore(
                0x1d60,
                addmod(mload(0xa80), 18693453454875224815822140634906661423952077813296465366093344247538411484425, f_q)
            )
            mstore(
                0x1d80,
                mulmod(mload(0x1220), 3090451643741879200285099477849831179472024364989630500355756836624424014697, f_q)
            )
            mstore(
                0x1da0,
                addmod(mload(0xa80), 18797791228097396021961306267407443909076340035426403843342447349951384480920, f_q)
            )
            mstore(
                0x1dc0,
                mulmod(
                    mload(0x1220), 15927748781034921005593027077824543133423706442106451156060388409950986747549, f_q
                )
            )
            mstore(
                0x1de0,
                addmod(mload(0xa80), 5960494090804354216653378667432731955124657958309583187637815776624821748068, f_q)
            )
            mstore(
                0x1e00,
                mulmod(
                    mload(0x1220), 21594472933355353940227302948201802990541640451776958309590170926766063614527, f_q
                )
            )
            mstore(
                0x1e20,
                addmod(mload(0xa80), 293769938483921282019102797055472098006723948639076034108033259809744881090, f_q)
            )
            mstore(
                0x1e40,
                mulmod(
                    mload(0x1220), 18627493688178473377890450102960302362510276568110871848038317193719995024144, f_q
                )
            )
            mstore(
                0x1e60,
                addmod(mload(0xa80), 3260749183660801844355955642296972726038087832305162495659886992855813471473, f_q)
            )
            mstore(
                0x1e80,
                mulmod(
                    mload(0x1220), 15233875724801927436678555222002139405060841628305391430751578735629430475003, f_q
                )
            )
            mstore(
                0x1ea0,
                addmod(mload(0xa80), 6654367147037347785567850523255135683487522772110642912946625450946378020614, f_q)
            )
            mstore(
                0x1ec0,
                mulmod(
                    mload(0x1220), 12662796367122493153085459582914902083443981635312477834616629373139110863873, f_q
                )
            )
            mstore(
                0x1ee0,
                addmod(mload(0xa80), 9225446504716782069160946162342373005104382765103556509081574813436697631744, f_q)
            )
            mstore(
                0x1f00,
                mulmod(mload(0x1220), 9228489335593836417731216695316971397516686186585289059470421738439643366942, f_q)
            )
            mstore(
                0x1f20,
                addmod(mload(0xa80), 12659753536245438804515189049940303691031678213830745284227782448136165128675, f_q)
            )
            mstore(
                0x1f40,
                mulmod(mload(0x1220), 6904960663187367776878651408524770307710353971752548687936010869699798414796, f_q)
            )
            mstore(
                0x1f60,
                addmod(mload(0xa80), 14983282208651907445367754336732504780838010428663485655762193316876010080821, f_q)
            )
            {
                let prod := mload(0x1260)

                prod := mulmod(mload(0x12a0), prod, f_q)
                mstore(0x1f80, prod)

                prod := mulmod(mload(0x12e0), prod, f_q)
                mstore(0x1fa0, prod)

                prod := mulmod(mload(0x1320), prod, f_q)
                mstore(0x1fc0, prod)

                prod := mulmod(mload(0x1360), prod, f_q)
                mstore(0x1fe0, prod)

                prod := mulmod(mload(0x13a0), prod, f_q)
                mstore(0x2000, prod)

                prod := mulmod(mload(0x13e0), prod, f_q)
                mstore(0x2020, prod)

                prod := mulmod(mload(0x1420), prod, f_q)
                mstore(0x2040, prod)

                prod := mulmod(mload(0x1460), prod, f_q)
                mstore(0x2060, prod)

                prod := mulmod(mload(0x14a0), prod, f_q)
                mstore(0x2080, prod)

                prod := mulmod(mload(0x14e0), prod, f_q)
                mstore(0x20a0, prod)

                prod := mulmod(mload(0x1520), prod, f_q)
                mstore(0x20c0, prod)

                prod := mulmod(mload(0x1560), prod, f_q)
                mstore(0x20e0, prod)

                prod := mulmod(mload(0x15a0), prod, f_q)
                mstore(0x2100, prod)

                prod := mulmod(mload(0x15e0), prod, f_q)
                mstore(0x2120, prod)

                prod := mulmod(mload(0x1620), prod, f_q)
                mstore(0x2140, prod)

                prod := mulmod(mload(0x1660), prod, f_q)
                mstore(0x2160, prod)

                prod := mulmod(mload(0x16a0), prod, f_q)
                mstore(0x2180, prod)

                prod := mulmod(mload(0x16e0), prod, f_q)
                mstore(0x21a0, prod)

                prod := mulmod(mload(0x1720), prod, f_q)
                mstore(0x21c0, prod)

                prod := mulmod(mload(0x1760), prod, f_q)
                mstore(0x21e0, prod)

                prod := mulmod(mload(0x17a0), prod, f_q)
                mstore(0x2200, prod)

                prod := mulmod(mload(0x17e0), prod, f_q)
                mstore(0x2220, prod)

                prod := mulmod(mload(0x1820), prod, f_q)
                mstore(0x2240, prod)

                prod := mulmod(mload(0x1860), prod, f_q)
                mstore(0x2260, prod)

                prod := mulmod(mload(0x18a0), prod, f_q)
                mstore(0x2280, prod)

                prod := mulmod(mload(0x18e0), prod, f_q)
                mstore(0x22a0, prod)

                prod := mulmod(mload(0x1920), prod, f_q)
                mstore(0x22c0, prod)

                prod := mulmod(mload(0x1960), prod, f_q)
                mstore(0x22e0, prod)

                prod := mulmod(mload(0x19a0), prod, f_q)
                mstore(0x2300, prod)

                prod := mulmod(mload(0x19e0), prod, f_q)
                mstore(0x2320, prod)

                prod := mulmod(mload(0x1a20), prod, f_q)
                mstore(0x2340, prod)

                prod := mulmod(mload(0x1a60), prod, f_q)
                mstore(0x2360, prod)

                prod := mulmod(mload(0x1aa0), prod, f_q)
                mstore(0x2380, prod)

                prod := mulmod(mload(0x1ae0), prod, f_q)
                mstore(0x23a0, prod)

                prod := mulmod(mload(0x1b20), prod, f_q)
                mstore(0x23c0, prod)

                prod := mulmod(mload(0x1b60), prod, f_q)
                mstore(0x23e0, prod)

                prod := mulmod(mload(0x1ba0), prod, f_q)
                mstore(0x2400, prod)

                prod := mulmod(mload(0x1be0), prod, f_q)
                mstore(0x2420, prod)

                prod := mulmod(mload(0x1c20), prod, f_q)
                mstore(0x2440, prod)

                prod := mulmod(mload(0x1c60), prod, f_q)
                mstore(0x2460, prod)

                prod := mulmod(mload(0x1ca0), prod, f_q)
                mstore(0x2480, prod)

                prod := mulmod(mload(0x1ce0), prod, f_q)
                mstore(0x24a0, prod)

                prod := mulmod(mload(0x1d20), prod, f_q)
                mstore(0x24c0, prod)

                prod := mulmod(mload(0x1d60), prod, f_q)
                mstore(0x24e0, prod)

                prod := mulmod(mload(0x1da0), prod, f_q)
                mstore(0x2500, prod)

                prod := mulmod(mload(0x1de0), prod, f_q)
                mstore(0x2520, prod)

                prod := mulmod(mload(0x1e20), prod, f_q)
                mstore(0x2540, prod)

                prod := mulmod(mload(0x1e60), prod, f_q)
                mstore(0x2560, prod)

                prod := mulmod(mload(0x1ea0), prod, f_q)
                mstore(0x2580, prod)

                prod := mulmod(mload(0x1ee0), prod, f_q)
                mstore(0x25a0, prod)

                prod := mulmod(mload(0x1f20), prod, f_q)
                mstore(0x25c0, prod)

                prod := mulmod(mload(0x1f60), prod, f_q)
                mstore(0x25e0, prod)

                prod := mulmod(mload(0x1200), prod, f_q)
                mstore(0x2600, prod)
            }
            mstore(0x2640, 32)
            mstore(0x2660, 32)
            mstore(0x2680, 32)
            mstore(0x26a0, mload(0x2600))
            mstore(0x26c0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
            mstore(0x26e0, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
            success := and(eq(staticcall(gas(), 0x5, 0x2640, 0xc0, 0x2620, 0x20), 1), success)
            {
                let inv := mload(0x2620)
                let v

                v := mload(0x1200)
                mstore(4608, mulmod(mload(0x25e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1f60)
                mstore(8032, mulmod(mload(0x25c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1f20)
                mstore(7968, mulmod(mload(0x25a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ee0)
                mstore(7904, mulmod(mload(0x2580), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ea0)
                mstore(7840, mulmod(mload(0x2560), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1e60)
                mstore(7776, mulmod(mload(0x2540), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1e20)
                mstore(7712, mulmod(mload(0x2520), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1de0)
                mstore(7648, mulmod(mload(0x2500), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1da0)
                mstore(7584, mulmod(mload(0x24e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1d60)
                mstore(7520, mulmod(mload(0x24c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1d20)
                mstore(7456, mulmod(mload(0x24a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ce0)
                mstore(7392, mulmod(mload(0x2480), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ca0)
                mstore(7328, mulmod(mload(0x2460), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1c60)
                mstore(7264, mulmod(mload(0x2440), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1c20)
                mstore(7200, mulmod(mload(0x2420), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1be0)
                mstore(7136, mulmod(mload(0x2400), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ba0)
                mstore(7072, mulmod(mload(0x23e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1b60)
                mstore(7008, mulmod(mload(0x23c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1b20)
                mstore(6944, mulmod(mload(0x23a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ae0)
                mstore(6880, mulmod(mload(0x2380), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1aa0)
                mstore(6816, mulmod(mload(0x2360), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1a60)
                mstore(6752, mulmod(mload(0x2340), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1a20)
                mstore(6688, mulmod(mload(0x2320), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x19e0)
                mstore(6624, mulmod(mload(0x2300), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x19a0)
                mstore(6560, mulmod(mload(0x22e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1960)
                mstore(6496, mulmod(mload(0x22c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1920)
                mstore(6432, mulmod(mload(0x22a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x18e0)
                mstore(6368, mulmod(mload(0x2280), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x18a0)
                mstore(6304, mulmod(mload(0x2260), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1860)
                mstore(6240, mulmod(mload(0x2240), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1820)
                mstore(6176, mulmod(mload(0x2220), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x17e0)
                mstore(6112, mulmod(mload(0x2200), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x17a0)
                mstore(6048, mulmod(mload(0x21e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1760)
                mstore(5984, mulmod(mload(0x21c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1720)
                mstore(5920, mulmod(mload(0x21a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x16e0)
                mstore(5856, mulmod(mload(0x2180), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x16a0)
                mstore(5792, mulmod(mload(0x2160), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1660)
                mstore(5728, mulmod(mload(0x2140), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1620)
                mstore(5664, mulmod(mload(0x2120), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x15e0)
                mstore(5600, mulmod(mload(0x2100), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x15a0)
                mstore(5536, mulmod(mload(0x20e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1560)
                mstore(5472, mulmod(mload(0x20c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1520)
                mstore(5408, mulmod(mload(0x20a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x14e0)
                mstore(5344, mulmod(mload(0x2080), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x14a0)
                mstore(5280, mulmod(mload(0x2060), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1460)
                mstore(5216, mulmod(mload(0x2040), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1420)
                mstore(5152, mulmod(mload(0x2020), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x13e0)
                mstore(5088, mulmod(mload(0x2000), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x13a0)
                mstore(5024, mulmod(mload(0x1fe0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1360)
                mstore(4960, mulmod(mload(0x1fc0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1320)
                mstore(4896, mulmod(mload(0x1fa0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x12e0)
                mstore(4832, mulmod(mload(0x1f80), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x12a0)
                mstore(4768, mulmod(mload(0x1260), inv, f_q))
                inv := mulmod(v, inv, f_q)
                mstore(0x1260, inv)
            }
            mstore(0x2700, mulmod(mload(0x1240), mload(0x1260), f_q))
            mstore(0x2720, mulmod(mload(0x1280), mload(0x12a0), f_q))
            mstore(0x2740, mulmod(mload(0x12c0), mload(0x12e0), f_q))
            mstore(0x2760, mulmod(mload(0x1300), mload(0x1320), f_q))
            mstore(0x2780, mulmod(mload(0x1340), mload(0x1360), f_q))
            mstore(0x27a0, mulmod(mload(0x1380), mload(0x13a0), f_q))
            mstore(0x27c0, mulmod(mload(0x13c0), mload(0x13e0), f_q))
            mstore(0x27e0, mulmod(mload(0x1400), mload(0x1420), f_q))
            mstore(0x2800, mulmod(mload(0x1440), mload(0x1460), f_q))
            mstore(0x2820, mulmod(mload(0x1480), mload(0x14a0), f_q))
            mstore(0x2840, mulmod(mload(0x14c0), mload(0x14e0), f_q))
            mstore(0x2860, mulmod(mload(0x1500), mload(0x1520), f_q))
            mstore(0x2880, mulmod(mload(0x1540), mload(0x1560), f_q))
            mstore(0x28a0, mulmod(mload(0x1580), mload(0x15a0), f_q))
            mstore(0x28c0, mulmod(mload(0x15c0), mload(0x15e0), f_q))
            mstore(0x28e0, mulmod(mload(0x1600), mload(0x1620), f_q))
            mstore(0x2900, mulmod(mload(0x1640), mload(0x1660), f_q))
            mstore(0x2920, mulmod(mload(0x1680), mload(0x16a0), f_q))
            mstore(0x2940, mulmod(mload(0x16c0), mload(0x16e0), f_q))
            mstore(0x2960, mulmod(mload(0x1700), mload(0x1720), f_q))
            mstore(0x2980, mulmod(mload(0x1740), mload(0x1760), f_q))
            mstore(0x29a0, mulmod(mload(0x1780), mload(0x17a0), f_q))
            mstore(0x29c0, mulmod(mload(0x17c0), mload(0x17e0), f_q))
            mstore(0x29e0, mulmod(mload(0x1800), mload(0x1820), f_q))
            mstore(0x2a00, mulmod(mload(0x1840), mload(0x1860), f_q))
            mstore(0x2a20, mulmod(mload(0x1880), mload(0x18a0), f_q))
            mstore(0x2a40, mulmod(mload(0x18c0), mload(0x18e0), f_q))
            mstore(0x2a60, mulmod(mload(0x1900), mload(0x1920), f_q))
            mstore(0x2a80, mulmod(mload(0x1940), mload(0x1960), f_q))
            mstore(0x2aa0, mulmod(mload(0x1980), mload(0x19a0), f_q))
            mstore(0x2ac0, mulmod(mload(0x19c0), mload(0x19e0), f_q))
            mstore(0x2ae0, mulmod(mload(0x1a00), mload(0x1a20), f_q))
            mstore(0x2b00, mulmod(mload(0x1a40), mload(0x1a60), f_q))
            mstore(0x2b20, mulmod(mload(0x1a80), mload(0x1aa0), f_q))
            mstore(0x2b40, mulmod(mload(0x1ac0), mload(0x1ae0), f_q))
            mstore(0x2b60, mulmod(mload(0x1b00), mload(0x1b20), f_q))
            mstore(0x2b80, mulmod(mload(0x1b40), mload(0x1b60), f_q))
            mstore(0x2ba0, mulmod(mload(0x1b80), mload(0x1ba0), f_q))
            mstore(0x2bc0, mulmod(mload(0x1bc0), mload(0x1be0), f_q))
            mstore(0x2be0, mulmod(mload(0x1c00), mload(0x1c20), f_q))
            mstore(0x2c00, mulmod(mload(0x1c40), mload(0x1c60), f_q))
            mstore(0x2c20, mulmod(mload(0x1c80), mload(0x1ca0), f_q))
            mstore(0x2c40, mulmod(mload(0x1cc0), mload(0x1ce0), f_q))
            mstore(0x2c60, mulmod(mload(0x1d00), mload(0x1d20), f_q))
            mstore(0x2c80, mulmod(mload(0x1d40), mload(0x1d60), f_q))
            mstore(0x2ca0, mulmod(mload(0x1d80), mload(0x1da0), f_q))
            mstore(0x2cc0, mulmod(mload(0x1dc0), mload(0x1de0), f_q))
            mstore(0x2ce0, mulmod(mload(0x1e00), mload(0x1e20), f_q))
            mstore(0x2d00, mulmod(mload(0x1e40), mload(0x1e60), f_q))
            mstore(0x2d20, mulmod(mload(0x1e80), mload(0x1ea0), f_q))
            mstore(0x2d40, mulmod(mload(0x1ec0), mload(0x1ee0), f_q))
            mstore(0x2d60, mulmod(mload(0x1f00), mload(0x1f20), f_q))
            mstore(0x2d80, mulmod(mload(0x1f40), mload(0x1f60), f_q))
            {
                let result := mulmod(mload(0x27e0), mload(0xa0), f_q)
                result := addmod(mulmod(mload(0x2800), mload(0xc0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2820), mload(0xe0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2840), mload(0x100), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2860), mload(0x120), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2880), mload(0x140), f_q), result, f_q)
                result := addmod(mulmod(mload(0x28a0), mload(0x160), f_q), result, f_q)
                result := addmod(mulmod(mload(0x28c0), mload(0x180), f_q), result, f_q)
                result := addmod(mulmod(mload(0x28e0), mload(0x1a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2900), mload(0x1c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2920), mload(0x1e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2940), mload(0x200), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2960), mload(0x220), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2980), mload(0x240), f_q), result, f_q)
                result := addmod(mulmod(mload(0x29a0), mload(0x260), f_q), result, f_q)
                result := addmod(mulmod(mload(0x29c0), mload(0x280), f_q), result, f_q)
                result := addmod(mulmod(mload(0x29e0), mload(0x2a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a00), mload(0x2c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a20), mload(0x2e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a40), mload(0x300), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a60), mload(0x320), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a80), mload(0x340), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2aa0), mload(0x360), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ac0), mload(0x380), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ae0), mload(0x3a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b00), mload(0x3c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b20), mload(0x3e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b40), mload(0x400), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b60), mload(0x420), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b80), mload(0x440), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ba0), mload(0x460), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2bc0), mload(0x480), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2be0), mload(0x4a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c00), mload(0x4c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c20), mload(0x4e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c40), mload(0x500), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c60), mload(0x520), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c80), mload(0x540), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ca0), mload(0x560), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2cc0), mload(0x580), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ce0), mload(0x5a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d00), mload(0x5c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d20), mload(0x5e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d40), mload(0x600), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d60), mload(0x620), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d80), mload(0x640), f_q), result, f_q)
                mstore(11680, result)
            }
            mstore(0x2dc0, mulmod(mload(0xb00), mload(0xae0), f_q))
            mstore(0x2de0, addmod(mload(0xac0), mload(0x2dc0), f_q))
            mstore(0x2e00, addmod(mload(0x2de0), sub(f_q, mload(0xb20)), f_q))
            mstore(0x2e20, mulmod(mload(0x2e00), mload(0xb80), f_q))
            mstore(0x2e40, mulmod(mload(0x920), mload(0x2e20), f_q))
            mstore(0x2e60, addmod(1, sub(f_q, mload(0xc40)), f_q))
            mstore(0x2e80, mulmod(mload(0x2e60), mload(0x27e0), f_q))
            mstore(0x2ea0, addmod(mload(0x2e40), mload(0x2e80), f_q))
            mstore(0x2ec0, mulmod(mload(0x920), mload(0x2ea0), f_q))
            mstore(0x2ee0, mulmod(mload(0xc40), mload(0xc40), f_q))
            mstore(0x2f00, addmod(mload(0x2ee0), sub(f_q, mload(0xc40)), f_q))
            mstore(0x2f20, mulmod(mload(0x2f00), mload(0x2700), f_q))
            mstore(0x2f40, addmod(mload(0x2ec0), mload(0x2f20), f_q))
            mstore(0x2f60, mulmod(mload(0x920), mload(0x2f40), f_q))
            mstore(0x2f80, addmod(1, sub(f_q, mload(0x2700)), f_q))
            mstore(0x2fa0, addmod(mload(0x2720), mload(0x2740), f_q))
            mstore(0x2fc0, addmod(mload(0x2fa0), mload(0x2760), f_q))
            mstore(0x2fe0, addmod(mload(0x2fc0), mload(0x2780), f_q))
            mstore(0x3000, addmod(mload(0x2fe0), mload(0x27a0), f_q))
            mstore(0x3020, addmod(mload(0x3000), mload(0x27c0), f_q))
            mstore(0x3040, addmod(mload(0x2f80), sub(f_q, mload(0x3020)), f_q))
            mstore(0x3060, mulmod(mload(0xbe0), mload(0x7a0), f_q))
            mstore(0x3080, addmod(mload(0xb40), mload(0x3060), f_q))
            mstore(0x30a0, addmod(mload(0x3080), mload(0x800), f_q))
            mstore(0x30c0, mulmod(mload(0xc00), mload(0x7a0), f_q))
            mstore(0x30e0, addmod(mload(0xac0), mload(0x30c0), f_q))
            mstore(0x3100, addmod(mload(0x30e0), mload(0x800), f_q))
            mstore(0x3120, mulmod(mload(0x3100), mload(0x30a0), f_q))
            mstore(0x3140, mulmod(mload(0xc20), mload(0x7a0), f_q))
            mstore(0x3160, addmod(mload(0x2da0), mload(0x3140), f_q))
            mstore(0x3180, addmod(mload(0x3160), mload(0x800), f_q))
            mstore(0x31a0, mulmod(mload(0x3180), mload(0x3120), f_q))
            mstore(0x31c0, mulmod(mload(0x31a0), mload(0xc60), f_q))
            mstore(0x31e0, mulmod(1, mload(0x7a0), f_q))
            mstore(0x3200, mulmod(mload(0xa80), mload(0x31e0), f_q))
            mstore(0x3220, addmod(mload(0xb40), mload(0x3200), f_q))
            mstore(0x3240, addmod(mload(0x3220), mload(0x800), f_q))
            mstore(
                0x3260,
                mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, mload(0x7a0), f_q)
            )
            mstore(0x3280, mulmod(mload(0xa80), mload(0x3260), f_q))
            mstore(0x32a0, addmod(mload(0xac0), mload(0x3280), f_q))
            mstore(0x32c0, addmod(mload(0x32a0), mload(0x800), f_q))
            mstore(0x32e0, mulmod(mload(0x32c0), mload(0x3240), f_q))
            mstore(
                0x3300,
                mulmod(8910878055287538404433155982483128285667088683464058436815641868457422632747, mload(0x7a0), f_q)
            )
            mstore(0x3320, mulmod(mload(0xa80), mload(0x3300), f_q))
            mstore(0x3340, addmod(mload(0x2da0), mload(0x3320), f_q))
            mstore(0x3360, addmod(mload(0x3340), mload(0x800), f_q))
            mstore(0x3380, mulmod(mload(0x3360), mload(0x32e0), f_q))
            mstore(0x33a0, mulmod(mload(0x3380), mload(0xc40), f_q))
            mstore(0x33c0, addmod(mload(0x31c0), sub(f_q, mload(0x33a0)), f_q))
            mstore(0x33e0, mulmod(mload(0x33c0), mload(0x3040), f_q))
            mstore(0x3400, addmod(mload(0x2f60), mload(0x33e0), f_q))
            mstore(0x3420, mulmod(mload(0x920), mload(0x3400), f_q))
            mstore(0x3440, addmod(1, sub(f_q, mload(0xc80)), f_q))
            mstore(0x3460, mulmod(mload(0x3440), mload(0x27e0), f_q))
            mstore(0x3480, addmod(mload(0x3420), mload(0x3460), f_q))
            mstore(0x34a0, mulmod(mload(0x920), mload(0x3480), f_q))
            mstore(0x34c0, mulmod(mload(0xc80), mload(0xc80), f_q))
            mstore(0x34e0, addmod(mload(0x34c0), sub(f_q, mload(0xc80)), f_q))
            mstore(0x3500, mulmod(mload(0x34e0), mload(0x2700), f_q))
            mstore(0x3520, addmod(mload(0x34a0), mload(0x3500), f_q))
            mstore(0x3540, mulmod(mload(0x920), mload(0x3520), f_q))
            mstore(0x3560, addmod(mload(0xcc0), mload(0x7a0), f_q))
            mstore(0x3580, mulmod(mload(0x3560), mload(0xca0), f_q))
            mstore(0x35a0, addmod(mload(0xd00), mload(0x800), f_q))
            mstore(0x35c0, mulmod(mload(0x35a0), mload(0x3580), f_q))
            mstore(0x35e0, mulmod(mload(0xac0), mload(0xba0), f_q))
            mstore(0x3600, addmod(mload(0x35e0), mload(0x7a0), f_q))
            mstore(0x3620, mulmod(mload(0x3600), mload(0xc80), f_q))
            mstore(0x3640, addmod(mload(0xb60), mload(0x800), f_q))
            mstore(0x3660, mulmod(mload(0x3640), mload(0x3620), f_q))
            mstore(0x3680, addmod(mload(0x35c0), sub(f_q, mload(0x3660)), f_q))
            mstore(0x36a0, mulmod(mload(0x3680), mload(0x3040), f_q))
            mstore(0x36c0, addmod(mload(0x3540), mload(0x36a0), f_q))
            mstore(0x36e0, mulmod(mload(0x920), mload(0x36c0), f_q))
            mstore(0x3700, addmod(mload(0xcc0), sub(f_q, mload(0xd00)), f_q))
            mstore(0x3720, mulmod(mload(0x3700), mload(0x27e0), f_q))
            mstore(0x3740, addmod(mload(0x36e0), mload(0x3720), f_q))
            mstore(0x3760, mulmod(mload(0x920), mload(0x3740), f_q))
            mstore(0x3780, mulmod(mload(0x3700), mload(0x3040), f_q))
            mstore(0x37a0, addmod(mload(0xcc0), sub(f_q, mload(0xce0)), f_q))
            mstore(0x37c0, mulmod(mload(0x37a0), mload(0x3780), f_q))
            mstore(0x37e0, addmod(mload(0x3760), mload(0x37c0), f_q))
            mstore(0x3800, mulmod(mload(0x11e0), mload(0x11e0), f_q))
            mstore(0x3820, mulmod(mload(0x3800), mload(0x11e0), f_q))
            mstore(0x3840, mulmod(mload(0x3820), mload(0x11e0), f_q))
            mstore(0x3860, mulmod(1, mload(0x11e0), f_q))
            mstore(0x3880, mulmod(1, mload(0x3800), f_q))
            mstore(0x38a0, mulmod(1, mload(0x3820), f_q))
            mstore(0x38c0, mulmod(mload(0x37e0), mload(0x1200), f_q))
            mstore(0x38e0, mulmod(mload(0xf40), mload(0xa80), f_q))
            mstore(0x3900, mulmod(mload(0x38e0), mload(0xa80), f_q))
            mstore(
                0x3920,
                mulmod(mload(0xa80), 8734126352828345679573237859165904705806588461301144420590422589042130041188, f_q)
            )
            mstore(0x3940, addmod(mload(0xe40), sub(f_q, mload(0x3920)), f_q))
            mstore(0x3960, mulmod(mload(0xa80), 1, f_q))
            mstore(0x3980, addmod(mload(0xe40), sub(f_q, mload(0x3960)), f_q))
            mstore(
                0x39a0,
                mulmod(mload(0xa80), 11211301017135681023579411905410872569206244553457844956874280139879520583390, f_q)
            )
            mstore(0x39c0, addmod(mload(0xe40), sub(f_q, mload(0x39a0)), f_q))
            mstore(
                0x39e0,
                mulmod(mload(0xa80), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q)
            )
            mstore(0x3a00, addmod(mload(0xe40), sub(f_q, mload(0x39e0)), f_q))
            mstore(
                0x3a20,
                mulmod(mload(0xa80), 12619617507853212586156872920672483948819476989779550311307282715684870266992, f_q)
            )
            mstore(0x3a40, addmod(mload(0xe40), sub(f_q, mload(0x3a20)), f_q))
            mstore(
                0x3a60,
                mulmod(3544324119167359571073009690693121464267965232733679586767649244433889388945, mload(0x38e0), f_q)
            )
            mstore(0x3a80, mulmod(mload(0x3a60), 1, f_q))
            {
                let result := mulmod(mload(0xe40), mload(0x3a60), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3a80)), f_q), result, f_q)
                mstore(15008, result)
            }
            mstore(
                0x3ac0,
                mulmod(3860370625838117017501327045244227871206764201116468958063324100051382735289, mload(0x38e0), f_q)
            )
            mstore(
                0x3ae0,
                mulmod(
                    mload(0x3ac0), 11211301017135681023579411905410872569206244553457844956874280139879520583390, f_q
                )
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3ac0), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3ae0)), f_q), result, f_q)
                mstore(15104, result)
            }
            mstore(
                0x3b20,
                mulmod(
                    21616901807277407275624036604424346159916096890712898844034238973395610537327, mload(0x38e0), f_q
                )
            )
            mstore(
                0x3b40,
                mulmod(mload(0x3b20), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q)
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3b20), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3b40)), f_q), result, f_q)
                mstore(15200, result)
            }
            mstore(
                0x3b80,
                mulmod(3209408481237076479025468386201293941554240476766691830436732310949352383503, mload(0x38e0), f_q)
            )
            mstore(
                0x3ba0,
                mulmod(
                    mload(0x3b80), 12619617507853212586156872920672483948819476989779550311307282715684870266992, f_q
                )
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3b80), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3ba0)), f_q), result, f_q)
                mstore(15296, result)
            }
            mstore(0x3be0, mulmod(1, mload(0x3980), f_q))
            mstore(0x3c00, mulmod(mload(0x3be0), mload(0x39c0), f_q))
            mstore(0x3c20, mulmod(mload(0x3c00), mload(0x3a00), f_q))
            mstore(0x3c40, mulmod(mload(0x3c20), mload(0x3a40), f_q))
            mstore(
                0x3c60,
                mulmod(10676941854703594198666993839846402519342119846958189386823924046696287912228, mload(0xa80), f_q)
            )
            mstore(0x3c80, mulmod(mload(0x3c60), 1, f_q))
            {
                let result := mulmod(mload(0xe40), mload(0x3c60), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3c80)), f_q), result, f_q)
                mstore(15520, result)
            }
            mstore(
                0x3cc0,
                mulmod(11211301017135681023579411905410872569206244553457844956874280139879520583389, mload(0xa80), f_q)
            )
            mstore(
                0x3ce0,
                mulmod(
                    mload(0x3cc0), 11211301017135681023579411905410872569206244553457844956874280139879520583390, f_q
                )
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3cc0), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3ce0)), f_q), result, f_q)
                mstore(15616, result)
            }
            mstore(
                0x3d20,
                mulmod(13154116519010929542673167886091370382741775939114889923107781597533678454430, mload(0xa80), f_q)
            )
            mstore(0x3d40, mulmod(mload(0x3d20), 1, f_q))
            {
                let result := mulmod(mload(0xe40), mload(0x3d20), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3d40)), f_q), result, f_q)
                mstore(15712, result)
            }
            mstore(
                0x3d80,
                mulmod(8734126352828345679573237859165904705806588461301144420590422589042130041187, mload(0xa80), f_q)
            )
            mstore(
                0x3da0,
                mulmod(mload(0x3d80), 8734126352828345679573237859165904705806588461301144420590422589042130041188, f_q)
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3d80), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3da0)), f_q), result, f_q)
                mstore(15808, result)
            }
            mstore(0x3de0, mulmod(mload(0x3be0), mload(0x3940), f_q))
            {
                let result := mulmod(mload(0xe40), 1, f_q)
                result :=
                    addmod(
                        mulmod(
                            mload(0xa80), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q
                        ),
                        result,
                        f_q
                    )
                mstore(15872, result)
            }
            {
                let prod := mload(0x3aa0)

                prod := mulmod(mload(0x3b00), prod, f_q)
                mstore(0x3e20, prod)

                prod := mulmod(mload(0x3b60), prod, f_q)
                mstore(0x3e40, prod)

                prod := mulmod(mload(0x3bc0), prod, f_q)
                mstore(0x3e60, prod)

                prod := mulmod(mload(0x3ca0), prod, f_q)
                mstore(0x3e80, prod)

                prod := mulmod(mload(0x3d00), prod, f_q)
                mstore(0x3ea0, prod)

                prod := mulmod(mload(0x3c00), prod, f_q)
                mstore(0x3ec0, prod)

                prod := mulmod(mload(0x3d60), prod, f_q)
                mstore(0x3ee0, prod)

                prod := mulmod(mload(0x3dc0), prod, f_q)
                mstore(0x3f00, prod)

                prod := mulmod(mload(0x3de0), prod, f_q)
                mstore(0x3f20, prod)

                prod := mulmod(mload(0x3e00), prod, f_q)
                mstore(0x3f40, prod)

                prod := mulmod(mload(0x3be0), prod, f_q)
                mstore(0x3f60, prod)
            }
            mstore(0x3fa0, 32)
            mstore(0x3fc0, 32)
            mstore(0x3fe0, 32)
            mstore(0x4000, mload(0x3f60))
            mstore(0x4020, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
            mstore(0x4040, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
            success := and(eq(staticcall(gas(), 0x5, 0x3fa0, 0xc0, 0x3f80, 0x20), 1), success)
            {
                let inv := mload(0x3f80)
                let v

                v := mload(0x3be0)
                mstore(15328, mulmod(mload(0x3f40), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3e00)
                mstore(15872, mulmod(mload(0x3f20), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3de0)
                mstore(15840, mulmod(mload(0x3f00), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3dc0)
                mstore(15808, mulmod(mload(0x3ee0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3d60)
                mstore(15712, mulmod(mload(0x3ec0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3c00)
                mstore(15360, mulmod(mload(0x3ea0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3d00)
                mstore(15616, mulmod(mload(0x3e80), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3ca0)
                mstore(15520, mulmod(mload(0x3e60), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3bc0)
                mstore(15296, mulmod(mload(0x3e40), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3b60)
                mstore(15200, mulmod(mload(0x3e20), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3b00)
                mstore(15104, mulmod(mload(0x3aa0), inv, f_q))
                inv := mulmod(v, inv, f_q)
                mstore(0x3aa0, inv)
            }
            {
                let result := mload(0x3aa0)
                result := addmod(mload(0x3b00), result, f_q)
                result := addmod(mload(0x3b60), result, f_q)
                result := addmod(mload(0x3bc0), result, f_q)
                mstore(16480, result)
            }
            mstore(0x4080, mulmod(mload(0x3c40), mload(0x3c00), f_q))
            {
                let result := mload(0x3ca0)
                result := addmod(mload(0x3d00), result, f_q)
                mstore(16544, result)
            }
            mstore(0x40c0, mulmod(mload(0x3c40), mload(0x3de0), f_q))
            {
                let result := mload(0x3d60)
                result := addmod(mload(0x3dc0), result, f_q)
                mstore(16608, result)
            }
            mstore(0x4100, mulmod(mload(0x3c40), mload(0x3be0), f_q))
            {
                let result := mload(0x3e00)
                mstore(16672, result)
            }
            {
                let prod := mload(0x4060)

                prod := mulmod(mload(0x40a0), prod, f_q)
                mstore(0x4140, prod)

                prod := mulmod(mload(0x40e0), prod, f_q)
                mstore(0x4160, prod)

                prod := mulmod(mload(0x4120), prod, f_q)
                mstore(0x4180, prod)
            }
            mstore(0x41c0, 32)
            mstore(0x41e0, 32)
            mstore(0x4200, 32)
            mstore(0x4220, mload(0x4180))
            mstore(0x4240, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
            mstore(0x4260, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
            success := and(eq(staticcall(gas(), 0x5, 0x41c0, 0xc0, 0x41a0, 0x20), 1), success)
            {
                let inv := mload(0x41a0)
                let v

                v := mload(0x4120)
                mstore(16672, mulmod(mload(0x4160), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x40e0)
                mstore(16608, mulmod(mload(0x4140), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x40a0)
                mstore(16544, mulmod(mload(0x4060), inv, f_q))
                inv := mulmod(v, inv, f_q)
                mstore(0x4060, inv)
            }
            mstore(0x4280, mulmod(mload(0x4080), mload(0x40a0), f_q))
            mstore(0x42a0, mulmod(mload(0x40c0), mload(0x40e0), f_q))
            mstore(0x42c0, mulmod(mload(0x4100), mload(0x4120), f_q))
            mstore(0x42e0, mulmod(mload(0xd40), mload(0xd40), f_q))
            mstore(0x4300, mulmod(mload(0x42e0), mload(0xd40), f_q))
            mstore(0x4320, mulmod(mload(0x4300), mload(0xd40), f_q))
            mstore(0x4340, mulmod(mload(0x4320), mload(0xd40), f_q))
            mstore(0x4360, mulmod(mload(0x4340), mload(0xd40), f_q))
            mstore(0x4380, mulmod(mload(0x4360), mload(0xd40), f_q))
            mstore(0x43a0, mulmod(mload(0x4380), mload(0xd40), f_q))
            mstore(0x43c0, mulmod(mload(0x43a0), mload(0xd40), f_q))
            mstore(0x43e0, mulmod(mload(0x43c0), mload(0xd40), f_q))
            mstore(0x4400, mulmod(mload(0xda0), mload(0xda0), f_q))
            mstore(0x4420, mulmod(mload(0x4400), mload(0xda0), f_q))
            mstore(0x4440, mulmod(mload(0x4420), mload(0xda0), f_q))
            {
                let result := mulmod(mload(0xac0), mload(0x3aa0), f_q)
                result := addmod(mulmod(mload(0xae0), mload(0x3b00), f_q), result, f_q)
                result := addmod(mulmod(mload(0xb00), mload(0x3b60), f_q), result, f_q)
                result := addmod(mulmod(mload(0xb20), mload(0x3bc0), f_q), result, f_q)
                mstore(17504, result)
            }
            mstore(0x4480, mulmod(mload(0x4460), mload(0x4060), f_q))
            mstore(0x44a0, mulmod(sub(f_q, mload(0x4480)), 1, f_q))
            mstore(0x44c0, mulmod(mload(0x44a0), 1, f_q))
            mstore(0x44e0, mulmod(1, mload(0x4080), f_q))
            {
                let result := mulmod(mload(0xc40), mload(0x3ca0), f_q)
                result := addmod(mulmod(mload(0xc60), mload(0x3d00), f_q), result, f_q)
                mstore(17664, result)
            }
            mstore(0x4520, mulmod(mload(0x4500), mload(0x4280), f_q))
            mstore(0x4540, mulmod(sub(f_q, mload(0x4520)), 1, f_q))
            mstore(0x4560, mulmod(mload(0x44e0), 1, f_q))
            {
                let result := mulmod(mload(0xc80), mload(0x3ca0), f_q)
                result := addmod(mulmod(mload(0xca0), mload(0x3d00), f_q), result, f_q)
                mstore(17792, result)
            }
            mstore(0x45a0, mulmod(mload(0x4580), mload(0x4280), f_q))
            mstore(0x45c0, mulmod(sub(f_q, mload(0x45a0)), mload(0xd40), f_q))
            mstore(0x45e0, mulmod(mload(0x44e0), mload(0xd40), f_q))
            mstore(0x4600, addmod(mload(0x4540), mload(0x45c0), f_q))
            mstore(0x4620, mulmod(mload(0x4600), mload(0xda0), f_q))
            mstore(0x4640, mulmod(mload(0x4560), mload(0xda0), f_q))
            mstore(0x4660, mulmod(mload(0x45e0), mload(0xda0), f_q))
            mstore(0x4680, addmod(mload(0x44c0), mload(0x4620), f_q))
            mstore(0x46a0, mulmod(1, mload(0x40c0), f_q))
            {
                let result := mulmod(mload(0xcc0), mload(0x3d60), f_q)
                result := addmod(mulmod(mload(0xce0), mload(0x3dc0), f_q), result, f_q)
                mstore(18112, result)
            }
            mstore(0x46e0, mulmod(mload(0x46c0), mload(0x42a0), f_q))
            mstore(0x4700, mulmod(sub(f_q, mload(0x46e0)), 1, f_q))
            mstore(0x4720, mulmod(mload(0x46a0), 1, f_q))
            mstore(0x4740, mulmod(mload(0x4700), mload(0x4400), f_q))
            mstore(0x4760, mulmod(mload(0x4720), mload(0x4400), f_q))
            mstore(0x4780, addmod(mload(0x4680), mload(0x4740), f_q))
            mstore(0x47a0, mulmod(1, mload(0x4100), f_q))
            {
                let result := mulmod(mload(0xd00), mload(0x3e00), f_q)
                mstore(18368, result)
            }
            mstore(0x47e0, mulmod(mload(0x47c0), mload(0x42c0), f_q))
            mstore(0x4800, mulmod(sub(f_q, mload(0x47e0)), 1, f_q))
            mstore(0x4820, mulmod(mload(0x47a0), 1, f_q))
            {
                let result := mulmod(mload(0xb40), mload(0x3e00), f_q)
                mstore(18496, result)
            }
            mstore(0x4860, mulmod(mload(0x4840), mload(0x42c0), f_q))
            mstore(0x4880, mulmod(sub(f_q, mload(0x4860)), mload(0xd40), f_q))
            mstore(0x48a0, mulmod(mload(0x47a0), mload(0xd40), f_q))
            mstore(0x48c0, addmod(mload(0x4800), mload(0x4880), f_q))
            {
                let result := mulmod(mload(0xb60), mload(0x3e00), f_q)
                mstore(18656, result)
            }
            mstore(0x4900, mulmod(mload(0x48e0), mload(0x42c0), f_q))
            mstore(0x4920, mulmod(sub(f_q, mload(0x4900)), mload(0x42e0), f_q))
            mstore(0x4940, mulmod(mload(0x47a0), mload(0x42e0), f_q))
            mstore(0x4960, addmod(mload(0x48c0), mload(0x4920), f_q))
            {
                let result := mulmod(mload(0xb80), mload(0x3e00), f_q)
                mstore(18816, result)
            }
            mstore(0x49a0, mulmod(mload(0x4980), mload(0x42c0), f_q))
            mstore(0x49c0, mulmod(sub(f_q, mload(0x49a0)), mload(0x4300), f_q))
            mstore(0x49e0, mulmod(mload(0x47a0), mload(0x4300), f_q))
            mstore(0x4a00, addmod(mload(0x4960), mload(0x49c0), f_q))
            {
                let result := mulmod(mload(0xba0), mload(0x3e00), f_q)
                mstore(18976, result)
            }
            mstore(0x4a40, mulmod(mload(0x4a20), mload(0x42c0), f_q))
            mstore(0x4a60, mulmod(sub(f_q, mload(0x4a40)), mload(0x4320), f_q))
            mstore(0x4a80, mulmod(mload(0x47a0), mload(0x4320), f_q))
            mstore(0x4aa0, addmod(mload(0x4a00), mload(0x4a60), f_q))
            {
                let result := mulmod(mload(0xbe0), mload(0x3e00), f_q)
                mstore(19136, result)
            }
            mstore(0x4ae0, mulmod(mload(0x4ac0), mload(0x42c0), f_q))
            mstore(0x4b00, mulmod(sub(f_q, mload(0x4ae0)), mload(0x4340), f_q))
            mstore(0x4b20, mulmod(mload(0x47a0), mload(0x4340), f_q))
            mstore(0x4b40, addmod(mload(0x4aa0), mload(0x4b00), f_q))
            {
                let result := mulmod(mload(0xc00), mload(0x3e00), f_q)
                mstore(19296, result)
            }
            mstore(0x4b80, mulmod(mload(0x4b60), mload(0x42c0), f_q))
            mstore(0x4ba0, mulmod(sub(f_q, mload(0x4b80)), mload(0x4360), f_q))
            mstore(0x4bc0, mulmod(mload(0x47a0), mload(0x4360), f_q))
            mstore(0x4be0, addmod(mload(0x4b40), mload(0x4ba0), f_q))
            {
                let result := mulmod(mload(0xc20), mload(0x3e00), f_q)
                mstore(19456, result)
            }
            mstore(0x4c20, mulmod(mload(0x4c00), mload(0x42c0), f_q))
            mstore(0x4c40, mulmod(sub(f_q, mload(0x4c20)), mload(0x4380), f_q))
            mstore(0x4c60, mulmod(mload(0x47a0), mload(0x4380), f_q))
            mstore(0x4c80, addmod(mload(0x4be0), mload(0x4c40), f_q))
            mstore(0x4ca0, mulmod(mload(0x3860), mload(0x4100), f_q))
            mstore(0x4cc0, mulmod(mload(0x3880), mload(0x4100), f_q))
            mstore(0x4ce0, mulmod(mload(0x38a0), mload(0x4100), f_q))
            {
                let result := mulmod(mload(0x38c0), mload(0x3e00), f_q)
                mstore(19712, result)
            }
            mstore(0x4d20, mulmod(mload(0x4d00), mload(0x42c0), f_q))
            mstore(0x4d40, mulmod(sub(f_q, mload(0x4d20)), mload(0x43a0), f_q))
            mstore(0x4d60, mulmod(mload(0x47a0), mload(0x43a0), f_q))
            mstore(0x4d80, mulmod(mload(0x4ca0), mload(0x43a0), f_q))
            mstore(0x4da0, mulmod(mload(0x4cc0), mload(0x43a0), f_q))
            mstore(0x4dc0, mulmod(mload(0x4ce0), mload(0x43a0), f_q))
            mstore(0x4de0, addmod(mload(0x4c80), mload(0x4d40), f_q))
            {
                let result := mulmod(mload(0xbc0), mload(0x3e00), f_q)
                mstore(19968, result)
            }
            mstore(0x4e20, mulmod(mload(0x4e00), mload(0x42c0), f_q))
            mstore(0x4e40, mulmod(sub(f_q, mload(0x4e20)), mload(0x43c0), f_q))
            mstore(0x4e60, mulmod(mload(0x47a0), mload(0x43c0), f_q))
            mstore(0x4e80, addmod(mload(0x4de0), mload(0x4e40), f_q))
            mstore(0x4ea0, mulmod(mload(0x4e80), mload(0x4420), f_q))
            mstore(0x4ec0, mulmod(mload(0x4820), mload(0x4420), f_q))
            mstore(0x4ee0, mulmod(mload(0x48a0), mload(0x4420), f_q))
            mstore(0x4f00, mulmod(mload(0x4940), mload(0x4420), f_q))
            mstore(0x4f20, mulmod(mload(0x49e0), mload(0x4420), f_q))
            mstore(0x4f40, mulmod(mload(0x4a80), mload(0x4420), f_q))
            mstore(0x4f60, mulmod(mload(0x4b20), mload(0x4420), f_q))
            mstore(0x4f80, mulmod(mload(0x4bc0), mload(0x4420), f_q))
            mstore(0x4fa0, mulmod(mload(0x4c60), mload(0x4420), f_q))
            mstore(0x4fc0, mulmod(mload(0x4d60), mload(0x4420), f_q))
            mstore(0x4fe0, mulmod(mload(0x4d80), mload(0x4420), f_q))
            mstore(0x5000, mulmod(mload(0x4da0), mload(0x4420), f_q))
            mstore(0x5020, mulmod(mload(0x4dc0), mload(0x4420), f_q))
            mstore(0x5040, mulmod(mload(0x4e60), mload(0x4420), f_q))
            mstore(0x5060, addmod(mload(0x4780), mload(0x4ea0), f_q))
            mstore(0x5080, mulmod(1, mload(0x3c40), f_q))
            mstore(0x50a0, mulmod(1, mload(0xe40), f_q))
            mstore(0x50c0, 0x0000000000000000000000000000000000000000000000000000000000000001)
            mstore(0x50e0, 0x0000000000000000000000000000000000000000000000000000000000000002)
            mstore(0x5100, mload(0x5060))
            success := and(eq(staticcall(gas(), 0x7, 0x50c0, 0x60, 0x50c0, 0x40), 1), success)
            mstore(0x5120, mload(0x50c0))
            mstore(0x5140, mload(0x50e0))
            mstore(0x5160, mload(0x660))
            mstore(0x5180, mload(0x680))
            success := and(eq(staticcall(gas(), 0x6, 0x5120, 0x80, 0x5120, 0x40), 1), success)
            mstore(0x51a0, mload(0x840))
            mstore(0x51c0, mload(0x860))
            mstore(0x51e0, mload(0x4640))
            success := and(eq(staticcall(gas(), 0x7, 0x51a0, 0x60, 0x51a0, 0x40), 1), success)
            mstore(0x5200, mload(0x5120))
            mstore(0x5220, mload(0x5140))
            mstore(0x5240, mload(0x51a0))
            mstore(0x5260, mload(0x51c0))
            success := and(eq(staticcall(gas(), 0x6, 0x5200, 0x80, 0x5200, 0x40), 1), success)
            mstore(0x5280, mload(0x880))
            mstore(0x52a0, mload(0x8a0))
            mstore(0x52c0, mload(0x4660))
            success := and(eq(staticcall(gas(), 0x7, 0x5280, 0x60, 0x5280, 0x40), 1), success)
            mstore(0x52e0, mload(0x5200))
            mstore(0x5300, mload(0x5220))
            mstore(0x5320, mload(0x5280))
            mstore(0x5340, mload(0x52a0))
            success := and(eq(staticcall(gas(), 0x6, 0x52e0, 0x80, 0x52e0, 0x40), 1), success)
            mstore(0x5360, mload(0x700))
            mstore(0x5380, mload(0x720))
            mstore(0x53a0, mload(0x4760))
            success := and(eq(staticcall(gas(), 0x7, 0x5360, 0x60, 0x5360, 0x40), 1), success)
            mstore(0x53c0, mload(0x52e0))
            mstore(0x53e0, mload(0x5300))
            mstore(0x5400, mload(0x5360))
            mstore(0x5420, mload(0x5380))
            success := and(eq(staticcall(gas(), 0x6, 0x53c0, 0x80, 0x53c0, 0x40), 1), success)
            mstore(0x5440, mload(0x740))
            mstore(0x5460, mload(0x760))
            mstore(0x5480, mload(0x4ec0))
            success := and(eq(staticcall(gas(), 0x7, 0x5440, 0x60, 0x5440, 0x40), 1), success)
            mstore(0x54a0, mload(0x53c0))
            mstore(0x54c0, mload(0x53e0))
            mstore(0x54e0, mload(0x5440))
            mstore(0x5500, mload(0x5460))
            success := and(eq(staticcall(gas(), 0x6, 0x54a0, 0x80, 0x54a0, 0x40), 1), success)
            mstore(0x5520, 0x215365efc7b867c1204aab35fb060db538521b93b08872e3a9700c7ee4a285c2)
            mstore(0x5540, 0x26da76077e618e9351d4e53058afcb50f9ecb808ef537ffed4c95f1e964a8c58)
            mstore(0x5560, mload(0x4ee0))
            success := and(eq(staticcall(gas(), 0x7, 0x5520, 0x60, 0x5520, 0x40), 1), success)
            mstore(0x5580, mload(0x54a0))
            mstore(0x55a0, mload(0x54c0))
            mstore(0x55c0, mload(0x5520))
            mstore(0x55e0, mload(0x5540))
            success := and(eq(staticcall(gas(), 0x6, 0x5580, 0x80, 0x5580, 0x40), 1), success)
            mstore(0x5600, 0x21c6ea7d6dbcd767ffb9d9beeb4f9c2f8243bc65290f2d75a59aea4f65ba8f3d)
            mstore(0x5620, 0x24d0a0acb031c9a5687da08cdaf96650aae5c60435739bda8bbd574eb962622c)
            mstore(0x5640, mload(0x4f00))
            success := and(eq(staticcall(gas(), 0x7, 0x5600, 0x60, 0x5600, 0x40), 1), success)
            mstore(0x5660, mload(0x5580))
            mstore(0x5680, mload(0x55a0))
            mstore(0x56a0, mload(0x5600))
            mstore(0x56c0, mload(0x5620))
            success := and(eq(staticcall(gas(), 0x6, 0x5660, 0x80, 0x5660, 0x40), 1), success)
            mstore(0x56e0, 0x289feda4952fe4464c9716d071e291bbecdcd5432356042dc79b76ed38cbbb0d)
            mstore(0x5700, 0x07f3ca14a8801fa413462ad72ea448da5d7cf8c5218534cdc39bb23779b70bb9)
            mstore(0x5720, mload(0x4f20))
            success := and(eq(staticcall(gas(), 0x7, 0x56e0, 0x60, 0x56e0, 0x40), 1), success)
            mstore(0x5740, mload(0x5660))
            mstore(0x5760, mload(0x5680))
            mstore(0x5780, mload(0x56e0))
            mstore(0x57a0, mload(0x5700))
            success := and(eq(staticcall(gas(), 0x6, 0x5740, 0x80, 0x5740, 0x40), 1), success)
            mstore(0x57c0, 0x259670bd2f2f6fce3b18100f92a2e59874da3b66a9ddd61e163eb4b071e24a97)
            mstore(0x57e0, 0x097f07272f7ca89070ad9c06d9a3da1bb6e91d0e69bf7872f44cc5d332291eb5)
            mstore(0x5800, mload(0x4f40))
            success := and(eq(staticcall(gas(), 0x7, 0x57c0, 0x60, 0x57c0, 0x40), 1), success)
            mstore(0x5820, mload(0x5740))
            mstore(0x5840, mload(0x5760))
            mstore(0x5860, mload(0x57c0))
            mstore(0x5880, mload(0x57e0))
            success := and(eq(staticcall(gas(), 0x6, 0x5820, 0x80, 0x5820, 0x40), 1), success)
            mstore(0x58a0, 0x1e9efbe537998d8260c28c8e2ca8d83118f378f1e83daed033c2ae772806280a)
            mstore(0x58c0, 0x15e04128b5f6b9bb6c758886eda92c27e8414c25809bd547e4987c332c38a430)
            mstore(0x58e0, mload(0x4f60))
            success := and(eq(staticcall(gas(), 0x7, 0x58a0, 0x60, 0x58a0, 0x40), 1), success)
            mstore(0x5900, mload(0x5820))
            mstore(0x5920, mload(0x5840))
            mstore(0x5940, mload(0x58a0))
            mstore(0x5960, mload(0x58c0))
            success := and(eq(staticcall(gas(), 0x6, 0x5900, 0x80, 0x5900, 0x40), 1), success)
            mstore(0x5980, 0x2db56ede49a6f38ee215d1fa9557ac54cb085bbb6170e9a2cda8db3c996c496e)
            mstore(0x59a0, 0x017bd7af014917e84cda777f32c3b586cf6de90f0d649cbbce320ee837513cb8)
            mstore(0x59c0, mload(0x4f80))
            success := and(eq(staticcall(gas(), 0x7, 0x5980, 0x60, 0x5980, 0x40), 1), success)
            mstore(0x59e0, mload(0x5900))
            mstore(0x5a00, mload(0x5920))
            mstore(0x5a20, mload(0x5980))
            mstore(0x5a40, mload(0x59a0))
            success := and(eq(staticcall(gas(), 0x6, 0x59e0, 0x80, 0x59e0, 0x40), 1), success)
            mstore(0x5a60, 0x0f76818adad3c635f139fde306f33aba7249952bdbbf72cf477a51f9d84f3ccc)
            mstore(0x5a80, 0x23f89f9896b1cc39de92659098ea839186ff2e997ffa3413c1a7af4f31abe4ce)
            mstore(0x5aa0, mload(0x4fa0))
            success := and(eq(staticcall(gas(), 0x7, 0x5a60, 0x60, 0x5a60, 0x40), 1), success)
            mstore(0x5ac0, mload(0x59e0))
            mstore(0x5ae0, mload(0x5a00))
            mstore(0x5b00, mload(0x5a60))
            mstore(0x5b20, mload(0x5a80))
            success := and(eq(staticcall(gas(), 0x6, 0x5ac0, 0x80, 0x5ac0, 0x40), 1), success)
            mstore(0x5b40, mload(0x960))
            mstore(0x5b60, mload(0x980))
            mstore(0x5b80, mload(0x4fc0))
            success := and(eq(staticcall(gas(), 0x7, 0x5b40, 0x60, 0x5b40, 0x40), 1), success)
            mstore(0x5ba0, mload(0x5ac0))
            mstore(0x5bc0, mload(0x5ae0))
            mstore(0x5be0, mload(0x5b40))
            mstore(0x5c00, mload(0x5b60))
            success := and(eq(staticcall(gas(), 0x6, 0x5ba0, 0x80, 0x5ba0, 0x40), 1), success)
            mstore(0x5c20, mload(0x9a0))
            mstore(0x5c40, mload(0x9c0))
            mstore(0x5c60, mload(0x4fe0))
            success := and(eq(staticcall(gas(), 0x7, 0x5c20, 0x60, 0x5c20, 0x40), 1), success)
            mstore(0x5c80, mload(0x5ba0))
            mstore(0x5ca0, mload(0x5bc0))
            mstore(0x5cc0, mload(0x5c20))
            mstore(0x5ce0, mload(0x5c40))
            success := and(eq(staticcall(gas(), 0x6, 0x5c80, 0x80, 0x5c80, 0x40), 1), success)
            mstore(0x5d00, mload(0x9e0))
            mstore(0x5d20, mload(0xa00))
            mstore(0x5d40, mload(0x5000))
            success := and(eq(staticcall(gas(), 0x7, 0x5d00, 0x60, 0x5d00, 0x40), 1), success)
            mstore(0x5d60, mload(0x5c80))
            mstore(0x5d80, mload(0x5ca0))
            mstore(0x5da0, mload(0x5d00))
            mstore(0x5dc0, mload(0x5d20))
            success := and(eq(staticcall(gas(), 0x6, 0x5d60, 0x80, 0x5d60, 0x40), 1), success)
            mstore(0x5de0, mload(0xa20))
            mstore(0x5e00, mload(0xa40))
            mstore(0x5e20, mload(0x5020))
            success := and(eq(staticcall(gas(), 0x7, 0x5de0, 0x60, 0x5de0, 0x40), 1), success)
            mstore(0x5e40, mload(0x5d60))
            mstore(0x5e60, mload(0x5d80))
            mstore(0x5e80, mload(0x5de0))
            mstore(0x5ea0, mload(0x5e00))
            success := and(eq(staticcall(gas(), 0x6, 0x5e40, 0x80, 0x5e40, 0x40), 1), success)
            mstore(0x5ec0, mload(0x8c0))
            mstore(0x5ee0, mload(0x8e0))
            mstore(0x5f00, mload(0x5040))
            success := and(eq(staticcall(gas(), 0x7, 0x5ec0, 0x60, 0x5ec0, 0x40), 1), success)
            mstore(0x5f20, mload(0x5e40))
            mstore(0x5f40, mload(0x5e60))
            mstore(0x5f60, mload(0x5ec0))
            mstore(0x5f80, mload(0x5ee0))
            success := and(eq(staticcall(gas(), 0x6, 0x5f20, 0x80, 0x5f20, 0x40), 1), success)
            mstore(0x5fa0, mload(0xde0))
            mstore(0x5fc0, mload(0xe00))
            mstore(0x5fe0, sub(f_q, mload(0x5080)))
            success := and(eq(staticcall(gas(), 0x7, 0x5fa0, 0x60, 0x5fa0, 0x40), 1), success)
            mstore(0x6000, mload(0x5f20))
            mstore(0x6020, mload(0x5f40))
            mstore(0x6040, mload(0x5fa0))
            mstore(0x6060, mload(0x5fc0))
            success := and(eq(staticcall(gas(), 0x6, 0x6000, 0x80, 0x6000, 0x40), 1), success)
            mstore(0x6080, mload(0xe80))
            mstore(0x60a0, mload(0xea0))
            mstore(0x60c0, mload(0x50a0))
            success := and(eq(staticcall(gas(), 0x7, 0x6080, 0x60, 0x6080, 0x40), 1), success)
            mstore(0x60e0, mload(0x6000))
            mstore(0x6100, mload(0x6020))
            mstore(0x6120, mload(0x6080))
            mstore(0x6140, mload(0x60a0))
            success := and(eq(staticcall(gas(), 0x6, 0x60e0, 0x80, 0x60e0, 0x40), 1), success)
            mstore(0x6160, mload(0x60e0))
            mstore(0x6180, mload(0x6100))
            mstore(0x61a0, mload(0xe80))
            mstore(0x61c0, mload(0xea0))
            mstore(0x61e0, mload(0xec0))
            mstore(0x6200, mload(0xee0))
            mstore(0x6220, mload(0xf00))
            mstore(0x6240, mload(0xf20))
            mstore(0x6260, keccak256(0x6160, 256))
            mstore(25216, mod(mload(25184), f_q))
            mstore(0x62a0, mulmod(mload(0x6280), mload(0x6280), f_q))
            mstore(0x62c0, mulmod(1, mload(0x6280), f_q))
            mstore(0x62e0, mload(0x61e0))
            mstore(0x6300, mload(0x6200))
            mstore(0x6320, mload(0x62c0))
            success := and(eq(staticcall(gas(), 0x7, 0x62e0, 0x60, 0x62e0, 0x40), 1), success)
            mstore(0x6340, mload(0x6160))
            mstore(0x6360, mload(0x6180))
            mstore(0x6380, mload(0x62e0))
            mstore(0x63a0, mload(0x6300))
            success := and(eq(staticcall(gas(), 0x6, 0x6340, 0x80, 0x6340, 0x40), 1), success)
            mstore(0x63c0, mload(0x6220))
            mstore(0x63e0, mload(0x6240))
            mstore(0x6400, mload(0x62c0))
            success := and(eq(staticcall(gas(), 0x7, 0x63c0, 0x60, 0x63c0, 0x40), 1), success)
            mstore(0x6420, mload(0x61a0))
            mstore(0x6440, mload(0x61c0))
            mstore(0x6460, mload(0x63c0))
            mstore(0x6480, mload(0x63e0))
            success := and(eq(staticcall(gas(), 0x6, 0x6420, 0x80, 0x6420, 0x40), 1), success)
            mstore(0x64a0, mload(0x6340))
            mstore(0x64c0, mload(0x6360))
            mstore(0x64e0, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)
            mstore(0x6500, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed)
            mstore(0x6520, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
            mstore(0x6540, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa)
            mstore(0x6560, mload(0x6420))
            mstore(0x6580, mload(0x6440))
            mstore(0x65a0, 0x172aa93c41f16e1e04d62ac976a5d945f4be0acab990c6dc19ac4a7cf68bf77b)
            mstore(0x65c0, 0x2ae0c8c3a090f7200ff398ee9845bbae8f8c1445ae7b632212775f60a0e21600)
            mstore(0x65e0, 0x190fa476a5b352809ed41d7a0d7fe12b8f685e3c12a6d83855dba27aaf469643)
            mstore(0x6600, 0x1c0a500618907df9e4273d5181e31088deb1f05132de037cbfe73888f97f77c9)
            success := and(eq(staticcall(gas(), 0x8, 0x64a0, 0x180, 0x64a0, 0x20), 1), success)
            success := and(eq(mload(0x64a0), 1), success)

            // Revert if anything fails
            if iszero(success) { revert(0, 0) }

            // Return empty bytes on success
            return(0, 0)
        }
    }
}
