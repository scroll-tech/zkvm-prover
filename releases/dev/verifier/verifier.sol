// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

contract Halo2Verifier {
    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {
                revert(0, 0)
            }

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
            mstore(0x80, 3099200876874169560829918599785312545415625616099245974171476775798883330872)

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
            mstore(0x1200, mulmod(mload(0x11e0), mload(0x11e0), f_q))
            mstore(0x1220, mulmod(mload(0x1200), mload(0x1200), f_q))
            mstore(
                0x1240,
                addmod(
                    mload(0x1220),
                    21888242871839275222246405745257275088548364400416034343698204186575808495616,
                    f_q
                )
            )
            mstore(
                0x1260,
                mulmod(
                    mload(0x1240),
                    21888241567198334088790460357988866238279339518792980768180410072331574733841,
                    f_q
                )
            )
            mstore(
                0x1280,
                mulmod(
                    mload(0x1260),
                    12929131318670223636853686797196826072950305380535537217467769528748593133487,
                    f_q
                )
            )
            mstore(
                0x12a0,
                addmod(mload(0xa80), 8959111553169051585392718948060449015598059019880497126230434657827215362130, f_q)
            )
            mstore(
                0x12c0,
                mulmod(
                    mload(0x1260),
                    14655294445420895451632927078981340937842238432098198055057679026789553137428,
                    f_q
                )
            )
            mstore(
                0x12e0,
                addmod(mload(0xa80), 7232948426418379770613478666275934150706125968317836288640525159786255358189, f_q)
            )
            mstore(
                0x1300,
                mulmod(
                    mload(0x1260),
                    12220484078924208264862893648548198807365556694478604924193442790112568454894,
                    f_q
                )
            )
            mstore(
                0x1320,
                addmod(mload(0xa80), 9667758792915066957383512096709076281182807705937429419504761396463240040723, f_q)
            )
            mstore(
                0x1340,
                mulmod(mload(0x1260), 8734126352828345679573237859165904705806588461301144420590422589042130041188, f_q)
            )
            mstore(
                0x1360,
                addmod(mload(0xa80), 13154116519010929542673167886091370382741775939114889923107781597533678454429, f_q)
            )
            mstore(
                0x1380,
                mulmod(mload(0x1260), 7358966525675286471217089135633860168646304224547606326237275077574224349359, f_q)
            )
            mstore(
                0x13a0,
                addmod(mload(0xa80), 14529276346163988751029316609623414919902060175868428017460929109001584146258, f_q)
            )
            mstore(
                0x13c0,
                mulmod(mload(0x1260), 9741553891420464328295280489650144566903017206473301385034033384879943874347, f_q)
            )
            mstore(
                0x13e0,
                addmod(mload(0xa80), 12146688980418810893951125255607130521645347193942732958664170801695864621270, f_q)
            )
            mstore(
                0x1400,
                mulmod(
                    mload(0x1260),
                    17329448237240114492580865744088056414251735686965494637158808787419781175510,
                    f_q
                )
            )
            mstore(
                0x1420,
                addmod(mload(0xa80), 4558794634599160729665540001169218674296628713450539706539395399156027320107, f_q)
            )
            mstore(0x1440, mulmod(mload(0x1260), 1, f_q))
            mstore(
                0x1460,
                addmod(mload(0xa80), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q)
            )
            mstore(
                0x1480,
                mulmod(
                    mload(0x1260),
                    11451405578697956743456240853980216273390554734748796433026540431386972584651,
                    f_q
                )
            )
            mstore(
                0x14a0,
                addmod(mload(0xa80), 10436837293141318478790164891277058815157809665667237910671663755188835910966, f_q)
            )
            mstore(
                0x14c0,
                mulmod(mload(0x1260), 8374374965308410102411073611984011876711565317741801500439755773472076597347, f_q)
            )
            mstore(
                0x14e0,
                addmod(mload(0xa80), 13513867906530865119835332133273263211836799082674232843258448413103731898270, f_q)
            )
            mstore(
                0x1500,
                mulmod(
                    mload(0x1260),
                    21490807004895109926141140246143262403290679459142140821740925192625185504522,
                    f_q
                )
            )
            mstore(
                0x1520,
                addmod(mload(0xa80), 397435866944165296105265499114012685257684941273893521957278993950622991095, f_q)
            )
            mstore(
                0x1540,
                mulmod(
                    mload(0x1260),
                    11211301017135681023579411905410872569206244553457844956874280139879520583390,
                    f_q
                )
            )
            mstore(
                0x1560,
                addmod(mload(0xa80), 10676941854703594198666993839846402519342119846958189386823924046696287912227, f_q)
            )
            mstore(
                0x1580,
                mulmod(
                    mload(0x1260),
                    18846108080730935585192484934247867403156699586319724728525857970312957475341,
                    f_q
                )
            )
            mstore(
                0x15a0,
                addmod(mload(0xa80), 3042134791108339637053920811009407685391664814096309615172346216262851020276, f_q)
            )
            mstore(
                0x15c0,
                mulmod(mload(0x1260), 3615478808282855240548287271348143516886772452944084747768312988864436725401, f_q)
            )
            mstore(
                0x15e0,
                addmod(mload(0xa80), 18272764063556419981698118473909131571661591947471949595929891197711371770216, f_q)
            )
            mstore(
                0x1600,
                mulmod(
                    mload(0x1260),
                    21451937155080765789602997556105366785934335730087568134349216848800867145453,
                    f_q
                )
            )
            mstore(
                0x1620,
                addmod(mload(0xa80), 436305716758509432643408189151908302614028670328466209348987337774941350164, f_q)
            )
            mstore(
                0x1640,
                mulmod(mload(0x1260), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q)
            )
            mstore(
                0x1660,
                addmod(mload(0xa80), 20461838439117790833741043996939313553025008529160428886800406442142042007110, f_q)
            )
            mstore(
                0x1680,
                mulmod(
                    mload(0x1260),
                    13982290267294411190096162596630216412723378687553046594730793425118513274800,
                    f_q
                )
            )
            mstore(
                0x16a0,
                addmod(mload(0xa80), 7905952604544864032150243148627058675824985712862987748967410761457295220817, f_q)
            )
            mstore(
                0x16c0,
                mulmod(mload(0x1260), 216092043779272773661818549620449970334216366264741118684015851799902419467, f_q)
            )
            mstore(
                0x16e0,
                addmod(mload(0xa80), 21672150828060002448584587195636825118214148034151293225014188334775906076150, f_q)
            )
            mstore(
                0x1700,
                mulmod(mload(0x1260), 9537783784440837896026284659246718978615447564543116209283382057778110278482, f_q)
            )
            mstore(
                0x1720,
                addmod(mload(0xa80), 12350459087398437326220121086010556109932916835872918134414822128797698217135, f_q)
            )
            mstore(
                0x1740,
                mulmod(
                    mload(0x1260),
                    12619617507853212586156872920672483948819476989779550311307282715684870266992,
                    f_q
                )
            )
            mstore(
                0x1760,
                addmod(mload(0xa80), 9268625363986062636089532824584791139728887410636484032390921470890938228625, f_q)
            )
            mstore(
                0x1780,
                mulmod(mload(0x1260), 3947443723575973965644279767310964219908423994086470065513888332899718123222, f_q)
            )
            mstore(
                0x17a0,
                addmod(mload(0xa80), 17940799148263301256602125977946310868639940406329564278184315853676090372395, f_q)
            )
            mstore(
                0x17c0,
                mulmod(
                    mload(0x1260),
                    18610195890048912503953886742825279624920778288956610528523679659246523534888,
                    f_q
                )
            )
            mstore(
                0x17e0,
                addmod(mload(0xa80), 3278046981790362718292519002431995463627586111459423815174524527329284960729, f_q)
            )
            mstore(
                0x1800,
                mulmod(mload(0x1260), 1539082509056298927655194235755440186888826897239928178265486731666142403222, f_q)
            )
            mstore(
                0x1820,
                addmod(mload(0xa80), 20349160362782976294591211509501834901659537503176106165432717454909666092395, f_q)
            )
            mstore(
                0x1840,
                mulmod(
                    mload(0x1260),
                    19032961837237948602743626455740240236231119053033140765040043513661803148152,
                    f_q
                )
            )
            mstore(
                0x1860,
                addmod(mload(0xa80), 2855281034601326619502779289517034852317245347382893578658160672914005347465, f_q)
            )
            mstore(
                0x1880,
                mulmod(mload(0x1260), 4317410353320599552056040796202302907960891408523818766419977508859423800635, f_q)
            )
            mstore(
                0x18a0,
                addmod(mload(0xa80), 17570832518518675670190364949054972180587472991892215577278226677716384694982, f_q)
            )
            mstore(
                0x18c0,
                mulmod(
                    mload(0x1260),
                    14875928112196239563830800280253496262679717528621719058794366823499719730250,
                    f_q
                )
            )
            mstore(
                0x18e0,
                addmod(mload(0xa80), 7012314759643035658415605465003778825868646871794315284903837363076088765367, f_q)
            )
            mstore(
                0x1900,
                mulmod(mload(0x1260), 2366023502186770334390939928726871658997402416352868340984630739442624219298, f_q)
            )
            mstore(
                0x1920,
                addmod(mload(0xa80), 19522219369652504887855465816530403429550961984063166002713573447133184276319, f_q)
            )
            mstore(
                0x1940,
                mulmod(mload(0x1260), 915149353520972163646494413843788069594022902357002628455555785223409501882, f_q)
            )
            mstore(
                0x1960,
                addmod(mload(0xa80), 20973093518318303058599911331413487018954341498059031715242648401352398993735, f_q)
            )
            mstore(
                0x1980,
                mulmod(
                    mload(0x1260),
                    14391499717548074167711220639833994904150450341569029103202493919171555826079,
                    f_q
                )
            )
            mstore(
                0x19a0,
                addmod(mload(0xa80), 7496743154291201054535185105423280184397914058847005240495710267404252669538, f_q)
            )
            mstore(
                0x19c0,
                mulmod(mload(0x1260), 5522161504810533295870699551020523636289972223872138525048055197429246400245, f_q)
            )
            mstore(
                0x19e0,
                addmod(mload(0xa80), 16366081367028741926375706194236751452258392176543895818650148989146562095372, f_q)
            )
            mstore(
                0x1a00,
                mulmod(
                    mload(0x1260),
                    10119780362642123194334092174270235809557798114544683654677907882314807212354,
                    f_q
                )
            )
            mstore(
                0x1a20,
                addmod(mload(0xa80), 11768462509197152027912313570987039278990566285871350689020296304261001283263, f_q)
            )
            mstore(
                0x1a40,
                mulmod(mload(0x1260), 3766081621734395783232337525162072736827576297943013392955872170138036189193, f_q)
            )
            mstore(
                0x1a60,
                addmod(mload(0xa80), 18122161250104879439014068220095202351720788102473020950742332016437772306424, f_q)
            )
            mstore(
                0x1a80,
                mulmod(mload(0x1260), 2080322550956715654503104356805349981348621877591103674778333538652571537127, f_q)
            )
            mstore(
                0x1aa0,
                addmod(mload(0xa80), 19807920320882559567743301388451925107199742522824930668919870647923236958490, f_q)
            )
            mstore(
                0x1ac0,
                mulmod(mload(0x1260), 9100833993744738801214480881117348002768153232283708533639316963648253510584, f_q)
            )
            mstore(
                0x1ae0,
                addmod(mload(0xa80), 12787408878094536421031924864139927085780211168132325810058887222927554985033, f_q)
            )
            mstore(
                0x1b00,
                mulmod(
                    mload(0x1260),
                    11145214675344139457514777444556774698911688619991656085001542609383151586084,
                    f_q
                )
            )
            mstore(
                0x1b20,
                addmod(mload(0xa80), 10743028196495135764731628300700500389636675780424378258696661577192656909533, f_q)
            )
            mstore(
                0x1b40,
                mulmod(mload(0x1260), 4245441013247250116003069945606352967193023389718465410501109428393342802981, f_q)
            )
            mstore(
                0x1b60,
                addmod(mload(0xa80), 17642801858592025106243335799650922121355341010697568933197094758182465692636, f_q)
            )
            mstore(
                0x1b80,
                mulmod(
                    mload(0x1260),
                    19228510170961893342195489288913594506775385223367826565223897736323409650249,
                    f_q
                )
            )
            mstore(
                0x1ba0,
                addmod(mload(0xa80), 2659732700877381880050916456343680581772979177048207778474306450252398845368, f_q)
            )
            mstore(
                0x1bc0,
                mulmod(mload(0x1260), 6132660129994545119218258312491950835441607143741804980633129304664017206141, f_q)
            )
            mstore(
                0x1be0,
                addmod(mload(0xa80), 15755582741844730103028147432765324253106757256674229363065074881911791289476, f_q)
            )
            mstore(
                0x1c00,
                mulmod(
                    mload(0x1260),
                    10094752117139066216691253588991632982053223883646966177987813353508871280747,
                    f_q
                )
            )
            mstore(
                0x1c20,
                addmod(mload(0xa80), 11793490754700209005555152156265642106495140516769068165710390833066937214870, f_q)
            )
            mstore(
                0x1c40,
                mulmod(mload(0x1260), 5854133144571823792863860130267644613802765696134002830362054821530146160770, f_q)
            )
            mstore(
                0x1c60,
                addmod(mload(0xa80), 16034109727267451429382545614989630474745598704282031513336149365045662334847, f_q)
            )
            mstore(
                0x1c80,
                mulmod(
                    mload(0x1260),
                    21346203717540287263608402129024479709126363130664317843105498655869866203005,
                    f_q
                )
            )
            mstore(
                0x1ca0,
                addmod(mload(0xa80), 542039154298987958638003616232795379422001269751716500592705530705942292612, f_q)
            )
            mstore(
                0x1cc0,
                mulmod(mload(0x1260), 515148244606945972463850631189471072103916690263705052318085725998468254533, f_q)
            )
            mstore(
                0x1ce0,
                addmod(mload(0xa80), 21373094627232329249782555114067804016444447710152329291380118460577340241084, f_q)
            )
            mstore(
                0x1d00,
                mulmod(
                    mload(0x1260),
                    13788243025932779125104144225768424453664118806559109014238064020826883170336,
                    f_q
                )
            )
            mstore(
                0x1d20,
                addmod(mload(0xa80), 8099999845906496097142261519488850634884245593856925329460140165748925325281, f_q)
            )
            mstore(
                0x1d40,
                mulmod(mload(0x1260), 5980488956150442207659150513163747165544364597008566989111579977672498964212, f_q)
            )
            mstore(
                0x1d60,
                addmod(mload(0xa80), 15907753915688833014587255232093527923003999803407467354586624208903309531405, f_q)
            )
            mstore(
                0x1d80,
                mulmod(mload(0x1260), 8561696234966975469289029207282849740510759316794581475824569334969644143582, f_q)
            )
            mstore(
                0x1da0,
                addmod(mload(0xa80), 13326546636872299752957376537974425348037605083621452867873634851606164352035, f_q)
            )
            mstore(
                0x1dc0,
                mulmod(mload(0x1260), 5223738580615264174925218065001555728265216895679471490312087802465486318994, f_q)
            )
            mstore(
                0x1de0,
                addmod(mload(0xa80), 16664504291224011047321187680255719360283147504736562853386116384110322176623, f_q)
            )
            mstore(
                0x1e00,
                mulmod(mload(0x1260), 3302268277365219249160464068848832456250192077357408622723420445620736662125, f_q)
            )
            mstore(
                0x1e20,
                addmod(mload(0xa80), 18585974594474055973085941676408442632298172323058625720974783740955071833492, f_q)
            )
            mstore(
                0x1e40,
                mulmod(
                    mload(0x1260),
                    14557038802599140430182096396825290815503940951075961210638273254419942783582,
                    f_q
                )
            )
            mstore(
                0x1e60,
                addmod(mload(0xa80), 7331204069240134792064309348431984273044423449340073133059930932155865712035, f_q)
            )
            mstore(
                0x1e80,
                mulmod(
                    mload(0x1260),
                    21631349642691366221117117325940229443266870213711402446456178962469345982255,
                    f_q
                )
            )
            mstore(
                0x1ea0,
                addmod(mload(0xa80), 256893229147909001129288419317045645281494186704631897242025224106462513362, f_q)
            )
            mstore(
                0x1ec0,
                mulmod(
                    mload(0x1260),
                    16976236069879939850923145256911338076234942200101755618884183331004076579046,
                    f_q
                )
            )
            mstore(
                0x1ee0,
                addmod(mload(0xa80), 4912006801959335371323260488345937012313422200314278724814020855571731916571, f_q)
            )
            mstore(
                0x1f00,
                mulmod(
                    mload(0x1260),
                    18106030913818996184930975996483865250387924434749113154514488995517615180373,
                    f_q
                )
            )
            mstore(
                0x1f20,
                addmod(mload(0xa80), 3782211958020279037315429748773409838160439965666921189183715191058193315244, f_q)
            )
            mstore(
                0x1f40,
                mulmod(
                    mload(0x1260),
                    13553911191894110065493137367144919847521088405945523452288398666974237857208,
                    f_q
                )
            )
            mstore(
                0x1f60,
                addmod(mload(0xa80), 8334331679945165156753268378112355241027275994470510891409805519601570638409, f_q)
            )
            mstore(
                0x1f80,
                mulmod(
                    mload(0x1260),
                    15126807493918544618788554261654793824894621953586710625413511093368555507114,
                    f_q
                )
            )
            mstore(
                0x1fa0,
                addmod(mload(0xa80), 6761435377920730603457851483602481263653742446829323718284693093207252988503, f_q)
            )
            {
                let prod := mload(0x12a0)

                prod := mulmod(mload(0x12e0), prod, f_q)
                mstore(0x1fc0, prod)

                prod := mulmod(mload(0x1320), prod, f_q)
                mstore(0x1fe0, prod)

                prod := mulmod(mload(0x1360), prod, f_q)
                mstore(0x2000, prod)

                prod := mulmod(mload(0x13a0), prod, f_q)
                mstore(0x2020, prod)

                prod := mulmod(mload(0x13e0), prod, f_q)
                mstore(0x2040, prod)

                prod := mulmod(mload(0x1420), prod, f_q)
                mstore(0x2060, prod)

                prod := mulmod(mload(0x1460), prod, f_q)
                mstore(0x2080, prod)

                prod := mulmod(mload(0x14a0), prod, f_q)
                mstore(0x20a0, prod)

                prod := mulmod(mload(0x14e0), prod, f_q)
                mstore(0x20c0, prod)

                prod := mulmod(mload(0x1520), prod, f_q)
                mstore(0x20e0, prod)

                prod := mulmod(mload(0x1560), prod, f_q)
                mstore(0x2100, prod)

                prod := mulmod(mload(0x15a0), prod, f_q)
                mstore(0x2120, prod)

                prod := mulmod(mload(0x15e0), prod, f_q)
                mstore(0x2140, prod)

                prod := mulmod(mload(0x1620), prod, f_q)
                mstore(0x2160, prod)

                prod := mulmod(mload(0x1660), prod, f_q)
                mstore(0x2180, prod)

                prod := mulmod(mload(0x16a0), prod, f_q)
                mstore(0x21a0, prod)

                prod := mulmod(mload(0x16e0), prod, f_q)
                mstore(0x21c0, prod)

                prod := mulmod(mload(0x1720), prod, f_q)
                mstore(0x21e0, prod)

                prod := mulmod(mload(0x1760), prod, f_q)
                mstore(0x2200, prod)

                prod := mulmod(mload(0x17a0), prod, f_q)
                mstore(0x2220, prod)

                prod := mulmod(mload(0x17e0), prod, f_q)
                mstore(0x2240, prod)

                prod := mulmod(mload(0x1820), prod, f_q)
                mstore(0x2260, prod)

                prod := mulmod(mload(0x1860), prod, f_q)
                mstore(0x2280, prod)

                prod := mulmod(mload(0x18a0), prod, f_q)
                mstore(0x22a0, prod)

                prod := mulmod(mload(0x18e0), prod, f_q)
                mstore(0x22c0, prod)

                prod := mulmod(mload(0x1920), prod, f_q)
                mstore(0x22e0, prod)

                prod := mulmod(mload(0x1960), prod, f_q)
                mstore(0x2300, prod)

                prod := mulmod(mload(0x19a0), prod, f_q)
                mstore(0x2320, prod)

                prod := mulmod(mload(0x19e0), prod, f_q)
                mstore(0x2340, prod)

                prod := mulmod(mload(0x1a20), prod, f_q)
                mstore(0x2360, prod)

                prod := mulmod(mload(0x1a60), prod, f_q)
                mstore(0x2380, prod)

                prod := mulmod(mload(0x1aa0), prod, f_q)
                mstore(0x23a0, prod)

                prod := mulmod(mload(0x1ae0), prod, f_q)
                mstore(0x23c0, prod)

                prod := mulmod(mload(0x1b20), prod, f_q)
                mstore(0x23e0, prod)

                prod := mulmod(mload(0x1b60), prod, f_q)
                mstore(0x2400, prod)

                prod := mulmod(mload(0x1ba0), prod, f_q)
                mstore(0x2420, prod)

                prod := mulmod(mload(0x1be0), prod, f_q)
                mstore(0x2440, prod)

                prod := mulmod(mload(0x1c20), prod, f_q)
                mstore(0x2460, prod)

                prod := mulmod(mload(0x1c60), prod, f_q)
                mstore(0x2480, prod)

                prod := mulmod(mload(0x1ca0), prod, f_q)
                mstore(0x24a0, prod)

                prod := mulmod(mload(0x1ce0), prod, f_q)
                mstore(0x24c0, prod)

                prod := mulmod(mload(0x1d20), prod, f_q)
                mstore(0x24e0, prod)

                prod := mulmod(mload(0x1d60), prod, f_q)
                mstore(0x2500, prod)

                prod := mulmod(mload(0x1da0), prod, f_q)
                mstore(0x2520, prod)

                prod := mulmod(mload(0x1de0), prod, f_q)
                mstore(0x2540, prod)

                prod := mulmod(mload(0x1e20), prod, f_q)
                mstore(0x2560, prod)

                prod := mulmod(mload(0x1e60), prod, f_q)
                mstore(0x2580, prod)

                prod := mulmod(mload(0x1ea0), prod, f_q)
                mstore(0x25a0, prod)

                prod := mulmod(mload(0x1ee0), prod, f_q)
                mstore(0x25c0, prod)

                prod := mulmod(mload(0x1f20), prod, f_q)
                mstore(0x25e0, prod)

                prod := mulmod(mload(0x1f60), prod, f_q)
                mstore(0x2600, prod)

                prod := mulmod(mload(0x1fa0), prod, f_q)
                mstore(0x2620, prod)

                prod := mulmod(mload(0x1240), prod, f_q)
                mstore(0x2640, prod)
            }
            mstore(0x2680, 32)
            mstore(0x26a0, 32)
            mstore(0x26c0, 32)
            mstore(0x26e0, mload(0x2640))
            mstore(0x2700, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
            mstore(0x2720, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
            success := and(eq(staticcall(gas(), 0x5, 0x2680, 0xc0, 0x2660, 0x20), 1), success)
            {
                let inv := mload(0x2660)
                let v

                v := mload(0x1240)
                mstore(4672, mulmod(mload(0x2620), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1fa0)
                mstore(8096, mulmod(mload(0x2600), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1f60)
                mstore(8032, mulmod(mload(0x25e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1f20)
                mstore(7968, mulmod(mload(0x25c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ee0)
                mstore(7904, mulmod(mload(0x25a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ea0)
                mstore(7840, mulmod(mload(0x2580), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1e60)
                mstore(7776, mulmod(mload(0x2560), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1e20)
                mstore(7712, mulmod(mload(0x2540), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1de0)
                mstore(7648, mulmod(mload(0x2520), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1da0)
                mstore(7584, mulmod(mload(0x2500), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1d60)
                mstore(7520, mulmod(mload(0x24e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1d20)
                mstore(7456, mulmod(mload(0x24c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ce0)
                mstore(7392, mulmod(mload(0x24a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ca0)
                mstore(7328, mulmod(mload(0x2480), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1c60)
                mstore(7264, mulmod(mload(0x2460), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1c20)
                mstore(7200, mulmod(mload(0x2440), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1be0)
                mstore(7136, mulmod(mload(0x2420), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ba0)
                mstore(7072, mulmod(mload(0x2400), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1b60)
                mstore(7008, mulmod(mload(0x23e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1b20)
                mstore(6944, mulmod(mload(0x23c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1ae0)
                mstore(6880, mulmod(mload(0x23a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1aa0)
                mstore(6816, mulmod(mload(0x2380), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1a60)
                mstore(6752, mulmod(mload(0x2360), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1a20)
                mstore(6688, mulmod(mload(0x2340), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x19e0)
                mstore(6624, mulmod(mload(0x2320), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x19a0)
                mstore(6560, mulmod(mload(0x2300), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1960)
                mstore(6496, mulmod(mload(0x22e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1920)
                mstore(6432, mulmod(mload(0x22c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x18e0)
                mstore(6368, mulmod(mload(0x22a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x18a0)
                mstore(6304, mulmod(mload(0x2280), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1860)
                mstore(6240, mulmod(mload(0x2260), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1820)
                mstore(6176, mulmod(mload(0x2240), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x17e0)
                mstore(6112, mulmod(mload(0x2220), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x17a0)
                mstore(6048, mulmod(mload(0x2200), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1760)
                mstore(5984, mulmod(mload(0x21e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1720)
                mstore(5920, mulmod(mload(0x21c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x16e0)
                mstore(5856, mulmod(mload(0x21a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x16a0)
                mstore(5792, mulmod(mload(0x2180), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1660)
                mstore(5728, mulmod(mload(0x2160), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1620)
                mstore(5664, mulmod(mload(0x2140), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x15e0)
                mstore(5600, mulmod(mload(0x2120), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x15a0)
                mstore(5536, mulmod(mload(0x2100), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1560)
                mstore(5472, mulmod(mload(0x20e0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1520)
                mstore(5408, mulmod(mload(0x20c0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x14e0)
                mstore(5344, mulmod(mload(0x20a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x14a0)
                mstore(5280, mulmod(mload(0x2080), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1460)
                mstore(5216, mulmod(mload(0x2060), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1420)
                mstore(5152, mulmod(mload(0x2040), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x13e0)
                mstore(5088, mulmod(mload(0x2020), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x13a0)
                mstore(5024, mulmod(mload(0x2000), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1360)
                mstore(4960, mulmod(mload(0x1fe0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x1320)
                mstore(4896, mulmod(mload(0x1fc0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x12e0)
                mstore(4832, mulmod(mload(0x12a0), inv, f_q))
                inv := mulmod(v, inv, f_q)
                mstore(0x12a0, inv)
            }
            mstore(0x2740, mulmod(mload(0x1280), mload(0x12a0), f_q))
            mstore(0x2760, mulmod(mload(0x12c0), mload(0x12e0), f_q))
            mstore(0x2780, mulmod(mload(0x1300), mload(0x1320), f_q))
            mstore(0x27a0, mulmod(mload(0x1340), mload(0x1360), f_q))
            mstore(0x27c0, mulmod(mload(0x1380), mload(0x13a0), f_q))
            mstore(0x27e0, mulmod(mload(0x13c0), mload(0x13e0), f_q))
            mstore(0x2800, mulmod(mload(0x1400), mload(0x1420), f_q))
            mstore(0x2820, mulmod(mload(0x1440), mload(0x1460), f_q))
            mstore(0x2840, mulmod(mload(0x1480), mload(0x14a0), f_q))
            mstore(0x2860, mulmod(mload(0x14c0), mload(0x14e0), f_q))
            mstore(0x2880, mulmod(mload(0x1500), mload(0x1520), f_q))
            mstore(0x28a0, mulmod(mload(0x1540), mload(0x1560), f_q))
            mstore(0x28c0, mulmod(mload(0x1580), mload(0x15a0), f_q))
            mstore(0x28e0, mulmod(mload(0x15c0), mload(0x15e0), f_q))
            mstore(0x2900, mulmod(mload(0x1600), mload(0x1620), f_q))
            mstore(0x2920, mulmod(mload(0x1640), mload(0x1660), f_q))
            mstore(0x2940, mulmod(mload(0x1680), mload(0x16a0), f_q))
            mstore(0x2960, mulmod(mload(0x16c0), mload(0x16e0), f_q))
            mstore(0x2980, mulmod(mload(0x1700), mload(0x1720), f_q))
            mstore(0x29a0, mulmod(mload(0x1740), mload(0x1760), f_q))
            mstore(0x29c0, mulmod(mload(0x1780), mload(0x17a0), f_q))
            mstore(0x29e0, mulmod(mload(0x17c0), mload(0x17e0), f_q))
            mstore(0x2a00, mulmod(mload(0x1800), mload(0x1820), f_q))
            mstore(0x2a20, mulmod(mload(0x1840), mload(0x1860), f_q))
            mstore(0x2a40, mulmod(mload(0x1880), mload(0x18a0), f_q))
            mstore(0x2a60, mulmod(mload(0x18c0), mload(0x18e0), f_q))
            mstore(0x2a80, mulmod(mload(0x1900), mload(0x1920), f_q))
            mstore(0x2aa0, mulmod(mload(0x1940), mload(0x1960), f_q))
            mstore(0x2ac0, mulmod(mload(0x1980), mload(0x19a0), f_q))
            mstore(0x2ae0, mulmod(mload(0x19c0), mload(0x19e0), f_q))
            mstore(0x2b00, mulmod(mload(0x1a00), mload(0x1a20), f_q))
            mstore(0x2b20, mulmod(mload(0x1a40), mload(0x1a60), f_q))
            mstore(0x2b40, mulmod(mload(0x1a80), mload(0x1aa0), f_q))
            mstore(0x2b60, mulmod(mload(0x1ac0), mload(0x1ae0), f_q))
            mstore(0x2b80, mulmod(mload(0x1b00), mload(0x1b20), f_q))
            mstore(0x2ba0, mulmod(mload(0x1b40), mload(0x1b60), f_q))
            mstore(0x2bc0, mulmod(mload(0x1b80), mload(0x1ba0), f_q))
            mstore(0x2be0, mulmod(mload(0x1bc0), mload(0x1be0), f_q))
            mstore(0x2c00, mulmod(mload(0x1c00), mload(0x1c20), f_q))
            mstore(0x2c20, mulmod(mload(0x1c40), mload(0x1c60), f_q))
            mstore(0x2c40, mulmod(mload(0x1c80), mload(0x1ca0), f_q))
            mstore(0x2c60, mulmod(mload(0x1cc0), mload(0x1ce0), f_q))
            mstore(0x2c80, mulmod(mload(0x1d00), mload(0x1d20), f_q))
            mstore(0x2ca0, mulmod(mload(0x1d40), mload(0x1d60), f_q))
            mstore(0x2cc0, mulmod(mload(0x1d80), mload(0x1da0), f_q))
            mstore(0x2ce0, mulmod(mload(0x1dc0), mload(0x1de0), f_q))
            mstore(0x2d00, mulmod(mload(0x1e00), mload(0x1e20), f_q))
            mstore(0x2d20, mulmod(mload(0x1e40), mload(0x1e60), f_q))
            mstore(0x2d40, mulmod(mload(0x1e80), mload(0x1ea0), f_q))
            mstore(0x2d60, mulmod(mload(0x1ec0), mload(0x1ee0), f_q))
            mstore(0x2d80, mulmod(mload(0x1f00), mload(0x1f20), f_q))
            mstore(0x2da0, mulmod(mload(0x1f40), mload(0x1f60), f_q))
            mstore(0x2dc0, mulmod(mload(0x1f80), mload(0x1fa0), f_q))
            {
                let result := mulmod(mload(0x2820), mload(0xa0), f_q)
                result := addmod(mulmod(mload(0x2840), mload(0xc0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2860), mload(0xe0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2880), mload(0x100), f_q), result, f_q)
                result := addmod(mulmod(mload(0x28a0), mload(0x120), f_q), result, f_q)
                result := addmod(mulmod(mload(0x28c0), mload(0x140), f_q), result, f_q)
                result := addmod(mulmod(mload(0x28e0), mload(0x160), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2900), mload(0x180), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2920), mload(0x1a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2940), mload(0x1c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2960), mload(0x1e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2980), mload(0x200), f_q), result, f_q)
                result := addmod(mulmod(mload(0x29a0), mload(0x220), f_q), result, f_q)
                result := addmod(mulmod(mload(0x29c0), mload(0x240), f_q), result, f_q)
                result := addmod(mulmod(mload(0x29e0), mload(0x260), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a00), mload(0x280), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a20), mload(0x2a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a40), mload(0x2c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a60), mload(0x2e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2a80), mload(0x300), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2aa0), mload(0x320), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ac0), mload(0x340), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ae0), mload(0x360), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b00), mload(0x380), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b20), mload(0x3a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b40), mload(0x3c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b60), mload(0x3e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2b80), mload(0x400), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ba0), mload(0x420), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2bc0), mload(0x440), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2be0), mload(0x460), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c00), mload(0x480), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c20), mload(0x4a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c40), mload(0x4c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c60), mload(0x4e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2c80), mload(0x500), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ca0), mload(0x520), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2cc0), mload(0x540), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2ce0), mload(0x560), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d00), mload(0x580), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d20), mload(0x5a0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d40), mload(0x5c0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d60), mload(0x5e0), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2d80), mload(0x600), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2da0), mload(0x620), f_q), result, f_q)
                result := addmod(mulmod(mload(0x2dc0), mload(0x640), f_q), result, f_q)
                mstore(11744, result)
            }
            mstore(0x2e00, mulmod(mload(0xb00), mload(0xae0), f_q))
            mstore(0x2e20, addmod(mload(0xac0), mload(0x2e00), f_q))
            mstore(0x2e40, addmod(mload(0x2e20), sub(f_q, mload(0xb20)), f_q))
            mstore(0x2e60, mulmod(mload(0x2e40), mload(0xb80), f_q))
            mstore(0x2e80, mulmod(mload(0x920), mload(0x2e60), f_q))
            mstore(0x2ea0, addmod(1, sub(f_q, mload(0xc40)), f_q))
            mstore(0x2ec0, mulmod(mload(0x2ea0), mload(0x2820), f_q))
            mstore(0x2ee0, addmod(mload(0x2e80), mload(0x2ec0), f_q))
            mstore(0x2f00, mulmod(mload(0x920), mload(0x2ee0), f_q))
            mstore(0x2f20, mulmod(mload(0xc40), mload(0xc40), f_q))
            mstore(0x2f40, addmod(mload(0x2f20), sub(f_q, mload(0xc40)), f_q))
            mstore(0x2f60, mulmod(mload(0x2f40), mload(0x2740), f_q))
            mstore(0x2f80, addmod(mload(0x2f00), mload(0x2f60), f_q))
            mstore(0x2fa0, mulmod(mload(0x920), mload(0x2f80), f_q))
            mstore(0x2fc0, addmod(1, sub(f_q, mload(0x2740)), f_q))
            mstore(0x2fe0, addmod(mload(0x2760), mload(0x2780), f_q))
            mstore(0x3000, addmod(mload(0x2fe0), mload(0x27a0), f_q))
            mstore(0x3020, addmod(mload(0x3000), mload(0x27c0), f_q))
            mstore(0x3040, addmod(mload(0x3020), mload(0x27e0), f_q))
            mstore(0x3060, addmod(mload(0x3040), mload(0x2800), f_q))
            mstore(0x3080, addmod(mload(0x2fc0), sub(f_q, mload(0x3060)), f_q))
            mstore(0x30a0, mulmod(mload(0xbe0), mload(0x7a0), f_q))
            mstore(0x30c0, addmod(mload(0xb40), mload(0x30a0), f_q))
            mstore(0x30e0, addmod(mload(0x30c0), mload(0x800), f_q))
            mstore(0x3100, mulmod(mload(0xc00), mload(0x7a0), f_q))
            mstore(0x3120, addmod(mload(0xac0), mload(0x3100), f_q))
            mstore(0x3140, addmod(mload(0x3120), mload(0x800), f_q))
            mstore(0x3160, mulmod(mload(0x3140), mload(0x30e0), f_q))
            mstore(0x3180, mulmod(mload(0xc20), mload(0x7a0), f_q))
            mstore(0x31a0, addmod(mload(0x2de0), mload(0x3180), f_q))
            mstore(0x31c0, addmod(mload(0x31a0), mload(0x800), f_q))
            mstore(0x31e0, mulmod(mload(0x31c0), mload(0x3160), f_q))
            mstore(0x3200, mulmod(mload(0x31e0), mload(0xc60), f_q))
            mstore(0x3220, mulmod(1, mload(0x7a0), f_q))
            mstore(0x3240, mulmod(mload(0xa80), mload(0x3220), f_q))
            mstore(0x3260, addmod(mload(0xb40), mload(0x3240), f_q))
            mstore(0x3280, addmod(mload(0x3260), mload(0x800), f_q))
            mstore(
                0x32a0,
                mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, mload(0x7a0), f_q)
            )
            mstore(0x32c0, mulmod(mload(0xa80), mload(0x32a0), f_q))
            mstore(0x32e0, addmod(mload(0xac0), mload(0x32c0), f_q))
            mstore(0x3300, addmod(mload(0x32e0), mload(0x800), f_q))
            mstore(0x3320, mulmod(mload(0x3300), mload(0x3280), f_q))
            mstore(
                0x3340,
                mulmod(8910878055287538404433155982483128285667088683464058436815641868457422632747, mload(0x7a0), f_q)
            )
            mstore(0x3360, mulmod(mload(0xa80), mload(0x3340), f_q))
            mstore(0x3380, addmod(mload(0x2de0), mload(0x3360), f_q))
            mstore(0x33a0, addmod(mload(0x3380), mload(0x800), f_q))
            mstore(0x33c0, mulmod(mload(0x33a0), mload(0x3320), f_q))
            mstore(0x33e0, mulmod(mload(0x33c0), mload(0xc40), f_q))
            mstore(0x3400, addmod(mload(0x3200), sub(f_q, mload(0x33e0)), f_q))
            mstore(0x3420, mulmod(mload(0x3400), mload(0x3080), f_q))
            mstore(0x3440, addmod(mload(0x2fa0), mload(0x3420), f_q))
            mstore(0x3460, mulmod(mload(0x920), mload(0x3440), f_q))
            mstore(0x3480, addmod(1, sub(f_q, mload(0xc80)), f_q))
            mstore(0x34a0, mulmod(mload(0x3480), mload(0x2820), f_q))
            mstore(0x34c0, addmod(mload(0x3460), mload(0x34a0), f_q))
            mstore(0x34e0, mulmod(mload(0x920), mload(0x34c0), f_q))
            mstore(0x3500, mulmod(mload(0xc80), mload(0xc80), f_q))
            mstore(0x3520, addmod(mload(0x3500), sub(f_q, mload(0xc80)), f_q))
            mstore(0x3540, mulmod(mload(0x3520), mload(0x2740), f_q))
            mstore(0x3560, addmod(mload(0x34e0), mload(0x3540), f_q))
            mstore(0x3580, mulmod(mload(0x920), mload(0x3560), f_q))
            mstore(0x35a0, addmod(mload(0xcc0), mload(0x7a0), f_q))
            mstore(0x35c0, mulmod(mload(0x35a0), mload(0xca0), f_q))
            mstore(0x35e0, addmod(mload(0xd00), mload(0x800), f_q))
            mstore(0x3600, mulmod(mload(0x35e0), mload(0x35c0), f_q))
            mstore(0x3620, mulmod(mload(0xac0), mload(0xba0), f_q))
            mstore(0x3640, addmod(mload(0x3620), mload(0x7a0), f_q))
            mstore(0x3660, mulmod(mload(0x3640), mload(0xc80), f_q))
            mstore(0x3680, addmod(mload(0xb60), mload(0x800), f_q))
            mstore(0x36a0, mulmod(mload(0x3680), mload(0x3660), f_q))
            mstore(0x36c0, addmod(mload(0x3600), sub(f_q, mload(0x36a0)), f_q))
            mstore(0x36e0, mulmod(mload(0x36c0), mload(0x3080), f_q))
            mstore(0x3700, addmod(mload(0x3580), mload(0x36e0), f_q))
            mstore(0x3720, mulmod(mload(0x920), mload(0x3700), f_q))
            mstore(0x3740, addmod(mload(0xcc0), sub(f_q, mload(0xd00)), f_q))
            mstore(0x3760, mulmod(mload(0x3740), mload(0x2820), f_q))
            mstore(0x3780, addmod(mload(0x3720), mload(0x3760), f_q))
            mstore(0x37a0, mulmod(mload(0x920), mload(0x3780), f_q))
            mstore(0x37c0, mulmod(mload(0x3740), mload(0x3080), f_q))
            mstore(0x37e0, addmod(mload(0xcc0), sub(f_q, mload(0xce0)), f_q))
            mstore(0x3800, mulmod(mload(0x37e0), mload(0x37c0), f_q))
            mstore(0x3820, addmod(mload(0x37a0), mload(0x3800), f_q))
            mstore(0x3840, mulmod(mload(0x1220), mload(0x1220), f_q))
            mstore(0x3860, mulmod(mload(0x3840), mload(0x1220), f_q))
            mstore(0x3880, mulmod(mload(0x3860), mload(0x1220), f_q))
            mstore(0x38a0, mulmod(1, mload(0x1220), f_q))
            mstore(0x38c0, mulmod(1, mload(0x3840), f_q))
            mstore(0x38e0, mulmod(1, mload(0x3860), f_q))
            mstore(0x3900, mulmod(mload(0x3820), mload(0x1240), f_q))
            mstore(0x3920, mulmod(mload(0xf40), mload(0xa80), f_q))
            mstore(0x3940, mulmod(mload(0x3920), mload(0xa80), f_q))
            mstore(
                0x3960,
                mulmod(mload(0xa80), 17329448237240114492580865744088056414251735686965494637158808787419781175510, f_q)
            )
            mstore(0x3980, addmod(mload(0xe40), sub(f_q, mload(0x3960)), f_q))
            mstore(0x39a0, mulmod(mload(0xa80), 1, f_q))
            mstore(0x39c0, addmod(mload(0xe40), sub(f_q, mload(0x39a0)), f_q))
            mstore(
                0x39e0,
                mulmod(mload(0xa80), 11451405578697956743456240853980216273390554734748796433026540431386972584651, f_q)
            )
            mstore(0x3a00, addmod(mload(0xe40), sub(f_q, mload(0x39e0)), f_q))
            mstore(
                0x3a20,
                mulmod(mload(0xa80), 8374374965308410102411073611984011876711565317741801500439755773472076597347, f_q)
            )
            mstore(0x3a40, addmod(mload(0xe40), sub(f_q, mload(0x3a20)), f_q))
            mstore(
                0x3a60,
                mulmod(mload(0xa80), 21490807004895109926141140246143262403290679459142140821740925192625185504522, f_q)
            )
            mstore(0x3a80, addmod(mload(0xe40), sub(f_q, mload(0x3a60)), f_q))
            mstore(
                0x3aa0,
                mulmod(6616149745577394522356295102346368305374051634342887004165528916468992151333, mload(0x3920), f_q)
            )
            mstore(0x3ac0, mulmod(mload(0x3aa0), 1, f_q))
            {
                let result := mulmod(mload(0xe40), mload(0x3aa0), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3ac0)), f_q), result, f_q)
                mstore(15072, result)
            }
            mstore(
                0x3b00,
                mulmod(530501691302793820034524283154921640443166880847115433758691660016816186416, mload(0x3920), f_q)
            )
            mstore(
                0x3b20,
                mulmod(
                    mload(0x3b00),
                    11451405578697956743456240853980216273390554734748796433026540431386972584651,
                    f_q
                )
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3b00), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3b20)), f_q), result, f_q)
                mstore(15168, result)
            }
            mstore(
                0x3b60,
                mulmod(6735468303947967792722299167169712601265763928443086612877978228369959138708, mload(0x3920), f_q)
            )
            mstore(
                0x3b80,
                mulmod(mload(0x3b60), 8374374965308410102411073611984011876711565317741801500439755773472076597347, f_q)
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3b60), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3b80)), f_q), result, f_q)
                mstore(15264, result)
            }
            mstore(
                0x3bc0,
                mulmod(
                    21558793644302942916864965630979640748886316167261336210841195936026980690666,
                    mload(0x3920),
                    f_q
                )
            )
            mstore(
                0x3be0,
                mulmod(
                    mload(0x3bc0),
                    21490807004895109926141140246143262403290679459142140821740925192625185504522,
                    f_q
                )
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3bc0), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3be0)), f_q), result, f_q)
                mstore(15360, result)
            }
            mstore(0x3c20, mulmod(1, mload(0x39c0), f_q))
            mstore(0x3c40, mulmod(mload(0x3c20), mload(0x3a00), f_q))
            mstore(0x3c60, mulmod(mload(0x3c40), mload(0x3a40), f_q))
            mstore(0x3c80, mulmod(mload(0x3c60), mload(0x3a80), f_q))
            mstore(
                0x3ca0,
                mulmod(10436837293141318478790164891277058815157809665667237910671663755188835910967, mload(0xa80), f_q)
            )
            mstore(0x3cc0, mulmod(mload(0x3ca0), 1, f_q))
            {
                let result := mulmod(mload(0xe40), mload(0x3ca0), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3cc0)), f_q), result, f_q)
                mstore(15584, result)
            }
            mstore(
                0x3d00,
                mulmod(11451405578697956743456240853980216273390554734748796433026540431386972584650, mload(0xa80), f_q)
            )
            mstore(
                0x3d20,
                mulmod(
                    mload(0x3d00),
                    11451405578697956743456240853980216273390554734748796433026540431386972584651,
                    f_q
                )
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3d00), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3d20)), f_q), result, f_q)
                mstore(15680, result)
            }
            mstore(
                0x3d60,
                mulmod(4558794634599160729665540001169218674296628713450539706539395399156027320108, mload(0xa80), f_q)
            )
            mstore(0x3d80, mulmod(mload(0x3d60), 1, f_q))
            {
                let result := mulmod(mload(0xe40), mload(0x3d60), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3d80)), f_q), result, f_q)
                mstore(15776, result)
            }
            mstore(
                0x3dc0,
                mulmod(17329448237240114492580865744088056414251735686965494637158808787419781175509, mload(0xa80), f_q)
            )
            mstore(
                0x3de0,
                mulmod(
                    mload(0x3dc0),
                    17329448237240114492580865744088056414251735686965494637158808787419781175510,
                    f_q
                )
            )
            {
                let result := mulmod(mload(0xe40), mload(0x3dc0), f_q)
                result := addmod(mulmod(mload(0xa80), sub(f_q, mload(0x3de0)), f_q), result, f_q)
                mstore(15872, result)
            }
            mstore(0x3e20, mulmod(mload(0x3c20), mload(0x3980), f_q))
            {
                let result := mulmod(mload(0xe40), 1, f_q)
                result := addmod(
                    mulmod(
                        mload(0xa80),
                        21888242871839275222246405745257275088548364400416034343698204186575808495616,
                        f_q
                    ),
                    result,
                    f_q
                )
                mstore(15936, result)
            }
            {
                let prod := mload(0x3ae0)

                prod := mulmod(mload(0x3b40), prod, f_q)
                mstore(0x3e60, prod)

                prod := mulmod(mload(0x3ba0), prod, f_q)
                mstore(0x3e80, prod)

                prod := mulmod(mload(0x3c00), prod, f_q)
                mstore(0x3ea0, prod)

                prod := mulmod(mload(0x3ce0), prod, f_q)
                mstore(0x3ec0, prod)

                prod := mulmod(mload(0x3d40), prod, f_q)
                mstore(0x3ee0, prod)

                prod := mulmod(mload(0x3c40), prod, f_q)
                mstore(0x3f00, prod)

                prod := mulmod(mload(0x3da0), prod, f_q)
                mstore(0x3f20, prod)

                prod := mulmod(mload(0x3e00), prod, f_q)
                mstore(0x3f40, prod)

                prod := mulmod(mload(0x3e20), prod, f_q)
                mstore(0x3f60, prod)

                prod := mulmod(mload(0x3e40), prod, f_q)
                mstore(0x3f80, prod)

                prod := mulmod(mload(0x3c20), prod, f_q)
                mstore(0x3fa0, prod)
            }
            mstore(0x3fe0, 32)
            mstore(0x4000, 32)
            mstore(0x4020, 32)
            mstore(0x4040, mload(0x3fa0))
            mstore(0x4060, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
            mstore(0x4080, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
            success := and(eq(staticcall(gas(), 0x5, 0x3fe0, 0xc0, 0x3fc0, 0x20), 1), success)
            {
                let inv := mload(0x3fc0)
                let v

                v := mload(0x3c20)
                mstore(15392, mulmod(mload(0x3f80), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3e40)
                mstore(15936, mulmod(mload(0x3f60), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3e20)
                mstore(15904, mulmod(mload(0x3f40), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3e00)
                mstore(15872, mulmod(mload(0x3f20), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3da0)
                mstore(15776, mulmod(mload(0x3f00), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3c40)
                mstore(15424, mulmod(mload(0x3ee0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3d40)
                mstore(15680, mulmod(mload(0x3ec0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3ce0)
                mstore(15584, mulmod(mload(0x3ea0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3c00)
                mstore(15360, mulmod(mload(0x3e80), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3ba0)
                mstore(15264, mulmod(mload(0x3e60), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x3b40)
                mstore(15168, mulmod(mload(0x3ae0), inv, f_q))
                inv := mulmod(v, inv, f_q)
                mstore(0x3ae0, inv)
            }
            {
                let result := mload(0x3ae0)
                result := addmod(mload(0x3b40), result, f_q)
                result := addmod(mload(0x3ba0), result, f_q)
                result := addmod(mload(0x3c00), result, f_q)
                mstore(16544, result)
            }
            mstore(0x40c0, mulmod(mload(0x3c80), mload(0x3c40), f_q))
            {
                let result := mload(0x3ce0)
                result := addmod(mload(0x3d40), result, f_q)
                mstore(16608, result)
            }
            mstore(0x4100, mulmod(mload(0x3c80), mload(0x3e20), f_q))
            {
                let result := mload(0x3da0)
                result := addmod(mload(0x3e00), result, f_q)
                mstore(16672, result)
            }
            mstore(0x4140, mulmod(mload(0x3c80), mload(0x3c20), f_q))
            {
                let result := mload(0x3e40)
                mstore(16736, result)
            }
            {
                let prod := mload(0x40a0)

                prod := mulmod(mload(0x40e0), prod, f_q)
                mstore(0x4180, prod)

                prod := mulmod(mload(0x4120), prod, f_q)
                mstore(0x41a0, prod)

                prod := mulmod(mload(0x4160), prod, f_q)
                mstore(0x41c0, prod)
            }
            mstore(0x4200, 32)
            mstore(0x4220, 32)
            mstore(0x4240, 32)
            mstore(0x4260, mload(0x41c0))
            mstore(0x4280, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
            mstore(0x42a0, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
            success := and(eq(staticcall(gas(), 0x5, 0x4200, 0xc0, 0x41e0, 0x20), 1), success)
            {
                let inv := mload(0x41e0)
                let v

                v := mload(0x4160)
                mstore(16736, mulmod(mload(0x41a0), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x4120)
                mstore(16672, mulmod(mload(0x4180), inv, f_q))
                inv := mulmod(v, inv, f_q)

                v := mload(0x40e0)
                mstore(16608, mulmod(mload(0x40a0), inv, f_q))
                inv := mulmod(v, inv, f_q)
                mstore(0x40a0, inv)
            }
            mstore(0x42c0, mulmod(mload(0x40c0), mload(0x40e0), f_q))
            mstore(0x42e0, mulmod(mload(0x4100), mload(0x4120), f_q))
            mstore(0x4300, mulmod(mload(0x4140), mload(0x4160), f_q))
            mstore(0x4320, mulmod(mload(0xd40), mload(0xd40), f_q))
            mstore(0x4340, mulmod(mload(0x4320), mload(0xd40), f_q))
            mstore(0x4360, mulmod(mload(0x4340), mload(0xd40), f_q))
            mstore(0x4380, mulmod(mload(0x4360), mload(0xd40), f_q))
            mstore(0x43a0, mulmod(mload(0x4380), mload(0xd40), f_q))
            mstore(0x43c0, mulmod(mload(0x43a0), mload(0xd40), f_q))
            mstore(0x43e0, mulmod(mload(0x43c0), mload(0xd40), f_q))
            mstore(0x4400, mulmod(mload(0x43e0), mload(0xd40), f_q))
            mstore(0x4420, mulmod(mload(0x4400), mload(0xd40), f_q))
            mstore(0x4440, mulmod(mload(0xda0), mload(0xda0), f_q))
            mstore(0x4460, mulmod(mload(0x4440), mload(0xda0), f_q))
            mstore(0x4480, mulmod(mload(0x4460), mload(0xda0), f_q))
            {
                let result := mulmod(mload(0xac0), mload(0x3ae0), f_q)
                result := addmod(mulmod(mload(0xae0), mload(0x3b40), f_q), result, f_q)
                result := addmod(mulmod(mload(0xb00), mload(0x3ba0), f_q), result, f_q)
                result := addmod(mulmod(mload(0xb20), mload(0x3c00), f_q), result, f_q)
                mstore(17568, result)
            }
            mstore(0x44c0, mulmod(mload(0x44a0), mload(0x40a0), f_q))
            mstore(0x44e0, mulmod(sub(f_q, mload(0x44c0)), 1, f_q))
            mstore(0x4500, mulmod(mload(0x44e0), 1, f_q))
            mstore(0x4520, mulmod(1, mload(0x40c0), f_q))
            {
                let result := mulmod(mload(0xc40), mload(0x3ce0), f_q)
                result := addmod(mulmod(mload(0xc60), mload(0x3d40), f_q), result, f_q)
                mstore(17728, result)
            }
            mstore(0x4560, mulmod(mload(0x4540), mload(0x42c0), f_q))
            mstore(0x4580, mulmod(sub(f_q, mload(0x4560)), 1, f_q))
            mstore(0x45a0, mulmod(mload(0x4520), 1, f_q))
            {
                let result := mulmod(mload(0xc80), mload(0x3ce0), f_q)
                result := addmod(mulmod(mload(0xca0), mload(0x3d40), f_q), result, f_q)
                mstore(17856, result)
            }
            mstore(0x45e0, mulmod(mload(0x45c0), mload(0x42c0), f_q))
            mstore(0x4600, mulmod(sub(f_q, mload(0x45e0)), mload(0xd40), f_q))
            mstore(0x4620, mulmod(mload(0x4520), mload(0xd40), f_q))
            mstore(0x4640, addmod(mload(0x4580), mload(0x4600), f_q))
            mstore(0x4660, mulmod(mload(0x4640), mload(0xda0), f_q))
            mstore(0x4680, mulmod(mload(0x45a0), mload(0xda0), f_q))
            mstore(0x46a0, mulmod(mload(0x4620), mload(0xda0), f_q))
            mstore(0x46c0, addmod(mload(0x4500), mload(0x4660), f_q))
            mstore(0x46e0, mulmod(1, mload(0x4100), f_q))
            {
                let result := mulmod(mload(0xcc0), mload(0x3da0), f_q)
                result := addmod(mulmod(mload(0xce0), mload(0x3e00), f_q), result, f_q)
                mstore(18176, result)
            }
            mstore(0x4720, mulmod(mload(0x4700), mload(0x42e0), f_q))
            mstore(0x4740, mulmod(sub(f_q, mload(0x4720)), 1, f_q))
            mstore(0x4760, mulmod(mload(0x46e0), 1, f_q))
            mstore(0x4780, mulmod(mload(0x4740), mload(0x4440), f_q))
            mstore(0x47a0, mulmod(mload(0x4760), mload(0x4440), f_q))
            mstore(0x47c0, addmod(mload(0x46c0), mload(0x4780), f_q))
            mstore(0x47e0, mulmod(1, mload(0x4140), f_q))
            {
                let result := mulmod(mload(0xd00), mload(0x3e40), f_q)
                mstore(18432, result)
            }
            mstore(0x4820, mulmod(mload(0x4800), mload(0x4300), f_q))
            mstore(0x4840, mulmod(sub(f_q, mload(0x4820)), 1, f_q))
            mstore(0x4860, mulmod(mload(0x47e0), 1, f_q))
            {
                let result := mulmod(mload(0xb40), mload(0x3e40), f_q)
                mstore(18560, result)
            }
            mstore(0x48a0, mulmod(mload(0x4880), mload(0x4300), f_q))
            mstore(0x48c0, mulmod(sub(f_q, mload(0x48a0)), mload(0xd40), f_q))
            mstore(0x48e0, mulmod(mload(0x47e0), mload(0xd40), f_q))
            mstore(0x4900, addmod(mload(0x4840), mload(0x48c0), f_q))
            {
                let result := mulmod(mload(0xb60), mload(0x3e40), f_q)
                mstore(18720, result)
            }
            mstore(0x4940, mulmod(mload(0x4920), mload(0x4300), f_q))
            mstore(0x4960, mulmod(sub(f_q, mload(0x4940)), mload(0x4320), f_q))
            mstore(0x4980, mulmod(mload(0x47e0), mload(0x4320), f_q))
            mstore(0x49a0, addmod(mload(0x4900), mload(0x4960), f_q))
            {
                let result := mulmod(mload(0xb80), mload(0x3e40), f_q)
                mstore(18880, result)
            }
            mstore(0x49e0, mulmod(mload(0x49c0), mload(0x4300), f_q))
            mstore(0x4a00, mulmod(sub(f_q, mload(0x49e0)), mload(0x4340), f_q))
            mstore(0x4a20, mulmod(mload(0x47e0), mload(0x4340), f_q))
            mstore(0x4a40, addmod(mload(0x49a0), mload(0x4a00), f_q))
            {
                let result := mulmod(mload(0xba0), mload(0x3e40), f_q)
                mstore(19040, result)
            }
            mstore(0x4a80, mulmod(mload(0x4a60), mload(0x4300), f_q))
            mstore(0x4aa0, mulmod(sub(f_q, mload(0x4a80)), mload(0x4360), f_q))
            mstore(0x4ac0, mulmod(mload(0x47e0), mload(0x4360), f_q))
            mstore(0x4ae0, addmod(mload(0x4a40), mload(0x4aa0), f_q))
            {
                let result := mulmod(mload(0xbe0), mload(0x3e40), f_q)
                mstore(19200, result)
            }
            mstore(0x4b20, mulmod(mload(0x4b00), mload(0x4300), f_q))
            mstore(0x4b40, mulmod(sub(f_q, mload(0x4b20)), mload(0x4380), f_q))
            mstore(0x4b60, mulmod(mload(0x47e0), mload(0x4380), f_q))
            mstore(0x4b80, addmod(mload(0x4ae0), mload(0x4b40), f_q))
            {
                let result := mulmod(mload(0xc00), mload(0x3e40), f_q)
                mstore(19360, result)
            }
            mstore(0x4bc0, mulmod(mload(0x4ba0), mload(0x4300), f_q))
            mstore(0x4be0, mulmod(sub(f_q, mload(0x4bc0)), mload(0x43a0), f_q))
            mstore(0x4c00, mulmod(mload(0x47e0), mload(0x43a0), f_q))
            mstore(0x4c20, addmod(mload(0x4b80), mload(0x4be0), f_q))
            {
                let result := mulmod(mload(0xc20), mload(0x3e40), f_q)
                mstore(19520, result)
            }
            mstore(0x4c60, mulmod(mload(0x4c40), mload(0x4300), f_q))
            mstore(0x4c80, mulmod(sub(f_q, mload(0x4c60)), mload(0x43c0), f_q))
            mstore(0x4ca0, mulmod(mload(0x47e0), mload(0x43c0), f_q))
            mstore(0x4cc0, addmod(mload(0x4c20), mload(0x4c80), f_q))
            mstore(0x4ce0, mulmod(mload(0x38a0), mload(0x4140), f_q))
            mstore(0x4d00, mulmod(mload(0x38c0), mload(0x4140), f_q))
            mstore(0x4d20, mulmod(mload(0x38e0), mload(0x4140), f_q))
            {
                let result := mulmod(mload(0x3900), mload(0x3e40), f_q)
                mstore(19776, result)
            }
            mstore(0x4d60, mulmod(mload(0x4d40), mload(0x4300), f_q))
            mstore(0x4d80, mulmod(sub(f_q, mload(0x4d60)), mload(0x43e0), f_q))
            mstore(0x4da0, mulmod(mload(0x47e0), mload(0x43e0), f_q))
            mstore(0x4dc0, mulmod(mload(0x4ce0), mload(0x43e0), f_q))
            mstore(0x4de0, mulmod(mload(0x4d00), mload(0x43e0), f_q))
            mstore(0x4e00, mulmod(mload(0x4d20), mload(0x43e0), f_q))
            mstore(0x4e20, addmod(mload(0x4cc0), mload(0x4d80), f_q))
            {
                let result := mulmod(mload(0xbc0), mload(0x3e40), f_q)
                mstore(20032, result)
            }
            mstore(0x4e60, mulmod(mload(0x4e40), mload(0x4300), f_q))
            mstore(0x4e80, mulmod(sub(f_q, mload(0x4e60)), mload(0x4400), f_q))
            mstore(0x4ea0, mulmod(mload(0x47e0), mload(0x4400), f_q))
            mstore(0x4ec0, addmod(mload(0x4e20), mload(0x4e80), f_q))
            mstore(0x4ee0, mulmod(mload(0x4ec0), mload(0x4460), f_q))
            mstore(0x4f00, mulmod(mload(0x4860), mload(0x4460), f_q))
            mstore(0x4f20, mulmod(mload(0x48e0), mload(0x4460), f_q))
            mstore(0x4f40, mulmod(mload(0x4980), mload(0x4460), f_q))
            mstore(0x4f60, mulmod(mload(0x4a20), mload(0x4460), f_q))
            mstore(0x4f80, mulmod(mload(0x4ac0), mload(0x4460), f_q))
            mstore(0x4fa0, mulmod(mload(0x4b60), mload(0x4460), f_q))
            mstore(0x4fc0, mulmod(mload(0x4c00), mload(0x4460), f_q))
            mstore(0x4fe0, mulmod(mload(0x4ca0), mload(0x4460), f_q))
            mstore(0x5000, mulmod(mload(0x4da0), mload(0x4460), f_q))
            mstore(0x5020, mulmod(mload(0x4dc0), mload(0x4460), f_q))
            mstore(0x5040, mulmod(mload(0x4de0), mload(0x4460), f_q))
            mstore(0x5060, mulmod(mload(0x4e00), mload(0x4460), f_q))
            mstore(0x5080, mulmod(mload(0x4ea0), mload(0x4460), f_q))
            mstore(0x50a0, addmod(mload(0x47c0), mload(0x4ee0), f_q))
            mstore(0x50c0, mulmod(1, mload(0x3c80), f_q))
            mstore(0x50e0, mulmod(1, mload(0xe40), f_q))
            mstore(0x5100, 0x0000000000000000000000000000000000000000000000000000000000000001)
            mstore(0x5120, 0x0000000000000000000000000000000000000000000000000000000000000002)
            mstore(0x5140, mload(0x50a0))
            success := and(eq(staticcall(gas(), 0x7, 0x5100, 0x60, 0x5100, 0x40), 1), success)
            mstore(0x5160, mload(0x5100))
            mstore(0x5180, mload(0x5120))
            mstore(0x51a0, mload(0x660))
            mstore(0x51c0, mload(0x680))
            success := and(eq(staticcall(gas(), 0x6, 0x5160, 0x80, 0x5160, 0x40), 1), success)
            mstore(0x51e0, mload(0x840))
            mstore(0x5200, mload(0x860))
            mstore(0x5220, mload(0x4680))
            success := and(eq(staticcall(gas(), 0x7, 0x51e0, 0x60, 0x51e0, 0x40), 1), success)
            mstore(0x5240, mload(0x5160))
            mstore(0x5260, mload(0x5180))
            mstore(0x5280, mload(0x51e0))
            mstore(0x52a0, mload(0x5200))
            success := and(eq(staticcall(gas(), 0x6, 0x5240, 0x80, 0x5240, 0x40), 1), success)
            mstore(0x52c0, mload(0x880))
            mstore(0x52e0, mload(0x8a0))
            mstore(0x5300, mload(0x46a0))
            success := and(eq(staticcall(gas(), 0x7, 0x52c0, 0x60, 0x52c0, 0x40), 1), success)
            mstore(0x5320, mload(0x5240))
            mstore(0x5340, mload(0x5260))
            mstore(0x5360, mload(0x52c0))
            mstore(0x5380, mload(0x52e0))
            success := and(eq(staticcall(gas(), 0x6, 0x5320, 0x80, 0x5320, 0x40), 1), success)
            mstore(0x53a0, mload(0x700))
            mstore(0x53c0, mload(0x720))
            mstore(0x53e0, mload(0x47a0))
            success := and(eq(staticcall(gas(), 0x7, 0x53a0, 0x60, 0x53a0, 0x40), 1), success)
            mstore(0x5400, mload(0x5320))
            mstore(0x5420, mload(0x5340))
            mstore(0x5440, mload(0x53a0))
            mstore(0x5460, mload(0x53c0))
            success := and(eq(staticcall(gas(), 0x6, 0x5400, 0x80, 0x5400, 0x40), 1), success)
            mstore(0x5480, mload(0x740))
            mstore(0x54a0, mload(0x760))
            mstore(0x54c0, mload(0x4f00))
            success := and(eq(staticcall(gas(), 0x7, 0x5480, 0x60, 0x5480, 0x40), 1), success)
            mstore(0x54e0, mload(0x5400))
            mstore(0x5500, mload(0x5420))
            mstore(0x5520, mload(0x5480))
            mstore(0x5540, mload(0x54a0))
            success := and(eq(staticcall(gas(), 0x6, 0x54e0, 0x80, 0x54e0, 0x40), 1), success)
            mstore(0x5560, 0x28c9feac830a1d23683f2a635ca9232fd5a627948b2a063e04edbbd5df806073)
            mstore(0x5580, 0x098706d829dcb3f6fcc0df885174a2a2de081c590a00ac95f4525f60babbefe9)
            mstore(0x55a0, mload(0x4f20))
            success := and(eq(staticcall(gas(), 0x7, 0x5560, 0x60, 0x5560, 0x40), 1), success)
            mstore(0x55c0, mload(0x54e0))
            mstore(0x55e0, mload(0x5500))
            mstore(0x5600, mload(0x5560))
            mstore(0x5620, mload(0x5580))
            success := and(eq(staticcall(gas(), 0x6, 0x55c0, 0x80, 0x55c0, 0x40), 1), success)
            mstore(0x5640, 0x03847d4de6cbde8c639401cf45f0db7c7c8385ca483825448b5ba614691f53e6)
            mstore(0x5660, 0x0147b0ddc70c95e5285d289c54c930e5782d755366f5d3d0dc8376f01f47981e)
            mstore(0x5680, mload(0x4f40))
            success := and(eq(staticcall(gas(), 0x7, 0x5640, 0x60, 0x5640, 0x40), 1), success)
            mstore(0x56a0, mload(0x55c0))
            mstore(0x56c0, mload(0x55e0))
            mstore(0x56e0, mload(0x5640))
            mstore(0x5700, mload(0x5660))
            success := and(eq(staticcall(gas(), 0x6, 0x56a0, 0x80, 0x56a0, 0x40), 1), success)
            mstore(0x5720, 0x03a22feeb728a985ba1a7267babd2972060351c1893e8c9d1b4afea1997cfb2d)
            mstore(0x5740, 0x0f00b29e6e16328160b696c3e2c5d909f07915a12997bd55dd0b029c4693f6d6)
            mstore(0x5760, mload(0x4f60))
            success := and(eq(staticcall(gas(), 0x7, 0x5720, 0x60, 0x5720, 0x40), 1), success)
            mstore(0x5780, mload(0x56a0))
            mstore(0x57a0, mload(0x56c0))
            mstore(0x57c0, mload(0x5720))
            mstore(0x57e0, mload(0x5740))
            success := and(eq(staticcall(gas(), 0x6, 0x5780, 0x80, 0x5780, 0x40), 1), success)
            mstore(0x5800, 0x280c2465cda2991f784c170550813f50400fd1e437adc86a2d7c2f12d6ccece9)
            mstore(0x5820, 0x10a8f946db6ebc615b792f6b4f0d5522c1ade32208d2cb6b1019a9321314546e)
            mstore(0x5840, mload(0x4f80))
            success := and(eq(staticcall(gas(), 0x7, 0x5800, 0x60, 0x5800, 0x40), 1), success)
            mstore(0x5860, mload(0x5780))
            mstore(0x5880, mload(0x57a0))
            mstore(0x58a0, mload(0x5800))
            mstore(0x58c0, mload(0x5820))
            success := and(eq(staticcall(gas(), 0x6, 0x5860, 0x80, 0x5860, 0x40), 1), success)
            mstore(0x58e0, 0x1ecade5ea10ab9a44d2993527fc6263bd9148efb451b2eda13141156ff68104a)
            mstore(0x5900, 0x2d541cb34d01ce121940240afcdc8ede1d387be66ce2c56acfe3adde7030850d)
            mstore(0x5920, mload(0x4fa0))
            success := and(eq(staticcall(gas(), 0x7, 0x58e0, 0x60, 0x58e0, 0x40), 1), success)
            mstore(0x5940, mload(0x5860))
            mstore(0x5960, mload(0x5880))
            mstore(0x5980, mload(0x58e0))
            mstore(0x59a0, mload(0x5900))
            success := and(eq(staticcall(gas(), 0x6, 0x5940, 0x80, 0x5940, 0x40), 1), success)
            mstore(0x59c0, 0x1f7ec4a8e2d1dc36ac3029083025a40f990139b0d508385cb50e58cb9a90d09f)
            mstore(0x59e0, 0x1977fe3123b724391fee488dc63a61ee240ea7ddb6b24b11cfbb0b96dff676b5)
            mstore(0x5a00, mload(0x4fc0))
            success := and(eq(staticcall(gas(), 0x7, 0x59c0, 0x60, 0x59c0, 0x40), 1), success)
            mstore(0x5a20, mload(0x5940))
            mstore(0x5a40, mload(0x5960))
            mstore(0x5a60, mload(0x59c0))
            mstore(0x5a80, mload(0x59e0))
            success := and(eq(staticcall(gas(), 0x6, 0x5a20, 0x80, 0x5a20, 0x40), 1), success)
            mstore(0x5aa0, 0x06df94a5af1833345174baa17f9bc72e984b7fe5844f8a5f4f67d049eacc18b5)
            mstore(0x5ac0, 0x04f4452609f3a6ab5d471fd2e86383802e7a921b86b36219f446043d79e2fd78)
            mstore(0x5ae0, mload(0x4fe0))
            success := and(eq(staticcall(gas(), 0x7, 0x5aa0, 0x60, 0x5aa0, 0x40), 1), success)
            mstore(0x5b00, mload(0x5a20))
            mstore(0x5b20, mload(0x5a40))
            mstore(0x5b40, mload(0x5aa0))
            mstore(0x5b60, mload(0x5ac0))
            success := and(eq(staticcall(gas(), 0x6, 0x5b00, 0x80, 0x5b00, 0x40), 1), success)
            mstore(0x5b80, mload(0x960))
            mstore(0x5ba0, mload(0x980))
            mstore(0x5bc0, mload(0x5000))
            success := and(eq(staticcall(gas(), 0x7, 0x5b80, 0x60, 0x5b80, 0x40), 1), success)
            mstore(0x5be0, mload(0x5b00))
            mstore(0x5c00, mload(0x5b20))
            mstore(0x5c20, mload(0x5b80))
            mstore(0x5c40, mload(0x5ba0))
            success := and(eq(staticcall(gas(), 0x6, 0x5be0, 0x80, 0x5be0, 0x40), 1), success)
            mstore(0x5c60, mload(0x9a0))
            mstore(0x5c80, mload(0x9c0))
            mstore(0x5ca0, mload(0x5020))
            success := and(eq(staticcall(gas(), 0x7, 0x5c60, 0x60, 0x5c60, 0x40), 1), success)
            mstore(0x5cc0, mload(0x5be0))
            mstore(0x5ce0, mload(0x5c00))
            mstore(0x5d00, mload(0x5c60))
            mstore(0x5d20, mload(0x5c80))
            success := and(eq(staticcall(gas(), 0x6, 0x5cc0, 0x80, 0x5cc0, 0x40), 1), success)
            mstore(0x5d40, mload(0x9e0))
            mstore(0x5d60, mload(0xa00))
            mstore(0x5d80, mload(0x5040))
            success := and(eq(staticcall(gas(), 0x7, 0x5d40, 0x60, 0x5d40, 0x40), 1), success)
            mstore(0x5da0, mload(0x5cc0))
            mstore(0x5dc0, mload(0x5ce0))
            mstore(0x5de0, mload(0x5d40))
            mstore(0x5e00, mload(0x5d60))
            success := and(eq(staticcall(gas(), 0x6, 0x5da0, 0x80, 0x5da0, 0x40), 1), success)
            mstore(0x5e20, mload(0xa20))
            mstore(0x5e40, mload(0xa40))
            mstore(0x5e60, mload(0x5060))
            success := and(eq(staticcall(gas(), 0x7, 0x5e20, 0x60, 0x5e20, 0x40), 1), success)
            mstore(0x5e80, mload(0x5da0))
            mstore(0x5ea0, mload(0x5dc0))
            mstore(0x5ec0, mload(0x5e20))
            mstore(0x5ee0, mload(0x5e40))
            success := and(eq(staticcall(gas(), 0x6, 0x5e80, 0x80, 0x5e80, 0x40), 1), success)
            mstore(0x5f00, mload(0x8c0))
            mstore(0x5f20, mload(0x8e0))
            mstore(0x5f40, mload(0x5080))
            success := and(eq(staticcall(gas(), 0x7, 0x5f00, 0x60, 0x5f00, 0x40), 1), success)
            mstore(0x5f60, mload(0x5e80))
            mstore(0x5f80, mload(0x5ea0))
            mstore(0x5fa0, mload(0x5f00))
            mstore(0x5fc0, mload(0x5f20))
            success := and(eq(staticcall(gas(), 0x6, 0x5f60, 0x80, 0x5f60, 0x40), 1), success)
            mstore(0x5fe0, mload(0xde0))
            mstore(0x6000, mload(0xe00))
            mstore(0x6020, sub(f_q, mload(0x50c0)))
            success := and(eq(staticcall(gas(), 0x7, 0x5fe0, 0x60, 0x5fe0, 0x40), 1), success)
            mstore(0x6040, mload(0x5f60))
            mstore(0x6060, mload(0x5f80))
            mstore(0x6080, mload(0x5fe0))
            mstore(0x60a0, mload(0x6000))
            success := and(eq(staticcall(gas(), 0x6, 0x6040, 0x80, 0x6040, 0x40), 1), success)
            mstore(0x60c0, mload(0xe80))
            mstore(0x60e0, mload(0xea0))
            mstore(0x6100, mload(0x50e0))
            success := and(eq(staticcall(gas(), 0x7, 0x60c0, 0x60, 0x60c0, 0x40), 1), success)
            mstore(0x6120, mload(0x6040))
            mstore(0x6140, mload(0x6060))
            mstore(0x6160, mload(0x60c0))
            mstore(0x6180, mload(0x60e0))
            success := and(eq(staticcall(gas(), 0x6, 0x6120, 0x80, 0x6120, 0x40), 1), success)
            mstore(0x61a0, mload(0x6120))
            mstore(0x61c0, mload(0x6140))
            mstore(0x61e0, mload(0xe80))
            mstore(0x6200, mload(0xea0))
            mstore(0x6220, mload(0xec0))
            mstore(0x6240, mload(0xee0))
            mstore(0x6260, mload(0xf00))
            mstore(0x6280, mload(0xf20))
            mstore(0x62a0, keccak256(0x61a0, 256))
            mstore(25280, mod(mload(25248), f_q))
            mstore(0x62e0, mulmod(mload(0x62c0), mload(0x62c0), f_q))
            mstore(0x6300, mulmod(1, mload(0x62c0), f_q))
            mstore(0x6320, mload(0x6220))
            mstore(0x6340, mload(0x6240))
            mstore(0x6360, mload(0x6300))
            success := and(eq(staticcall(gas(), 0x7, 0x6320, 0x60, 0x6320, 0x40), 1), success)
            mstore(0x6380, mload(0x61a0))
            mstore(0x63a0, mload(0x61c0))
            mstore(0x63c0, mload(0x6320))
            mstore(0x63e0, mload(0x6340))
            success := and(eq(staticcall(gas(), 0x6, 0x6380, 0x80, 0x6380, 0x40), 1), success)
            mstore(0x6400, mload(0x6260))
            mstore(0x6420, mload(0x6280))
            mstore(0x6440, mload(0x6300))
            success := and(eq(staticcall(gas(), 0x7, 0x6400, 0x60, 0x6400, 0x40), 1), success)
            mstore(0x6460, mload(0x61e0))
            mstore(0x6480, mload(0x6200))
            mstore(0x64a0, mload(0x6400))
            mstore(0x64c0, mload(0x6420))
            success := and(eq(staticcall(gas(), 0x6, 0x6460, 0x80, 0x6460, 0x40), 1), success)
            mstore(0x64e0, mload(0x6380))
            mstore(0x6500, mload(0x63a0))
            mstore(0x6520, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)
            mstore(0x6540, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed)
            mstore(0x6560, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
            mstore(0x6580, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa)
            mstore(0x65a0, mload(0x6460))
            mstore(0x65c0, mload(0x6480))
            mstore(0x65e0, 0x172aa93c41f16e1e04d62ac976a5d945f4be0acab990c6dc19ac4a7cf68bf77b)
            mstore(0x6600, 0x2ae0c8c3a090f7200ff398ee9845bbae8f8c1445ae7b632212775f60a0e21600)
            mstore(0x6620, 0x190fa476a5b352809ed41d7a0d7fe12b8f685e3c12a6d83855dba27aaf469643)
            mstore(0x6640, 0x1c0a500618907df9e4273d5181e31088deb1f05132de037cbfe73888f97f77c9)
            success := and(eq(staticcall(gas(), 0x8, 0x64e0, 0x180, 0x64e0, 0x20), 1), success)
            success := and(eq(mload(0x64e0), 1), success)

            // Revert if anything fails
            if iszero(success) { revert(0, 0) }

            // Return empty bytes on success
            return(0, 0)
        }
    }
}
