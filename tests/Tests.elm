module Tests exposing (suite)

import Bytes exposing (Bytes)
import Bytes.Decode as Decode
import Bytes.Encode as Encode
import Bytes.Extra as Bytes
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer)
import GF256 as GF
import GF256.Polynomial as GFP
import List.Extra as List
import Random
import Secret
import Secret.Key exposing (Key)
import Shrink
import Test exposing (Test)


{-| Unfortunately any bytes == any other bytes, so we need to check their values.
-}
expectBytes : Bytes -> Bytes -> Expectation
expectBytes expected actual =
    Bytes.toByteValues actual
        |> Expect.equalLists (Bytes.toByteValues expected)


expectBytes_ : Result x Bytes -> Result x Bytes -> Expectation
expectBytes_ expected actual =
    case ( expected, actual ) of
        ( Ok exp, Ok act ) ->
            expectBytes exp act

        _ ->
            Expect.equal expected actual


uint8 : Fuzzer Int
uint8 =
    Fuzz.intRange 0 255


nonemptyBytes : Fuzzer Bytes
nonemptyBytes =
    Fuzz.map2 (::) uint8 (Fuzz.list uint8)
        |> Fuzz.map Bytes.fromByteValues


partsAndMin : Fuzzer { parts : Int, minPartsNeeded : Int }
partsAndMin =
    Fuzz.custom
        {- The max number of parts allowed by the library is 255.

           There would be combinatorial explosion in some tests later when
           generating all permitted key combinations, so we're limiting the parts
           in this fuzzer to 10. That gives at max 2^10 = 1024 combinations to
           try.
        -}
        (Random.int 2 10
            |> Random.andThen
                (\parts ->
                    Random.int 2 parts
                        |> Random.map
                            (\minPartsNeeded ->
                                { parts = parts
                                , minPartsNeeded = minPartsNeeded
                                }
                            )
                )
        )
        Shrink.noShrink


suite : Test
suite =
    Test.describe "Janiczek/elm-secret-sharing"
        [ Test.describe "GaloisField256"
            [ Test.fuzz2 uint8 uint8 "add == sub" <|
                \a b ->
                    GF.add a b
                        |> Expect.equal (GF.sub a b)
            , Test.fuzz2 uint8 uint8 "sub is inverse of add" <|
                \a b ->
                    GF.sub (GF.add a b) b
                        |> Expect.equal a
            , Test.describe "add"
                [ Test.test "150 + 130 == 20" <| \() -> GF.add 150 130 |> Expect.equal 20
                , Test.test "150 + 254 == 104" <| \() -> GF.add 150 254 |> Expect.equal 104
                , Test.test "100 + 30 == 122" <| \() -> GF.add 100 30 |> Expect.equal 122
                , Test.fuzz uint8 "Cancelling" <|
                    \a ->
                        GF.add a a
                            |> Expect.equal 0
                , Test.fuzz2 uint8 uint8 "Commutativity" <|
                    \a b ->
                        GF.add a b
                            |> Expect.equal (GF.add b a)
                ]
            , Test.fuzz uint8 "inv >> inv == id (except 0)" <|
                \n ->
                    if n == 0 then
                        Expect.pass

                    else
                        GF.inv (GF.inv n)
                            |> Expect.equal n
            , Test.fuzz2 uint8 uint8 "div is inverse of mul (except 0)" <|
                \a b ->
                    if a == 0 || b == 0 then
                        Expect.pass

                    else
                        GF.div (GF.mul a b) b
                            |> Expect.equal a
            , Test.fuzz2 uint8 uint8 "mul is inverse of div (except 0)" <|
                \a b ->
                    if a == 0 || b == 0 then
                        Expect.pass

                    else
                        GF.mul (GF.div a b) b
                            |> Expect.equal a
            , Test.describe "mul"
                [ Test.test "20 * 20 == 11" <| \() -> GF.mul 20 20 |> Expect.equal 11
                , Test.test "21 * 20 == 31" <| \() -> GF.mul 21 20 |> Expect.equal 31
                , Test.test "90 * 21 == 254" <| \() -> GF.mul 90 21 |> Expect.equal 254
                , Test.test "133 * 5 == 167" <| \() -> GF.mul 133 5 |> Expect.equal 167
                , Test.test "0 * 21 == 0" <| \() -> GF.mul 0 21 |> Expect.equal 0
                , Test.test "0xB6 * 0x53 == 0x36" <| \() -> GF.mul 0xB6 0x53 |> Expect.equal 0x36
                , Test.fuzz2 uint8 uint8 "Commutativity (except 0)" <|
                    \a b ->
                        if a == 0 || b == 0 then
                            Expect.pass

                        else
                            GF.mul a b
                                |> Expect.equal (GF.mul b a)
                ]
            , Test.describe "div"
                [ Test.test "20 / 20 == 1" <| \() -> GF.div 20 20 |> Expect.equal 1
                , Test.test "21 / 20 == 152" <| \() -> GF.div 21 20 |> Expect.equal 152
                , Test.test "20 / 21 == 42" <| \() -> GF.div 20 21 |> Expect.equal 42
                , Test.test "90 / 21 == 189" <| \() -> GF.div 90 21 |> Expect.equal 189
                , Test.test "6 / 55 == 151" <| \() -> GF.div 6 55 |> Expect.equal 151
                , Test.test "22 / 192 == 138" <| \() -> GF.div 22 192 |> Expect.equal 138
                , Test.test "0 / 192 == 0" <| \() -> GF.div 0 192 |> Expect.equal 0
                ]
            , Test.describe "interpolate"
                [ Test.test "(1,2),(2,3),(3,4) -> (0,5)" <|
                    \() ->
                        GF.interpolate [ ( 1, 2 ), ( 2, 3 ), ( 3, 4 ) ]
                            |> Expect.equal 5
                , Test.test "(1,2),(10,3),(20,4) -> (0,212)" <|
                    \() ->
                        GF.interpolate [ ( 1, 2 ), ( 10, 3 ), ( 20, 4 ) ]
                            |> Expect.equal 212
                , Test.test "(1,1),(2,2),(3,3) -> (0,0)" <|
                    \() ->
                        GF.interpolate [ ( 1, 1 ), ( 2, 2 ), ( 3, 3 ) ]
                            |> Expect.equal 0
                , Test.test "(1,80),(2,90),(3,20) -> (0,30)" <|
                    \() ->
                        GF.interpolate [ ( 1, 80 ), ( 2, 90 ), ( 3, 20 ) ]
                            |> Expect.equal 30
                , Test.test "(1,43),(2,22),(3,86) -> (0,107)" <|
                    \() ->
                        GF.interpolate [ ( 1, 43 ), ( 2, 22 ), ( 3, 86 ) ]
                            |> Expect.equal 107
                ]
            ]
        , Test.describe "Polynomial"
            [ Test.test "1 + 2*x^2 + 3*x^3 at x=2 == 17" <|
                \() ->
                    GFP.evalAt 2 [ 1, 0, 2, 3 ]
                        |> Expect.equal 17
            ]
        , Test.describe "Secret"
            [ Test.test "Usage example (string)" <|
                \() ->
                    let
                        secret : String
                        secret =
                            "Hello there!"

                        allKeys : Result Secret.EncryptError (List Key)
                        allKeys =
                            Secret.encryptString
                                { seed = Random.initialSeed 0
                                , parts = 5
                                , minPartsNeeded = 3
                                }
                                secret
                    in
                    case allKeys of
                        Err _ ->
                            Expect.ok allKeys

                        Ok keys ->
                            let
                                onlySomeKeys : List Key
                                onlySomeKeys =
                                    List.drop 2 keys

                                decryptedSecret : Result Secret.DecryptError String
                                decryptedSecret =
                                    Secret.decryptString onlySomeKeys
                            in
                            decryptedSecret
                                |> Expect.equal (Ok secret)
            , Test.test "Usage example (bytes)" <|
                \() ->
                    let
                        secret : Bytes
                        secret =
                            [ 0, 10, 20, 30, 40, 50, 100, 200 ]
                                |> Bytes.fromByteValues

                        allKeys : Result Secret.EncryptError (List Key)
                        allKeys =
                            Secret.encryptBytes
                                { seed = Random.initialSeed 0
                                , parts = 5
                                , minPartsNeeded = 3
                                }
                                secret
                    in
                    case allKeys of
                        Err _ ->
                            Expect.ok allKeys

                        Ok keys ->
                            let
                                onlySomeKeys : List Key
                                onlySomeKeys =
                                    List.drop 2 keys

                                decryptedSecret : Result Secret.DecryptError Bytes
                                decryptedSecret =
                                    Secret.decryptBytes onlySomeKeys
                            in
                            decryptedSecret
                                |> expectBytes_ (Ok secret)
            , Test.fuzz Fuzz.string "Any string can be encrypted and decrypted" stringRoundtrip
            , Test.fuzz nonemptyBytes "Any nonempty bytes can be encrypted and decrypted" bytesRoundtrip
            , Test.fuzz2 partsAndMin nonemptyBytes "Any number of keys >= minPartsNeeded decrypts" <|
                \{ parts, minPartsNeeded } secret ->
                    let
                        allKeys : Result Secret.EncryptError (List Key)
                        allKeys =
                            Secret.encryptBytes
                                { seed = Random.initialSeed 0
                                , parts = parts
                                , minPartsNeeded = minPartsNeeded
                                }
                                secret
                    in
                    case allKeys of
                        Err _ ->
                            Expect.ok allKeys

                        Ok keys ->
                            let
                                allKeysCombinations : List (List Key)
                                allKeysCombinations =
                                    keys
                                        |> List.subsequences
                                        |> List.filter (\seq -> List.length seq >= minPartsNeeded)
                            in
                            secret
                                |> Expect.all
                                    (allKeysCombinations
                                        |> List.map
                                            (\keysCombination _ ->
                                                Secret.decryptBytes keysCombination
                                                    |> expectBytes_ (Ok secret)
                                            )
                                    )
            , Test.fuzz (Fuzz.intRange 0 1) "At least 2 parts must be required to decrypt" <|
                \minPartsNeeded ->
                    Secret.encryptString
                        { seed = Random.initialSeed 0
                        , parts = minPartsNeeded + 1
                        , minPartsNeeded = minPartsNeeded
                        }
                        ""
                        |> Expect.equal (Err Secret.TooFewPartsNeeded)
            , Test.fuzz (Fuzz.intRange 2 255) "Parts must >= minPartsNeeded" <|
                \minPartsNeeded ->
                    Secret.encryptString
                        { seed = Random.initialSeed 0
                        , parts = minPartsNeeded - 1
                        , minPartsNeeded = minPartsNeeded
                        }
                        ""
                        |> Expect.equal (Err Secret.MorePartsNeededThanAvailable)
            , Test.fuzz (Fuzz.intRange 256 1000) "Parts must <= 255" <|
                \parts ->
                    Secret.encryptString
                        { seed = Random.initialSeed 0
                        , parts = parts
                        , minPartsNeeded = 3
                        }
                        ""
                        |> Expect.equal (Err Secret.TooManyParts)
            , Test.test "Non-empty secret required" <|
                \() ->
                    Secret.encryptBytes
                        { seed = Random.initialSeed 0
                        , parts = 5
                        , minPartsNeeded = 3
                        }
                        Bytes.empty
                        |> Expect.equal (Err Secret.NoSecret)
            , Test.test "Some keys must be provided" <|
                \() ->
                    Secret.decryptString []
                        |> Expect.equal (Err Secret.NoKeysProvided)
            ]
        ]


bytesRoundtrip : Bytes -> Expectation
bytesRoundtrip secret =
    let
        allKeys : Result Secret.EncryptError (List Key)
        allKeys =
            Secret.encryptBytes
                { seed = Random.initialSeed 0
                , parts = 5
                , minPartsNeeded = 3
                }
                secret
    in
    case allKeys of
        Err _ ->
            Expect.ok allKeys

        Ok keys ->
            let
                decryptedSecret : Result Secret.DecryptError Bytes
                decryptedSecret =
                    Secret.decryptBytes keys
            in
            decryptedSecret
                |> expectBytes_ (Ok secret)


stringRoundtrip : String -> Expectation
stringRoundtrip secret =
    let
        allKeys : Result Secret.EncryptError (List Key)
        allKeys =
            Secret.encryptString
                { seed = Random.initialSeed 0
                , parts = 5
                , minPartsNeeded = 3
                }
                secret
    in
    case allKeys of
        Err _ ->
            Expect.ok allKeys

        Ok keys ->
            let
                decryptedSecret : Result Secret.DecryptError String
                decryptedSecret =
                    Secret.decryptString keys
            in
            decryptedSecret
                |> Expect.equal (Ok secret)
