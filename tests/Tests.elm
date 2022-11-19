module Tests exposing (suite)

import Bytes exposing (Bytes)
import Bytes.Extra as Bytes
import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer)
import GF256 as GF
import GF256.Polynomial as GFP
import List.Extra as List
import Random
import Secret
import Secret.Key exposing (Key)
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
    {- The max number of parts allowed by the library is 255.

       There would be combinatorial explosion in some tests later when
       generating all permitted key combinations, so we're limiting the parts
       in this fuzzer to 10. That gives at max 2^10 = 1024 combinations to
       try.
    -}
    Fuzz.intRange 2 10
        |> Fuzz.andThen
            (\parts ->
                Fuzz.intRange 2 parts
                    |> Fuzz.map
                        (\minPartsNeeded ->
                            { parts = parts
                            , minPartsNeeded = minPartsNeeded
                            }
                        )
            )


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
                    in
                    secret
                        |> Secret.encryptString
                            { seed = Random.initialSeed 0
                            , parts = 5
                            , minPartsNeeded = 3
                            }
                        |> Result.map Tuple.first
                        |> Result.withDefault []
                        |> List.drop 2
                        |> Secret.decryptString
                        |> Expect.equal (Ok secret)
            , Test.test "Usage example (bytes)" <|
                \() ->
                    let
                        secret : Bytes
                        secret =
                            [ 0, 10, 20, 30, 40, 50, 100, 200 ]
                                |> Bytes.fromByteValues
                    in
                    secret
                        |> Secret.encryptBytes
                            { seed = Random.initialSeed 0
                            , parts = 5
                            , minPartsNeeded = 3
                            }
                        |> Result.map Tuple.first
                        |> Result.withDefault []
                        |> List.drop 2
                        |> Secret.decryptBytes
                        |> expectBytes_ (Ok secret)
            , Test.fuzz Fuzz.string "Any string can be encrypted and decrypted" stringRoundtrip
            , Test.fuzz nonemptyBytes "Any nonempty bytes can be encrypted and decrypted" bytesRoundtrip
            , Test.fuzz (Fuzz.intRange 0 Random.maxInt) "Works with any seed" <|
                \seedInt ->
                    let
                        secret : String
                        secret =
                            "Hello world!"
                    in
                    secret
                        |> Secret.encryptString
                            { seed = Random.initialSeed seedInt
                            , parts = 5
                            , minPartsNeeded = 3
                            }
                        |> Result.map Tuple.first
                        |> Result.withDefault []
                        |> Secret.decryptString
                        |> Expect.equal (Ok secret)
            , Test.fuzz partsAndMin "Any number of keys >= minPartsNeeded decrypts" <|
                \{ parts, minPartsNeeded } ->
                    let
                        secret : String
                        secret =
                            "hello"

                        allKeys : List Key
                        allKeys =
                            secret
                                |> Secret.encryptString
                                    { seed = Random.initialSeed 0
                                    , parts = parts
                                    , minPartsNeeded = minPartsNeeded
                                    }
                                |> Result.map Tuple.first
                                |> Result.withDefault []

                        allKeysCombinations : List (List Key)
                        allKeysCombinations =
                            allKeys
                                |> List.subsequences
                                |> List.filter (\seq -> List.length seq >= minPartsNeeded)
                    in
                    secret
                        |> Expect.all
                            (allKeysCombinations
                                |> List.map
                                    (\keysCombination _ ->
                                        Secret.decryptString keysCombination
                                            |> Expect.equal (Ok secret)
                                    )
                            )
            , Test.fuzz (Fuzz.intRange 0 Random.maxInt) "Seed gets changed on success" <|
                \seedInt ->
                    let
                        seed : Random.Seed
                        seed =
                            Random.initialSeed seedInt
                    in
                    "Hello world!"
                        |> Secret.encryptString
                            { seed = seed
                            , parts = 5
                            , minPartsNeeded = 3
                            }
                        |> Result.map Tuple.second
                        |> Expect.notEqual (Ok seed)
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
            , Test.test "Keys must be the same length" <|
                \() ->
                    Secret.decryptString
                        [ Secret.Key.fromList ( 1, [] )
                        , Secret.Key.fromList ( 2, [ 1 ] )
                        ]
                        |> Expect.equal (Err Secret.KeysNotSameLength)
            ]
        , Test.describe "Secret.Key"
            [ Test.fuzz keyPrimitiveFuzzer "roundtrip" <|
                \key ->
                    key
                        |> Secret.Key.fromList
                        |> Secret.Key.toList
                        |> Expect.equal key
            ]
        ]


keyPrimitiveFuzzer : Fuzzer ( Int, List Int )
keyPrimitiveFuzzer =
    Fuzz.pair Fuzz.int (Fuzz.list Fuzz.int)


bytesRoundtrip : Bytes -> Expectation
bytesRoundtrip secret =
    secret
        |> Secret.encryptBytes
            { seed = Random.initialSeed 0
            , parts = 5
            , minPartsNeeded = 3
            }
        |> Result.map Tuple.first
        |> Result.withDefault []
        |> Secret.decryptBytes
        |> expectBytes_ (Ok secret)


stringRoundtrip : String -> Expectation
stringRoundtrip secret =
    secret
        |> Secret.encryptString
            { seed = Random.initialSeed 0
            , parts = 5
            , minPartsNeeded = 3
            }
        |> Result.map Tuple.first
        |> Result.withDefault []
        |> Secret.decryptString
        |> Expect.equal (Ok secret)
