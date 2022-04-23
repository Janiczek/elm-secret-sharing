module Secret exposing
    ( encryptBytes, encryptString, EncryptError(..)
    , Key
    , decryptBytes, decryptString, DecryptError(..)
    )

{-|

@docs encryptBytes, encryptString, EncryptError
@docs Key
@docs decryptBytes, decryptString, DecryptError

-}

import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as Decode exposing (Decoder)
import Bytes.Encode as Encode exposing (Encoder)
import Bytes.Extra as Bytes
import GF256 as GF
import GF256.Polynomial as GFP exposing (Polynomial)
import List.Extra as List
import Random exposing (Generator)



-- KEY


type Key
    = Key ( Int, List Int )


keyLength : Key -> Int
keyLength (Key ( _, key )) =
    List.length key


pointAtIndex : Int -> Key -> ( Int, Int )
pointAtIndex i (Key ( x, key )) =
    ( x
    , key
        |> List.drop i
        |> List.head
        |> Maybe.withDefault -1
    )



-- POLYNOMIAL HELPERS


secretPolynomial :
    { degree : Int
    , pointToHide : Int
    }
    -> Generator Polynomial
secretPolynomial { degree, pointToHide } =
    GFP.generator { degree = degree }
        |> Random.map (GFP.setYIntercept pointToHide)



-- ENCRYPT


type EncryptError
    = TooFewPartsNeeded
    | TooManyParts
    | MorePartsNeededThanAvailable
    | NoSecret


encryptBytes :
    { seed : Random.Seed
    , parts : Int
    , minPartsNeeded : Int
    }
    -> Bytes
    -> Result EncryptError (List Key)
encryptBytes c secret =
    if Bytes.width secret == 0 then
        Err NoSecret

    else if c.minPartsNeeded < 2 then
        Err TooFewPartsNeeded

    else if c.minPartsNeeded > c.parts then
        Err MorePartsNeededThanAvailable

    else if c.parts > 255 then
        Err TooManyParts

    else
        secret
            |> Bytes.toByteValues
            |> List.foldl
                (\secretByte ( accSeed, accValues ) ->
                    let
                        ( polynomial, newSeed ) =
                            Random.step
                                (secretPolynomial
                                    { degree = c.minPartsNeeded - 1
                                    , pointToHide = secretByte
                                    }
                                )
                                accSeed
                    in
                    ( newSeed
                    , (List.range 1 c.parts
                        -- starting at x=1 is important
                        |> List.map (\x -> GFP.evalAt x polynomial)
                      )
                        :: accValues
                    )
                )
                ( c.seed, [] )
            |> Tuple.second
            |> List.transpose
            |> List.map List.reverse
            |> List.indexedMap (\i key -> Key ( i + 1, key ))
            |> Ok


{-| Encrypts the string.

Compared to `encryptBytes`, adds one extra 32bit integer at the beginning, saying
how many UTF-8 bytes the string has (for easier decoding).

-}
encryptString :
    { seed : Random.Seed
    , parts : Int
    , minPartsNeeded : Int
    }
    -> String
    -> Result EncryptError (List Key)
encryptString c secret =
    encryptBytes c (Encode.encode (sizedStringEncoder secret))


sizedStringEncoder : String -> Encoder
sizedStringEncoder str =
    Encode.sequence
        [ Encode.unsignedInt32 BE (Encode.getStringWidth str)
        , Encode.string str
        ]



-- DECRYPT


type DecryptError
    = NoKeysProvided
    | KeysNotSameLength
    | NotAnUtf8String


decryptBytes : List Key -> Result DecryptError Bytes
decryptBytes keys =
    case keys of
        [] ->
            Err NoKeysProvided

        first :: rest ->
            let
                keyCount : Int
                keyCount =
                    List.length keys

                firstKeyLength : Int
                firstKeyLength =
                    keyLength first
            in
            if List.any (\key -> keyLength key /= firstKeyLength) keys then
                Err KeysNotSameLength

            else
                List.range 0 (firstKeyLength - 1)
                    |> List.map
                        (\i ->
                            keys
                                |> List.map (pointAtIndex i)
                                |> GF.interpolate
                        )
                    |> Bytes.fromByteValues
                    |> Ok


{-| Decrypts the string.

Compared to `decryptBytes`, requires one extra 32bit integer at the beginning,
saying how many UTF-8 bytes the string has.

-}
decryptString : List Key -> Result DecryptError String
decryptString keys =
    decryptBytes keys
        |> Result.andThen decodeSizedString


decodeSizedString : Bytes -> Result DecryptError String
decodeSizedString bytes =
    bytes
        |> Decode.decode sizedStringDecoder
        |> Result.fromMaybe NotAnUtf8String


sizedStringDecoder : Decoder String
sizedStringDecoder =
    Decode.unsignedInt32 BE
        |> Decode.andThen Decode.string
