module Secret exposing
    ( encryptBytes, encryptString, EncryptError(..)
    , decryptBytes, decryptString, DecryptError(..)
    )

{-| An implementation of [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing):
your secret is encrypted into `N` keys, of which only `K` are needed to
reconstruct the original secret.

Check the README for tips on usage!


# Encrypt

@docs encryptBytes, encryptString, EncryptError


# Decrypt

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
import Secret.Key.Internal as Key exposing (Key(..))



-- ENCRYPT


{-| These validation rules are in effect:

  - 2-255 parts must be generated
  - 2+ parts must be needed
  - there cannot be more parts needed than available
  - secret must be non-empty Bytes (Strings can be empty)

-}
type EncryptError
    = TooFewPartsNeeded
    | TooManyParts
    | MorePartsNeededThanAvailable
    | NoSecret


{-| Allows splitting the Bytes secret to a given number of keys.
-}
encryptBytes :
    { seed : Random.Seed
    , parts : Int
    , minPartsNeeded : Int
    }
    -> Bytes
    -> Result EncryptError ( List Key, Random.Seed )
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
                (\secretByte ( accValues, accSeed ) ->
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
                    ( (List.range 1 c.parts
                        -- starting at x=1 is important
                        |> List.map (\x -> GFP.evalAt x polynomial)
                      )
                        :: accValues
                    , newSeed
                    )
                )
                ( [], c.seed )
            |> Tuple.mapFirst
                (List.transpose
                    >> List.map List.reverse
                    >> List.indexedMap (\i key -> Key ( i + 1, key ))
                )
            |> Ok


{-| Allows splitting the String secret to a given number of keys.

Compared to `encryptBytes`, adds one extra 32bit integer at the beginning, saying
how many UTF-8 bytes the string has. This is required for correct reconstruction
later with `decryptString`.

-}
encryptString :
    { seed : Random.Seed
    , parts : Int
    , minPartsNeeded : Int
    }
    -> String
    -> Result EncryptError ( List Key, Random.Seed )
encryptString c secret =
    encryptBytes c (Encode.encode (sizedStringEncoder secret))


sizedStringEncoder : String -> Encoder
sizedStringEncoder str =
    Encode.sequence
        [ Encode.unsignedInt32 BE (Encode.getStringWidth str)
        , Encode.string str
        ]



-- DECRYPT


{-| The library will fail decrypting if:

  - the keys list is empty
  - keys are not of the same length
  - the secret wasn't an UTF-8 string and you attempted to `decryptString`

-}
type DecryptError
    = NoKeysProvided
    | KeysNotSameLength
    | NotAnUtf8String


{-| Allows deconstructing the Bytes secret from the given keys.
-}
decryptBytes : List Key -> Result DecryptError Bytes
decryptBytes keys =
    case keys of
        [] ->
            Err NoKeysProvided

        first :: _ ->
            let
                firstKeyLength : Int
                firstKeyLength =
                    Key.length first
            in
            if List.any (\key -> Key.length key /= firstKeyLength) keys then
                Err KeysNotSameLength

            else
                List.range 0 (firstKeyLength - 1)
                    |> List.map
                        (\i ->
                            keys
                                |> List.map (Key.pointAtIndex i)
                                |> GF.interpolate
                        )
                    |> Bytes.fromByteValues
                    |> Ok


{-| Allows deconstructing the String secret from the given keys.

Compared to `decryptBytes`, requires one extra 32bit integer at the beginning,
saying how many UTF-8 bytes the string has. This is given automatically during
encryption with `encryptString`.

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



-- POLYNOMIAL HELPERS


secretPolynomial :
    { degree : Int
    , pointToHide : Int
    }
    -> Generator Polynomial
secretPolynomial { degree, pointToHide } =
    GFP.generator { degree = degree }
        |> Random.map (GFP.setYIntercept pointToHide)
