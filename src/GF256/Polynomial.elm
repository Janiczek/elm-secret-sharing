module GF256.Polynomial exposing
    ( Polynomial
    , evalAt
    , generator
    , setYIntercept
    )

import GF256 as GF
import Random exposing (Generator)


{-| A polynomial, in general, is an expression like x^3 + 2 x y z^2 - y z + 1.

In this library we'll only care about polynomials of single variable: x^3 + 2x + 1.
Also, only polynomials over the GF(256) field.

We represent them as a list of coefficients, starting at x^0. So the polynomial above
would be represented by a list [1,2,0,1].

-}
type alias Polynomial =
    List Int


generator : { degree : Int } -> Generator Polynomial
generator c =
    Random.list c.degree (Random.int 0 255)
        |> Random.map (ensureDegree >> List.reverse)


{-| Take a degree in a reversed form and make sure the first coefficient is >0.
-}
ensureDegree : Polynomial -> Polynomial
ensureDegree p =
    case p of
        0 :: rest ->
            1 :: rest

        _ ->
            p


setYIntercept : Int -> Polynomial -> Polynomial
setYIntercept intercept p =
    case p of
        _ :: rest ->
            intercept :: rest

        _ ->
            p


evalAt : Int -> Polynomial -> Int
evalAt point polynomial =
    List.foldr
        (\coef acc -> GF.add (GF.mul acc point) coef)
        0
        polynomial
