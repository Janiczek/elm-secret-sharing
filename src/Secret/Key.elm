module Secret.Key exposing (Key, fromList, toList)

{-|

@docs Key, fromList, toList

-}

import Secret.Key.Internal as Internal


{-| A key used to reconstruct the secret.

Can be thought of as a set of points on a given `x = constant` vertical line.

-}
type alias Key =
    Internal.Key


{-| Construct a Key from a list of points on a vertical line.

Mostly useful for deserialization.

-}
fromList : ( Int, List Int ) -> Key
fromList key =
    Internal.Key key


{-| Convert a Key to a list of points on a vertical line.

Mostly useful for serialization.

-}
toList : Key -> ( Int, List Int )
toList (Internal.Key key) =
    key
