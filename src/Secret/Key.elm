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

In case you want to create these by hand, note the integers in the list must be
in the 0-255 range, and the first integer in the tuple must be greater than 0.

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
