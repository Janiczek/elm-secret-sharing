module Secret.Key exposing (Key, fromList, toList)

{-|

@docs Key, fromList, toList

-}

import Secret.Key.Internal as Internal


type alias Key =
    Internal.Key


fromList : ( Int, List Int ) -> Key
fromList key =
    Internal.Key key


toList : Key -> ( Int, List Int )
toList (Internal.Key key) =
    key
