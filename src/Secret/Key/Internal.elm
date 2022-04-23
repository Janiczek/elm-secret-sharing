module Secret.Key.Internal exposing (Key(..), length, pointAtIndex)


type Key
    = Key ( Int, List Int )


length : Key -> Int
length (Key ( _, key )) =
    List.length key


pointAtIndex : Int -> Key -> ( Int, Int )
pointAtIndex i (Key ( x, key )) =
    ( x
    , key
        |> List.drop i
        |> List.head
        |> Maybe.withDefault -1
    )
