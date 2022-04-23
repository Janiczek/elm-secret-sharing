# elm-secret-sharing

An implementation of [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing): your secret is encrypted into `N` keys, of which only `K` are needed to reconstruct the original secret.

Port of [`simbo1905/shamir`](https://github.com/simbo1905/shamir).

Example usage:
```elm
secret : String
secret =
    "Hello there!"

allKeys : Result Secret.EncryptError (List Key)
allKeys =
    Secret.encryptString
        -- Don't use a static seed in production!
        { seed = Random.initialSeed 0
        , parts = 5
        , minPartsNeeded = 3
        }
        secret

onlySomeKeys : List Key
onlySomeKeys =
    allKeys
        |> Result.withDefault []
        |> List.drop 2

decryptedSecret : Result Secret.DecryptError String
decryptedSecret =
    Secret.decryptString onlySomeKeys

-- decryptedSecret == Ok secret
```

## Advanced usage:

It's possible to have a tiered sharing: let's say you want to have admin keys and
user keys; allowing either two admin keys or one admin key and three user keys to
recover the secret.

For more info check [this link](https://github.com/simbo1905/shamir#tiered-sharing-java).
