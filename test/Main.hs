module Main where

import Test.Tasty
import Web.OAuth2.AuthorizeCallbackSpec qualified
import Web.OAuth2.AuthorizeSpec qualified
import Web.OAuth2.FlowSpec qualified
import Web.OAuth2.MetadataSpec qualified
import Web.OAuth2.RegisterSpec qualified
import Web.OAuth2.TokenSpec qualified

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
    testGroup
        "OAuth Tests"
        [ Web.OAuth2.MetadataSpec.tests
        , Web.OAuth2.RegisterSpec.tests
        , Web.OAuth2.AuthorizeSpec.tests
        , Web.OAuth2.AuthorizeCallbackSpec.tests
        , Web.OAuth2.TokenSpec.tests
        , Web.OAuth2.FlowSpec.tests
        ]
