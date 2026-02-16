module Main where

import Test.Tasty
import qualified Web.OAuth2.AuthorizeCallbackSpec
import qualified Web.OAuth2.AuthorizeSpec
import qualified Web.OAuth2.FlowSpec
import qualified Web.OAuth2.MetadataSpec
import qualified Web.OAuth2.RegisterSpec
import qualified Web.OAuth2.TokenSpec

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
