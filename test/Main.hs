module Main where

import Test.Tasty
import qualified Web.OAuth.AuthorizeCallbackSpec
import qualified Web.OAuth.AuthorizeSpec
import qualified Web.OAuth.FlowSpec
import qualified Web.OAuth.MetadataSpec
import qualified Web.OAuth.RegisterSpec
import qualified Web.OAuth.TokenSpec

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "OAuth Tests"
    [ Web.OAuth.MetadataSpec.tests
    , Web.OAuth.RegisterSpec.tests
    , Web.OAuth.AuthorizeSpec.tests
    , Web.OAuth.AuthorizeCallbackSpec.tests
    , Web.OAuth.TokenSpec.tests
    , Web.OAuth.FlowSpec.tests
    ]
