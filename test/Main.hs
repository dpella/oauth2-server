module Main where

import qualified Web.OAuth.FlowSpec
import Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "OAuth Tests"
    [ Web.OAuth.FlowSpec.tests
    ]
