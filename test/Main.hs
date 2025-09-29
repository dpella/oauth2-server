module Main where

import qualified OAuth.FlowSpec
import Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "OAuth Tests"
    [ OAuth.FlowSpec.tests
    ]
