{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.OAuth.AuthorizeSpec (tests) where

import Control.Concurrent.MVar (MVar)
import Data.Aeson (eitherDecode)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Network.HTTP.Types (hContentType, status200, status400, status401)
import Network.HTTP.Types.URI (renderQuery)
import Network.Wai (Application)
import Network.Wai.Test
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth.Types
import Web.OAuth.TestUtils

tests :: TestTree
tests =
  testGroup
    "Authorize endpoint"
    [ rejectsUnknownClient
    , rejectsMismatchedRedirect
    , rejectsInvalidScope
    , rendersLoginFormWithPkce
    , echoesErrorMessage
    , missingParametersReturnInvalidRequest
    ]

withApp :: (MVar (OAuthState TestUser) -> Application -> IO a) -> IO a
withApp action = do
  (stateVar, _ctx, app) <- createTestApplication
  action stateVar app

reconstructError :: LBS.ByteString -> IO OAuthError
reconstructError body =
  case eitherDecode body of
    Left err -> assertFailure ("Failed to decode OAuthError: " <> err)
    Right val -> pure val

rejectsUnknownClient :: TestTree
rejectsUnknownClient = testCase "returns 401 for unknown client_id" $
  withApp $ \_ app -> do
    let query =
          [ ("response_type", Just "code")
          , ("client_id", Just "missing-client")
          , ("redirect_uri", Just "http://localhost:4000/cb")
          , ("scope", Just "read")
          , ("state", Just "state-1")
          ]
        path = BS.concat ["/authorize", renderQuery True query]
    res <-
      runSession
        (srequest (SRequest (setPath defaultRequest path) LBS.empty))
        app
    simpleStatus res @?= status401
    lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
    errResp <- reconstructError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "unauthorized_client"

rejectsMismatchedRedirect :: TestTree
rejectsMismatchedRedirect = testCase "400 when redirect_uri not registered" $
  withApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "cid-1" ["http://localhost:4000/callback"] "read write")
    let query =
          [ ("response_type", Just "code")
          , ("client_id", Just "cid-1")
          , ("redirect_uri", Just "http://localhost:4000/evil")
          , ("scope", Just "read")
          , ("state", Just "s")
          ]
        path = BS.concat ["/authorize", renderQuery True query]
    res <-
      runSession
        (srequest (SRequest (setPath defaultRequest path) LBS.empty))
        app
    simpleStatus res @?= status400
    lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
    errResp <- reconstructError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "unauthorized_client"

rejectsInvalidScope :: TestTree
rejectsInvalidScope = testCase "400 when scope exceeds client allow list" $
  withApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "cid-2" ["http://localhost:4000/callback"] "read write")
    let query =
          [ ("response_type", Just "code")
          , ("client_id", Just "cid-2")
          , ("redirect_uri", Just "http://localhost:4000/callback")
          , ("scope", Just "admin")
          , ("state", Just "s")
          ]
        path = BS.concat ["/authorize", renderQuery True query]
    res <-
      runSession
        (srequest (SRequest (setPath defaultRequest path) LBS.empty))
        app
    simpleStatus res @?= status400
    lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
    errResp <- reconstructError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_scope"

rendersLoginFormWithPkce :: TestTree
rendersLoginFormWithPkce = testCase "renders login form for valid request including PKCE fields" $
  withApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "cid-3" ["http://localhost:4000/cb"] "read write")
    let query =
          [ ("response_type", Just "code")
          , ("client_id", Just "cid-3")
          , ("redirect_uri", Just "http://localhost:4000/cb")
          , ("scope", Just "read write")
          , ("state", Just "xyz")
          , ("code_challenge", Just "pkce-challenge")
          , ("code_challenge_method", Just "S256")
          ]
        path = BS.concat ["/authorize", renderQuery True query]
    res <-
      runSession
        (srequest (SRequest (setPath defaultRequest path) LBS.empty))
        app
    simpleStatus res @?= status200
    let bodyTxt = LBS.toStrict (simpleBody res)
    assertBool "code_challenge field present" ("name=\"code_challenge\"" `BS.isInfixOf` bodyTxt)
    assertBool "code_challenge_method field present" ("name=\"code_challenge_method\"" `BS.isInfixOf` bodyTxt)
    assertBool "state preserved" ("value=\"xyz\"" `BS.isInfixOf` bodyTxt)

echoesErrorMessage :: TestTree
echoesErrorMessage = testCase "renders login form with error message when provided" $
  withApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "cid-4" ["http://localhost:4000/cb"] "read")
    let query =
          [ ("response_type", Just "code")
          , ("client_id", Just "cid-4")
          , ("redirect_uri", Just "http://localhost:4000/cb")
          , ("scope", Just "read")
          , ("state", Just "s")
          , ("error", Just "invalid_password")
          ]
        path = BS.concat ["/authorize", renderQuery True query]
    res <-
      runSession
        (srequest (SRequest (setPath defaultRequest path) LBS.empty))
        app
    simpleStatus res @?= status200
    let bodyTxt = LBS.toStrict (simpleBody res)
    assertBool "error message rendered" ("Invalid username or password" `BS.isInfixOf` bodyTxt)

missingParametersReturnInvalidRequest :: TestTree
missingParametersReturnInvalidRequest = testCase "returns JSON invalid_request when required params absent" $
  withApp $ \_ app -> do
    res <-
      runSession
        (srequest (SRequest (setPath defaultRequest "/authorize") LBS.empty))
        app
    simpleStatus res @?= status400
    lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
    errResp <- reconstructError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_request"
