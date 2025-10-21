{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Web.OAuth.AuthorizeCallbackSpec (tests) where

import Control.Concurrent.MVar (MVar, readMVar)
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Network.HTTP.Types (hContentType, hLocation, methodPost, status303)
import Network.Wai (Application, requestHeaders, requestMethod)
import Network.Wai.Test
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth.TestUtils
import Web.OAuth.Types

tests :: TestTree
tests =
  testGroup
    "Authorize callback endpoint"
    [ successfulLoginIssuesAuthCode
    , invalidCredentialsRedirectBack
    ]

withApp :: (MVar (OAuthState TestUser) -> Application -> IO a) -> IO a
withApp action = do
  (stateVar, _ctx, app) <- createTestApplication
  addRegisteredClientToState stateVar (mkPublicClient "client-1" ["http://localhost:4000/cb"] "read write")
  action stateVar app

successfulLoginIssuesAuthCode :: TestTree
successfulLoginIssuesAuthCode = testCase "stores auth code and redirects with state" $
  withApp $ \stateVar app -> do
    now <- getCurrentTime
    let challenge = "verifier123"
        formBody =
          encodeForm
            [ ("username", "testuser")
            , ("password", "testpass")
            , ("client_id", "client-1")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("scope", "read")
            , ("state", "my-state")
            , ("code_challenge", challenge)
            , ("code_challenge_method", "plain")
            ]
        req =
          SRequest
            ( setPath defaultRequest "/authorize/callback"
                ){ requestMethod = methodPost
                 , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
                 }
            formBody
    res <- runSession (srequest req) app
    simpleStatus res @?= status303
    let location = lookup hLocation (simpleHeaders res)
    case location of
      Nothing -> assertFailure "Location header missing"
      Just loc -> do
        let locText = TE.decodeUtf8 loc
        assertBool "state propagated" ("state=my-state" `T.isInfixOf` locText)
        assertBool "authorization code parameter present" ("code=" `T.isInfixOf` locText)

    st <- readMVar stateVar
    let codes = Map.elems (auth_codes st)
    assertBool "auth code stored" (not (null codes))
    let stored = head codes
    auth_code_client_id stored @?= "client-1"
    auth_code_scope stored @?= "read"
    auth_code_challenge stored @?= Just challenge
    auth_code_challenge_method stored @?= Just "plain"
    assertBool "expiry in future" (auth_code_expiry stored > addUTCTime (-1) now)

invalidCredentialsRedirectBack :: TestTree
invalidCredentialsRedirectBack = testCase "redirects back to authorize with error=invalid_password" $
  withApp $ \stateVar app -> do
    let formBody =
          encodeForm
            [ ("username", "testuser")
            , ("password", "wrong")
            , ("client_id", "client-1")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("scope", "read write")
            , ("state", "orig-state")
            , ("code_challenge", "abc")
            , ("code_challenge_method", "S256")
            ]
        req =
          SRequest
            ( setPath defaultRequest "/authorize/callback"
                ){ requestMethod = methodPost
                 , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
                 }
            formBody
    res <- runSession (srequest req) app
    simpleStatus res @?= status303
    let location = lookup hLocation (simpleHeaders res)
    case location of
      Nothing -> assertFailure "Location header missing"
      Just loc -> do
        let locText = TE.decodeUtf8 loc
        assertBool "redirected to authorize" ("/authorize" `T.isPrefixOf` locText)
        assertBool "state preserved" ("state=orig-state" `T.isInfixOf` locText)
        assertBool "error flag propagated" ("error=invalid_password" `T.isInfixOf` locText)

    st <- readMVar stateVar
    Map.size (auth_codes st) @?= 0
