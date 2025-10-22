{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Web.OAuth.AuthorizeCallbackSpec (tests) where

import Control.Concurrent.MVar (MVar, readMVar)
import Data.Aeson (eitherDecode)
import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Network.HTTP.Types (hContentType, hLocation, methodPost, status303, status400)
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
    , rejectsTamperedRedirectUri
    , rejectsInvalidScope
    , rejectsMissingPkce
    , successfulLoginWithoutStateSkipsEcho
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
        assertBool "redirected to authorize" ("authorize" `T.isPrefixOf` locText)
        assertBool "state preserved" ("state=orig-state" `T.isInfixOf` locText)
        assertBool "error flag propagated" ("error=invalid_password" `T.isInfixOf` locText)

    st <- readMVar stateVar
    Map.size (auth_codes st) @?= 0

rejectsTamperedRedirectUri :: TestTree
rejectsTamperedRedirectUri = testCase "rejects redirect_uri not registered for client" $
  withApp $ \stateVar app -> do
    let formBody =
          encodeForm
            [ ("username", "testuser")
            , ("password", "testpass")
            , ("client_id", "client-1")
            , ("redirect_uri", "https://attacker.invalid/cb")
            , ("scope", "read")
            , ("state", "state-1")
            , ("code_challenge", "challenge")
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
    simpleStatus res @?= status400
    lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
    err <- decodeError (simpleBody res)
    Web.OAuth.Types.error err @?= "unauthorized_client"
    st <- readMVar stateVar
    Map.size (auth_codes st) @?= 0

rejectsInvalidScope :: TestTree
rejectsInvalidScope = testCase "rejects scope escalation attempts" $
  withApp $ \stateVar app -> do
    let formBody =
          encodeForm
            [ ("username", "testuser")
            , ("password", "testpass")
            , ("client_id", "client-1")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("scope", "admin")
            , ("state", "state-2")
            , ("code_challenge", "challenge")
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
    simpleStatus res @?= status400
    lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
    err <- decodeError (simpleBody res)
    Web.OAuth.Types.error err @?= "invalid_scope"
    st <- readMVar stateVar
    Map.size (auth_codes st) @?= 0

rejectsMissingPkce :: TestTree
rejectsMissingPkce = testCase "rejects requests missing PKCE code_challenge" $
  withApp $ \stateVar app -> do
    let formBody =
          encodeForm
            [ ("username", "testuser")
            , ("password", "testpass")
            , ("client_id", "client-1")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("scope", "read")
            , ("state", "state-3")
            ]
        req =
          SRequest
            ( setPath defaultRequest "/authorize/callback"
                ){ requestMethod = methodPost
                 , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
                 }
            formBody
    res <- runSession (srequest req) app
    simpleStatus res @?= status400
    lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
    err <- decodeError (simpleBody res)
    Web.OAuth.Types.error err @?= "invalid_request"
    st <- readMVar stateVar
    Map.size (auth_codes st) @?= 0

successfulLoginWithoutStateSkipsEcho :: TestTree
successfulLoginWithoutStateSkipsEcho = testCase "does not add state parameter when none provided" $
  withApp $ \stateVar app -> do
    let challenge = "verifier456"
        formBody =
          encodeForm
            [ ("username", "testuser")
            , ("password", "testpass")
            , ("client_id", "client-1")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("scope", "read")
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
        assertBool "redirected to provided redirect_uri" ("http://localhost:4000/cb" `T.isPrefixOf` locText)
        assertBool "state parameter absent" (not ("state=" `T.isInfixOf` locText))
    st <- readMVar stateVar
    Map.size (auth_codes st) @?= 1

decodeError :: LBS.ByteString -> IO OAuthError
decodeError body =
  case eitherDecode body of
    Left msg -> assertFailure ("Failed to decode OAuth error: " <> msg)
    Right v -> pure v
