{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.OAuth2.AuthorizeSpec (tests) where

import Control.Concurrent.MVar (MVar)
import Data.Aeson (eitherDecode)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Network.HTTP.Types (hContentType, status200, status303, status400, status401)
import Network.HTTP.Types.URI (renderQuery)
import Network.Wai (Application)
import Network.Wai.Test
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth2.TestUtils
import Web.OAuth2.Types hiding (error)
import Web.OAuth2.Types qualified as OAuthTypes

tests :: TestTree
tests =
  testGroup
    "Authorize endpoint"
    [ rejectsUnknownClient
    , rejectsMismatchedRedirect
    , rejectsInvalidScope
    , rendersLoginFormWithPkce
    , echoesErrorMessage
    , omitsStateHiddenFieldWhenAbsent
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
    errResp <- reconstructError (simpleBody res)
    OAuthTypes.error errResp @?= "unauthorized_client"

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
    errResp <- reconstructError (simpleBody res)
    OAuthTypes.error errResp @?= "unauthorized_client"

rejectsInvalidScope :: TestTree
rejectsInvalidScope = testCase "redirects with invalid_scope when request exceeds client allow list" $
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
    simpleStatus res @?= status303
    case lookup "Location" (simpleHeaders res) of
      Nothing -> assertFailure "Location header missing on invalid scope redirect"
      Just loc -> do
        let locText = TE.decodeUtf8 loc
        assertBool "redirect URI preserved" ("http://localhost:4000/callback" `T.isPrefixOf` locText)
        assertBool "invalid_scope error included" ("error=invalid_scope" `T.isInfixOf` locText)
        assertBool "state propagated" ("state=s" `T.isInfixOf` locText)

omitsStateHiddenFieldWhenAbsent :: TestTree
omitsStateHiddenFieldWhenAbsent = testCase "does not propagate state when request omitted it" $
  withApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "cid-5" ["http://localhost:4000/cb"] "read")
    let query =
          [ ("response_type", Just "code")
          , ("client_id", Just "cid-5")
          , ("redirect_uri", Just "http://localhost:4000/cb")
          , ("scope", Just "read")
          ]
        path = BS.concat ["/authorize", renderQuery True query]
    res <-
      runSession
        (srequest (SRequest (setPath defaultRequest path) LBS.empty))
        app
    simpleStatus res @?= status200
    let bodyTxt = LBS.toStrict (simpleBody res)
    assertBool "state input absent" (not ("name=\"state\"" `BS.isInfixOf` bodyTxt))

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
    OAuthTypes.error errResp @?= "invalid_request"

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
