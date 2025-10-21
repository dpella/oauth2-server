{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Web.OAuth.TokenSpec (tests) where

import Control.Concurrent.MVar (MVar, readMVar)
import Data.Aeson (eitherDecode)
import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Time.Clock
import Network.HTTP.Types (hContentType, methodPost, status400, status401)
import Network.Wai (Application, requestHeaders, requestMethod)
import Network.Wai.Test
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth.TestUtils
import Web.OAuth.Types

tests :: TestTree
tests =
  testGroup
    "Token endpoint"
    [ rejectsMissingVerifier
    , rejectsInvalidVerifier
    , rejectsExpiredAuthCode
    , confidentialClientsRequireSecret
    , rejectsUnknownRefreshToken
    , rejectsRefreshScopeEscalation
    ]

withFreshApp :: (MVar (OAuthState TestUser) -> Application -> IO a) -> IO a
withFreshApp action = do
  (stateVar, _ctx, app) <- createTestApplication
  action stateVar app

decodeOAuthError :: LBS.ByteString -> IO OAuthError
decodeOAuthError body =
  case eitherDecode body of
    Left err -> assertFailure ("Failed to decode OAuthError: " <> err)
    Right val -> pure val

postToken :: Application -> LBS.ByteString -> IO SResponse
postToken app body = do
  let req =
        SRequest
          ( setPath defaultRequest "/token"
              ){ requestMethod = methodPost
               , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
               }
          body
  runSession (srequest req) app

mkAuthCode
  :: Text
  -> Text
  -> Text
  -> Text
  -> UTCTime
  -> Maybe Text
  -> Maybe Text
  -> AuthCode TestUser
mkAuthCode value clientId redirect scope expiry challenge method =
  AuthCode
    { auth_code_value = value
    , auth_code_client_id = clientId
    , auth_code_user = testUser
    , auth_code_redirect_uri = redirect
    , auth_code_scope = scope
    , auth_code_expiry = expiry
    , auth_code_challenge = challenge
    , auth_code_challenge_method = method
    }

rejectsMissingVerifier :: TestTree
rejectsMissingVerifier = testCase "enforces PKCE code_verifier when challenge stored" $
  withFreshApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "pub-1" ["http://localhost:4000/cb"] "read write")
    now <- getCurrentTime
    let code = mkAuthCode "code-pkce" "pub-1" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "challenge") (Just "plain")
    addAuthCodeToState stateVar code
    res <-
      postToken
        app
        ( encodeForm
            [ ("grant_type", "authorization_code")
            , ("code", "code-pkce")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("client_id", "pub-1")
            ]
        )
    simpleStatus res @?= status400
    errResp <- decodeOAuthError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_request"

rejectsInvalidVerifier :: TestTree
rejectsInvalidVerifier = testCase "rejects mismatched code_verifier" $
  withFreshApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "pub-2" ["http://localhost:4000/cb"] "read")
    now <- getCurrentTime
    let code = mkAuthCode "code-wrong" "pub-2" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "correct") (Just "plain")
    addAuthCodeToState stateVar code
    res <-
      postToken
        app
        ( encodeForm
            [ ("grant_type", "authorization_code")
            , ("code", "code-wrong")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("client_id", "pub-2")
            , ("code_verifier", "incorrect")
            ]
        )
    simpleStatus res @?= status400
    errResp <- decodeOAuthError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_grant"
    Web.OAuth.Types.error_description errResp @?= Just "Invalid code verifier"

rejectsExpiredAuthCode :: TestTree
rejectsExpiredAuthCode = testCase "rejects expired authorization codes" $
  withFreshApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "pub-3" ["http://localhost:4000/cb"] "read")
    now <- getCurrentTime
    let code = mkAuthCode "code-expired" "pub-3" "http://localhost:4000/cb" "read" (addUTCTime (-30) now) (Just "verifier") (Just "plain")
    addAuthCodeToState stateVar code
    res <-
      postToken
        app
        ( encodeForm
            [ ("grant_type", "authorization_code")
            , ("code", "code-expired")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("client_id", "pub-3")
            , ("code_verifier", "verifier")
            ]
        )
    simpleStatus res @?= status400
    errResp <- decodeOAuthError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_grant"
    Web.OAuth.Types.error_description errResp @?= Just "Authorization code expired"

confidentialClientsRequireSecret :: TestTree
confidentialClientsRequireSecret = testCase "confidential clients must provide client_secret" $
  withFreshApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkConfidentialClient "conf-1" "top-secret" ["http://localhost:4000/cb"] "read")
    now <- getCurrentTime
    let code = mkAuthCode "code-conf" "conf-1" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "secret") Nothing
    addAuthCodeToState stateVar code
    res <-
      postToken
        app
        ( encodeForm
            [ ("grant_type", "authorization_code")
            , ("code", "code-conf")
            , ("redirect_uri", "http://localhost:4000/cb")
            , ("client_id", "conf-1")
            , ("code_verifier", "secret")
            ]
        )
    simpleStatus res @?= status401
    errResp <- decodeOAuthError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_client"
    st <- readMVar stateVar
    Map.member "code-conf" (auth_codes st) @?= True

rejectsUnknownRefreshToken :: TestTree
rejectsUnknownRefreshToken = testCase "rejects refresh_token grant when token missing" $
  withFreshApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "pub-4" ["http://localhost:4000/cb"] "read")
    res <-
      postToken
        app
        ( encodeForm
            [ ("grant_type", "refresh_token")
            , ("refresh_token", "does-not-exist")
            , ("client_id", "pub-4")
            ]
        )
    simpleStatus res @?= status400
    errResp <- decodeOAuthError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_grant"

rejectsRefreshScopeEscalation :: TestTree
rejectsRefreshScopeEscalation = testCase "rejects refresh token with scope outside client allowance" $
  withFreshApp $ \stateVar app -> do
    addRegisteredClientToState stateVar (mkPublicClient "pub-5" ["http://localhost:4000/cb"] "read")
    let refreshTok =
          RefreshToken
            { refresh_token_value = "rt-1"
            , refresh_token_client_id = "pub-5"
            , refresh_token_user = testUser
            , refresh_token_scope = "write"
            }
    addRefreshTokenToState stateVar refreshTok
    res <-
      postToken
        app
        ( encodeForm
            [ ("grant_type", "refresh_token")
            , ("refresh_token", "rt-1")
            , ("client_id", "pub-5")
            ]
        )
    simpleStatus res @?= status400
    errResp <- decodeOAuthError (simpleBody res)
    Web.OAuth.Types.error errResp @?= "invalid_scope"
