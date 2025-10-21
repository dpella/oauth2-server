{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.OAuth.FlowSpec (tests) where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (MonadIO, liftIO)
import Crypto.Hash (Digest, SHA256 (..), hashWith)
import Data.Aeson (Value (..), eitherDecode, object, (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.KeyMap qualified as KM
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as B64URL
import Data.ByteString.Lazy qualified as LBS
import Data.List (find)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromJust, isJust)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Scientific (toBoundedInteger)
import Network.HTTP.Types (hContentType, hLocation, methodPost, status200, status303)
import Network.Wai (requestHeaders, requestMethod)
import Network.Wai.Test
import Web.OAuth (OAuthAPI, oAuthAPI)
import Web.OAuth.TestUtils
import Web.OAuth.Types
import Servant
import Test.Tasty
import Test.Tasty.HUnit

tests :: TestTree
tests = testGroup "OAuth End-to-End Flow" [commonFlow]

commonFlow :: TestTree
commonFlow = testCase "Dynamic registration -> authorize -> token -> refresh" $ do
  -- 1) Fresh state and context
  stateVar <- emptyOAuthState
  ctx <- createTestContext
  let app :: Application
      app = serveWithContext (Proxy :: Proxy OAuthAPI) ctx (oAuthAPI stateVar ctx)

  -- Metadata should report stable issuer/endpoints without duplicating the port.
  metadataValue <-
    runSession
      ( do
          let req = setPath defaultRequest "/.well-known/oauth-authorization-server"
          res <- srequest (SRequest req LBS.empty)
          liftIO $ assertEqual "metadata status" status200 (simpleStatus res)
          case eitherDecode (simpleBody res) :: Either String Value of
            Left e -> abort e
            Right v -> pure v
      )
      app
  metadataObj <-
    case metadataValue of
      Object o -> pure o
      _ -> abort "unexpected metadata response"
  issuerValue <-
    case KM.lookup "issuer" metadataObj of
      Just (String t) -> pure t
      _ -> abort "issuer missing"
  authorizeEndpointValue <-
    case KM.lookup "authorization_endpoint" metadataObj of
      Just (String t) -> pure t
      _ -> abort "authorization_endpoint missing"
  tokenEndpointValue <-
    case KM.lookup "token_endpoint" metadataObj of
      Just (String t) -> pure t
      _ -> abort "token_endpoint missing"
  registerEndpointValue <-
    case KM.lookup "registration_endpoint" metadataObj of
      Just (String t) -> pure t
      _ -> abort "registration_endpoint missing"
  issuerValue @?= "http://localhost:8080"
  authorizeEndpointValue @?= "http://localhost:8080/authorize"
  tokenEndpointValue @?= "http://localhost:8080/token"
  registerEndpointValue @?= "http://localhost:8080/register"

  -- 2) Dynamic client registration (public client with PKCE, allows refresh)
  let redirectUri = "http://localhost:4000/cb"
  regResponsePublic <-
    runSession
      ( do
          let body =
                object
                  [ "client_name" .= ("Test SPA" :: Text)
                  , "redirect_uris" .= [redirectUri]
                  , "grant_types" .= (["authorization_code", "refresh_token"] :: [Text])
                  , "response_types" .= (["code"] :: [Text])
                  , "scope" .= ("read write" :: Text)
                  , "token_endpoint_auth_method" .= ("none" :: Text)
                  ]
              req =
                SRequest
                  (setPath defaultRequest "/register")
                    { requestMethod = methodPost
                    , requestHeaders = [(hContentType, "application/json")]
                    }
                  (Aeson.encode body)
          res <- srequest req
          liftIO $ assertEqual "register status" status200 (simpleStatus res)
          case eitherDecode (simpleBody res) :: Either String Value of
            Left e -> abort e
            Right v -> pure v
      )
      app
  clientId <-
    case regResponsePublic of
      Object o ->
        case KM.lookup "client_id" o of
          Just (String cid) -> pure cid
          _ -> abort "client_id not found"
      _ -> abort "unexpected registration response"
  publicSecret <-
    case regResponsePublic of
      Object o ->
        case KM.lookup "client_secret" o of
          Just Null -> pure Nothing
          Just (String s) -> pure (Just s)
          Nothing -> pure Nothing
          _ -> abort "unexpected client_secret type"
      _ -> abort "unexpected registration response"
  publicSecretExpiry <-
    case regResponsePublic of
      Object o ->
        case KM.lookup "client_secret_expires_at" o of
          Just Null -> pure Nothing
          Just (Number n) -> pure (toBoundedInteger @Int n)
          Nothing -> pure Nothing
          _ -> abort "unexpected client_secret_expires_at type"
      _ -> abort "unexpected registration response"
  publicSecret @?= Nothing
  publicSecretExpiry @?= Nothing

  regResponseConfidential <-
    runSession
      ( do
          let body =
                object
                  [ "client_name" .= ("Test Confidential" :: Text)
                  , "redirect_uris" .= [redirectUri]
                  , "grant_types" .= (["authorization_code"] :: [Text])
                  , "token_endpoint_auth_method" .= ("client_secret_post" :: Text)
                  ]
              req =
                SRequest
                  (setPath defaultRequest "/register")
                    { requestMethod = methodPost
                    , requestHeaders = [(hContentType, "application/json")]
                    }
                  (Aeson.encode body)
          res <- srequest req
          liftIO $ assertEqual "register confidential status" status200 (simpleStatus res)
          case eitherDecode (simpleBody res) :: Either String Value of
            Left e -> abort e
            Right v -> pure v
      )
      app
  confidentialClientId <-
    case regResponseConfidential of
      Object o ->
        case KM.lookup "client_id" o of
          Just (String cid) -> pure cid
          _ -> abort "confidential client_id not found"
      _ -> abort "unexpected confidential registration response"
  confidentialSecret <-
    case regResponseConfidential of
      Object o ->
        case KM.lookup "client_secret" o of
          Just (String s) -> pure (Just s)
          _ -> abort "confidential client_secret missing"
      _ -> abort "unexpected confidential registration response"
  confidentialSecretExpiry <-
    case regResponseConfidential of
      Object o ->
        case KM.lookup "client_secret_expires_at" o of
          Just (Number n) ->
            case toBoundedInteger @Int n of
              Just i -> pure (Just i)
              Nothing -> abort "confidential client_secret_expires_at out of range"
          _ -> abort "confidential client_secret_expires_at missing"
      _ -> abort "unexpected confidential registration response"
  assertBool "confidential secret non-empty" (maybe False (not . T.null) confidentialSecret)
  confidentialSecretExpiry @?= Just 0

  -- Check it exists in state
  st1 <- readMVar stateVar
  case Map.lookup clientId (registered_clients st1) of
    Nothing -> assertFailure "client not inserted in state"
    Just c -> do
      registered_client_token_endpoint_auth_method c @?= "none"
      registered_client_grant_types c @?= ["authorization_code", "refresh_token"]
      registered_client_secret c @?= Nothing
  case Map.lookup confidentialClientId (registered_clients st1) of
    Nothing -> assertFailure "confidential client not inserted in state"
    Just c -> do
      registered_client_token_endpoint_auth_method c @?= "client_secret_post"
      assertBool "stored confidential secret" (maybe False (not . T.null) (registered_client_secret c))

  -- 3) Authorization request (validate params produce login form)
  -- Validate authorize responds (200 OK)
  _ <-
    runSession
      ( do
          let q =
                "?response_type=code&client_id="
                  <> TE.encodeUtf8 clientId
                  <> "&redirect_uri="
                  <> TE.encodeUtf8 redirectUri
                  <> "&scope=read&state=state-xyz&code_challenge=dummy&code_challenge_method=plain"
              req = setPath defaultRequest (BS.append "/authorize" q)
          res <- srequest (SRequest req LBS.empty)
          liftIO $ assertEqual "authorize status" status200 (simpleStatus res)
          pure ()
      )
      app
  -- Not asserting on HTML content here; redirect assertions above cover failures.

  -- 4) User login and authorization callback issues an authorization code with PKCE
  -- Prepare a verifier and its S256 challenge
  let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_verifier"
      verifierBs = TE.encodeUtf8 verifier
      hash :: Digest SHA256
      hash = hashWith SHA256 verifierBs
      challenge = TE.decodeUtf8 $ B64URL.encodeUnpadded (BS.pack $ BA.unpack hash)
  -- POST /authorize/callback
  _ <-
    runSession
      ( do
          let formBody =
                formURLEncoded
                  [ ("username", "testuser")
                  , ("password", "testpass")
                  , ("client_id", clientId)
                  , ("redirect_uri", redirectUri)
                  , ("scope", "read")
                  , ("state", "state-xyz")
                  , ("code_challenge", challenge)
                  , ("code_challenge_method", "S256")
                  ]
              req =
                SRequest
                  (setPath defaultRequest "/authorize/callback")
                    { requestMethod = methodPost
                    , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
                    }
                  formBody
          res <- srequest req
          liftIO $ assertEqual "callback status" status303 (simpleStatus res)
          let locationHeader = lookup hLocation (simpleHeaders res)
          case locationHeader of
            Nothing -> abort "Location header missing on callback redirect"
            Just loc -> do
              let locationText = TE.decodeUtf8 loc
              liftIO $ assertBool "redirect URI echoed" (redirectUri `T.isPrefixOf` locationText)
              liftIO $ assertBool "state parameter included" ("state=state-xyz" `T.isInfixOf` locationText)
          pure ()
      )
      app

  -- 5) Extract the auth code from state
  st2 <- readMVar stateVar
  let ac = fromJust $ find ((== clientId) . auth_code_client_id) (Map.elems (auth_codes st2))
  -- Sanity check PKCE saved
  auth_code_challenge ac @?= Just challenge
  auth_code_challenge_method ac @?= Just "S256"

  -- 6) Exchange code for tokens
  -- POST /token (authorization_code)
  (accTok, rt1) <-
    runSession
      ( do
          let formBody =
                formURLEncoded
                  [ ("grant_type", "authorization_code")
                  , ("code", auth_code_value ac)
                  , ("redirect_uri", redirectUri)
                  , ("client_id", clientId)
                  , ("code_verifier", verifier)
                  ]
              req =
                SRequest
                  (setPath defaultRequest "/token")
                    { requestMethod = methodPost
                    , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
                    }
                  formBody
          res <- srequest req
          liftIO $ assertEqual "token status" status200 (simpleStatus res)
          value <-
            case eitherDecode (simpleBody res) :: Either String Value of
              Left e -> abort e
              Right v -> pure v
          obj <-
            case value of
              Object o -> pure o
              _ -> abort "unexpected token response"
          accessToken <-
            case KM.lookup "access_token" obj of
              Just (String t) -> pure t
              _ -> abort "no access_token"
          refreshTokenValue <-
            case KM.lookup "refresh_token" obj of
              Just (String t) -> pure t
              Nothing -> abort "no refresh token in response"
              _ -> abort "unexpected refresh token shape"
          pure (accessToken, refreshTokenValue)
      )
      app
  assertBool "access_token non-empty" (not (T.null accTok))

  -- Code must have been removed (single use)
  st3 <- readMVar stateVar
  Map.member (auth_code_value ac) (auth_codes st3) @?= False
  let p3 = refresh_token_persistence st3
  b <- isJust <$> lookupRefreshToken p3 rt1
  b @?= True

  -- 7) Refresh the token (rotation expected)
  -- POST /token (refresh_token)
  (accTok2, rt2) <-
    runSession
      ( do
          let formBody =
                formURLEncoded
                  [ ("grant_type", "refresh_token")
                  , ("refresh_token", rt1)
                  , ("client_id", clientId)
                  ]
              req =
                SRequest
                  (setPath defaultRequest "/token")
                    { requestMethod = methodPost
                    , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
                    }
                  formBody
          res <- srequest req
          liftIO $ assertEqual "refresh status" status200 (simpleStatus res)
          value <-
            case eitherDecode (simpleBody res) :: Either String Value of
              Left e -> abort e
              Right v -> pure v
          obj <-
            case value of
              Object o -> pure o
              _ -> abort "unexpected refresh response"
          accessToken <-
            case KM.lookup "access_token" obj of
              Just (String t) -> pure t
              _ -> abort "no access_token"
          rotatedRefreshToken <-
            case KM.lookup "refresh_token" obj of
              Just (String t) -> pure t
              Nothing -> abort "no rotated refresh token"
              _ -> abort "unexpected rotated refresh token shape"
          pure (accessToken, rotatedRefreshToken)
      )
      app
  assertBool "refreshed access token non-empty" (not (T.null accTok2))
  rt2 /= rt1 @?= True

  -- State must reflect rotation
  st4 <- readMVar stateVar
  let p4 = refresh_token_persistence st4
  b1 <- isJust <$> lookupRefreshToken p4 rt1
  b2 <- isJust <$> lookupRefreshToken p4 rt2
  b1 @?= False
  b2 @?= True

-- Very small encoder for x-www-form-urlencoded bodies for controlled inputs
formURLEncoded :: [(Text, Text)] -> LBS.ByteString
formURLEncoded kvs =
  let enc =
        T.intercalate "&"
          . map (\(k, v) -> k <> "=" <> v)
  in  LBS.fromStrict (TE.encodeUtf8 (enc kvs))

abort :: (MonadIO m, MonadFail m) => String -> m a
abort msg = liftIO (assertFailure msg) >> fail msg
