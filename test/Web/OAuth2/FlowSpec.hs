{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.OAuth2.FlowSpec (tests) where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (MonadIO, liftIO)
import Crypto.Hash (Digest, SHA256 (..), hashWith)
import Data.Aeson (Value (..), eitherDecode, object, (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KM
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as B64URL
import Data.ByteString.Lazy qualified as LBS
import Data.Foldable (toList)
import Data.List (find)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromJust, isJust)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time.Clock
import Network.HTTP.Types (hContentType, hLocation, methodPost, status200, status201, status303)
import Network.Wai (requestHeaders, requestMethod)
import Network.Wai.Test
import Servant
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth2 (OAuthAPI, oAuthAPI)
import Web.OAuth2.TestUtils
import Web.OAuth2.Types

tests :: TestTree
tests = testGroup "OAuth End-to-End Flow" [commonFlow]

commonFlow :: TestTree
commonFlow = testCase "Dynamic registration -> authorize -> token -> refresh" $ do
  stateVar <- emptyOAuthState
  ctx <- createTestContext
  let app :: Application
      app = serveWithContext (Proxy :: Proxy OAuthAPI) ctx (oAuthAPI stateVar ctx)

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
  issuerValue <- lookupText "issuer" metadataObj
  authorizeEndpointValue <- lookupText "authorization_endpoint" metadataObj
  tokenEndpointValue <- lookupText "token_endpoint" metadataObj
  registerEndpointValue <- lookupText "registration_endpoint" metadataObj
  issuerValue @?= "http://localhost:8080"
  authorizeEndpointValue @?= "http://localhost:8080/authorize"
  tokenEndpointValue @?= "http://localhost:8080/token"
  registerEndpointValue @?= "http://localhost:8080/register"
  case KM.lookup "token_endpoint_auth_methods_supported" metadataObj of
    Just (Array arr) -> toList arr @?= [String "none", String "client_secret_post"]
    _ -> abort "token_endpoint_auth_methods_supported missing"
  case KM.lookup "scopes_supported" metadataObj of
    Just (Array arr) -> toList arr @?= [String "read", String "write"]
    _ -> abort "scopes_supported missing"

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
          liftIO $ assertEqual "register status" status201 (simpleStatus res)
          case eitherDecode (simpleBody res) :: Either String Value of
            Left e -> abort e
            Right v -> pure v
      )
      app
  publicObj <- valueToObject regResponsePublic
  clientId <- lookupTextFromObject "client_id" publicObj
  registrationToken <- lookupTextFromObject "registration_access_token" publicObj
  registrationUri <- lookupTextFromObject "registration_client_uri" publicObj
  assertBool "public client secret omitted" (KM.lookup "client_secret" publicObj == Nothing)
  assertBool "public client secret expiry omitted" (KM.lookup "client_secret_expires_at" publicObj == Nothing)
  assertBool "registration access token present" (not (T.null registrationToken))
  assertBool "registration client URI includes register path" ("/register/" `T.isInfixOf` registrationUri)

  st1 <- readMVar stateVar
  case Map.lookup clientId (registered_clients st1) of
    Nothing -> assertFailure "client not inserted in state"
    Just c -> do
      registered_client_token_endpoint_auth_method c @?= "none"
      registered_client_grant_types c @?= ["authorization_code", "refresh_token"]
      registered_client_registration_access_token c @?= Just registrationToken

  now <- getCurrentTime
  verifier <- pure "verifier-value"
  let challenge = base64UrlHash verifier
      authorizeQuery =
        encodeForm
          [ ("response_type", "code")
          , ("client_id", clientId)
          , ("redirect_uri", redirectUri)
          , ("scope", "read")
          , ("state", "state-xyz")
          , ("code_challenge", challenge)
          , ("code_challenge_method", "S256")
          ]
  _ <-
    runSession
      ( do
          let req = setPath defaultRequest (BS.concat ["/authorize?", LBS.toStrict authorizeQuery])
          res <- srequest (SRequest req LBS.empty)
          liftIO $ assertEqual "authorize status" status200 (simpleStatus res)
      )
      app

  loginRes <-
    runSession
      ( do
          let formBody =
                encodeForm
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
          liftIO $ assertEqual "callback redirect" status303 (simpleStatus res)
          pure res
      )
      app
  case lookup hLocation (simpleHeaders loginRes) of
    Nothing -> assertFailure "authorize callback missing Location"
    Just loc -> do
      let locText = TE.decodeUtf8 loc
      assertBool "redirect URI echoed" (redirectUri `T.isPrefixOf` locText)
      assertBool "state parameter included" ("state=state-xyz" `T.isInfixOf` locText)

  st2 <- readMVar stateVar
  let ac = fromJust $ find ((== clientId) . auth_code_client_id) (Map.elems (auth_codes st2))
  auth_code_challenge ac @?= Just challenge
  auth_code_challenge_method ac @?= Just "S256"
  assertBool "expiry set in future" (auth_code_expiry ac > now)

  (accessTokenValue, refreshTokenValue) <-
    runSession
      ( do
          let formBody =
                encodeForm
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
          liftIO $ assertEqual "token exchange status" status200 (simpleStatus res)
          value <-
            case eitherDecode (simpleBody res) :: Either String Value of
              Left e -> abort e
              Right v -> pure v
          obj <- liftIO $ valueToObject value
          accessToken <- liftIO $ lookupTextFromObject "access_token" obj
          refreshToken <- liftIO $ lookupTextFromObject "refresh_token" obj
          pure (accessToken, refreshToken)
      )
      app
  assertBool "access token populated" (not (T.null accessTokenValue))
  assertBool "refresh token populated" (not (T.null refreshTokenValue))

  st3 <- readMVar stateVar
  Map.member (auth_code_value ac) (auth_codes st3) @?= False
  let persistence = refresh_token_persistence st3
  isJust <$> lookupRefreshToken persistence refreshTokenValue >>= (@?= True)

  (rotatedAccessToken, rotatedRefreshToken) <-
    runSession
      ( do
          let formBody =
                encodeForm
                  [ ("grant_type", "refresh_token")
                  , ("refresh_token", refreshTokenValue)
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
          obj <- liftIO $ valueToObject value
          accessTok <- liftIO $ lookupTextFromObject "access_token" obj
          refreshTok <- liftIO $ lookupTextFromObject "refresh_token" obj
          pure (accessTok, refreshTok)
      )
      app
  assertBool "rotated access token populated" (not (T.null rotatedAccessToken))
  assertBool "refresh token rotated" (rotatedRefreshToken /= refreshTokenValue)

  st4 <- readMVar stateVar
  let persistence' = refresh_token_persistence st4
  isJust <$> lookupRefreshToken persistence' refreshTokenValue >>= (@?= False)
  isJust <$> lookupRefreshToken persistence' rotatedRefreshToken >>= (@?= True)

lookupText :: Text -> KM.KeyMap Value -> IO Text
lookupText key obj = lookupTextFromObject key obj

lookupTextFromObject :: Text -> KM.KeyMap Value -> IO Text
lookupTextFromObject key obj =
  case KM.lookup (Key.fromText key) obj of
    Just (String t) -> pure t
    _ -> abort ("missing text field: " <> T.unpack key)

valueToObject :: Value -> IO (KM.KeyMap Value)
valueToObject (Object o) = pure o
valueToObject _ = abort "expected JSON object"

base64UrlHash :: Text -> Text
base64UrlHash verifier =
  let bytes = TE.encodeUtf8 verifier
      digest = hashWith SHA256 bytes :: Digest SHA256
  in  TE.decodeUtf8 (B64URL.encodeUnpadded (BS.pack (BA.unpack digest)))

abort :: (MonadIO m, MonadFail m) => String -> m a
abort msg = liftIO (assertFailure msg) >> fail msg
