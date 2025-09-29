{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module OAuth.FlowSpec (tests) where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (liftIO)
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
import Network.HTTP.Types (hContentType, methodPost, status200)
import Network.Wai (requestHeaders, requestMethod)
import Network.Wai.Test
import OAuth (OAuthAPI, oAuthAPI)
import OAuth.TestUtils
import OAuth.Types hiding (error)
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

  -- 2) Dynamic client registration (public client with PKCE, allows refresh)
  let redirectUri = "http://localhost:4000/cb"
  clientId <-
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
          let clientId' =
                case eitherDecode (simpleBody res) :: Either String Value of
                  Left e -> error e
                  Right (Object o) -> case KM.lookup "client_id" o of
                    Just (String cid) -> cid
                    _ -> error "client_id not found"
                  Right _ -> error "unexpected reg response"
          pure clientId'
      )
      app

  -- Check it exists in state
  st1 <- readMVar stateVar
  case Map.lookup clientId (registered_clients st1) of
    Nothing -> assertFailure "client not inserted in state"
    Just c -> do
      registered_client_token_endpoint_auth_method c @?= "none"
      registered_client_grant_types c @?= ["authorization_code", "refresh_token"]

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
  -- Not asserting on HTML content here; failure would throw error.

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
          liftIO $ assertEqual "callback status" status200 (simpleStatus res)
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
          let (at, mrt) =
                case eitherDecode (simpleBody res) :: Either String Value of
                  Left e -> error e
                  Right (Object o) ->
                    let at' = case KM.lookup "access_token" o of
                          Just (String t) -> t
                          _ -> error "no access_token"
                        rt' = case KM.lookup "refresh_token" o of
                          Just (String t) -> Just t
                          _ -> Nothing
                    in  (at', rt')
                  Right _ -> error "unexpected token response"
          case mrt of
            Nothing -> error "no refresh token in response"
            Just r -> pure (at, r)
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
          let (at, rt) =
                case eitherDecode (simpleBody res) :: Either String Value of
                  Left e -> error e
                  Right (Object o) ->
                    let at' = case KM.lookup "access_token" o of
                          Just (String t) -> t
                          _ -> error "no access_token"
                        rt' = case KM.lookup "refresh_token" o of
                          Just (String t) -> Just t
                          _ -> Nothing
                    in  (at', rt')
                  Right _ -> error "unexpected refresh response"
          case rt of
            Nothing -> error "no rotated refresh token"
            Just r -> pure (at, r)
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
