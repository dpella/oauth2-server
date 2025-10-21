{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Web.OAuth.TestUtils where

import Control.Concurrent.MVar
import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time.Clock
import GHC.Generics (Generic)
import Network.Wai (Application)
import Servant (Context (EmptyContext, (:.)), Proxy (..), serveWithContext)
import Servant.Auth.Server
  ( AuthResult (Authenticated, NoSuchUser)
  , FromJWT
  , JWTSettings
  , ToJWT
  , defaultJWTSettings
  , generateKey
  )
import Web.OAuth
import Web.OAuth.Types

-- Test user used throughout the specs
data TestUser = TestUser
  { userId :: Text
  , userName :: Text
  , userEmail :: Text
  }
  deriving (Eq, Show, Generic)

instance ToJSON TestUser

instance FromJSON TestUser

instance ToJWT TestUser

instance FromJWT TestUser

-- FormAuth instance to simulate login
instance FormAuth TestUser where
  type FormAuthSettings TestUser = TestAuthSettings
  runFormAuth _ username password =
    pure $ case (username, password) of
      ("testuser", "testpass") -> Authenticated $ TestUser "user1" "Test User" "test@example.com"
      ("admin", "admin") -> Authenticated $ TestUser "admin" "Admin User" "admin@example.com"
      _ -> NoSuchUser

data TestAuthSettings = TestAuthSettings

-- Fresh OAuth state with no pre-registered clients
emptyOAuthState :: IO (MVar (OAuthState TestUser))
emptyOAuthState = do
  p <- mkDefaultRefreshTokenPersistence
  newMVar (initOAuthState @TestUser "http://localhost:8080" 8080 p)

-- Create JWT settings for issuing access tokens in tests
createTestJWTSettings :: IO JWTSettings
createTestJWTSettings = defaultJWTSettings <$> generateKey

type TestContext = '[JWTSettings, TestAuthSettings]

createTestContext :: IO (Context TestContext)
createTestContext = do
  jwt <- createTestJWTSettings
  pure (jwt :. TestAuthSettings :. EmptyContext)

createTestApplication
  :: IO (MVar (OAuthState TestUser), Context TestContext, Application)
createTestApplication = do
  stateVar <- emptyOAuthState
  ctx <- createTestContext
  let app = serveWithContext (Proxy :: Proxy OAuthAPI) ctx (oAuthAPI stateVar ctx)
  pure (stateVar, ctx, app)

-- Helpers to inspect/update state in tests
addAuthCodeToState :: MVar (OAuthState TestUser) -> AuthCode TestUser -> IO ()
addAuthCodeToState st ac = modifyMVar_ st $ \s -> pure s{auth_codes = Map.insert (auth_code_value ac) ac (auth_codes s)}

addRefreshTokenToState :: MVar (OAuthState TestUser) -> RefreshToken TestUser -> IO ()
addRefreshTokenToState st rt = modifyMVar_ st $ \s -> do
  persistRefreshToken (refresh_token_persistence s) rt
  pure s

addRegisteredClientToState :: MVar (OAuthState TestUser) -> RegisteredClient -> IO ()
addRegisteredClientToState st client =
  modifyMVar_ st $ \s ->
    pure
      s
        { registered_clients =
            Map.insert (registered_client_id client) client (registered_clients s)
        }

mkPublicClient :: Text -> [Text] -> Text -> RegisteredClient
mkPublicClient clientId redirectUris scope =
  RegisteredClient
    { registered_client_id = clientId
    , registered_client_name = clientId
    , registered_client_secret = Nothing
    , registered_client_redirect_uris = redirectUris
    , registered_client_grant_types = ["authorization_code", "refresh_token"]
    , registered_client_response_types = ["code"]
    , registered_client_scope = scope
    , registered_client_token_endpoint_auth_method = "none"
    }

mkConfidentialClient :: Text -> Text -> [Text] -> Text -> RegisteredClient
mkConfidentialClient clientId secret redirectUris scope =
  RegisteredClient
    { registered_client_id = clientId
    , registered_client_name = clientId
    , registered_client_secret = Just secret
    , registered_client_redirect_uris = redirectUris
    , registered_client_grant_types = ["authorization_code", "refresh_token"]
    , registered_client_response_types = ["code"]
    , registered_client_scope = scope
    , registered_client_token_endpoint_auth_method = "client_secret_post"
    }

-- Convenience constructors used in some checks
createTestAuthCode :: TestUser -> Text -> IO (AuthCode TestUser)
createTestAuthCode user clientId = do
  code <- generateToken
  expiry <- addUTCTime (10 * 60) <$> getCurrentTime
  pure $ AuthCode code clientId user "http://localhost:3000/callback" "read" expiry Nothing Nothing

testUser :: TestUser
testUser = TestUser "user1" "Test User" "test@example.com"

encodeForm :: [(Text, Text)] -> LBS.ByteString
encodeForm fields =
  let fragment (k, v) = k <> "=" <> v
      body = T.intercalate "&" (map fragment fields)
  in  LBS.fromStrict (TE.encodeUtf8 body)
