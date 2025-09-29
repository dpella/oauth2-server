{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module OAuth.TestUtils where

import Control.Concurrent.MVar
import Data.Aeson (FromJSON, ToJSON)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Time.Clock
import GHC.Generics (Generic)
import OAuth.Types
import Servant (Context (EmptyContext, (:.)))
import Servant.Auth.Server

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

-- Helpers to inspect/update state in tests
addAuthCodeToState :: MVar (OAuthState TestUser) -> AuthCode TestUser -> IO ()
addAuthCodeToState st ac = modifyMVar_ st $ \s -> pure s{auth_codes = Map.insert (auth_code_value ac) ac (auth_codes s)}

addRefreshTokenToState :: MVar (OAuthState TestUser) -> RefreshToken TestUser -> IO ()
addRefreshTokenToState st rt = modifyMVar_ st $ \s -> do
  persistRefreshToken (refresh_token_persistence s) rt
  pure s

-- Convenience constructors used in some checks
createTestAuthCode :: TestUser -> Text -> IO (AuthCode TestUser)
createTestAuthCode user clientId = do
  code <- generateToken
  expiry <- addUTCTime (10 * 60) <$> getCurrentTime
  pure $ AuthCode code clientId user "http://localhost:3000/callback" "read" expiry Nothing Nothing
