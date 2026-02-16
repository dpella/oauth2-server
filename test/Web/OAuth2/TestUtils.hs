{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Web.OAuth2.TestUtils (
    -- * Shared fixtures
    TestUser (..),
    testUser,
    TestAuthSettings (..),
    mkAuthCode,
    mkRegisteredClient,
    mkPublicClient,
    mkConfidentialClient,
    mkTrackingPersistence,
    mkState,
    mkJWTSettings,
    jwtContext,
    formAuthContext,
    runHandler,
    encodeForm,

    -- * Application helpers
    emptyOAuthState,
    createTestContext,
    createTestApplication,
    addRegisteredClientToState,
    addAuthCodeToState,
    addRefreshTokenToState,
) where

import Control.Concurrent.MVar
import Control.Monad (void)
import Data.Aeson (FromJSON, ToJSON)
import Data.ByteString.Lazy qualified as LBS
import Data.IORef
import Data.List (find)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time.Clock
import GHC.Generics (Generic)
import Network.Wai (Application)
import Servant (Context (EmptyContext, (:.)), Handler, Proxy (..), ServerError, serveWithContext)
import Servant.Auth.Server
import Servant.Server.Internal.Handler qualified as Internal
import Web.OAuth2
import Web.OAuth2.Types

data TestUser = TestUser
    { userId :: Text
    , userName :: Text
    , userEmail :: Text
    }
    deriving (Eq, Show, Generic, ToJSON, FromJSON)

instance ToJWT TestUser

instance FromJWT TestUser

instance FormAuth TestUser where
    type FormAuthSettings TestUser = TestAuthSettings
    runFormAuth _ username password =
        pure $
            case (username, password) of
                ("testuser", "testpass") -> Authenticated testUser
                ("admin", "admin") -> Authenticated (TestUser "admin" "Admin User" "admin@example.com")
                _ -> NoSuchUser

data TestAuthSettings = TestAuthSettings

testUser :: TestUser
testUser = TestUser "user1" "Test User" "test@example.com"

mkAuthCode ::
    Text ->
    RegisteredClient ->
    TestUser ->
    UTCTime ->
    Text ->
    Maybe Text ->
    Maybe Text ->
    AuthCode TestUser
mkAuthCode codeValue RegisteredClient{registered_client_id, registered_client_scope} usr expiry redirectUri challenge challengeMethod =
    AuthCode
        { auth_code_value = codeValue
        , auth_code_client_id = registered_client_id
        , auth_code_user = usr
        , auth_code_redirect_uri = redirectUri
        , auth_code_scope = registered_client_scope
        , auth_code_expiry = expiry
        , auth_code_challenge = challenge
        , auth_code_challenge_method = challengeMethod
        }

mkRegisteredClient ::
    Text ->
    [Text] ->
    [Text] ->
    [Text] ->
    Text ->
    Text ->
    Maybe Text ->
    RegisteredClient
mkRegisteredClient clientId redirects grants responses scope tokenMethod secret =
    RegisteredClient
        { registered_client_id = clientId
        , registered_client_name = clientId
        , registered_client_secret = secret
        , registered_client_redirect_uris = redirects
        , registered_client_grant_types = grants
        , registered_client_response_types = responses
        , registered_client_scope = scope
        , registered_client_token_endpoint_auth_method = tokenMethod
        , registered_client_registration_access_token = Nothing
        }

mkPublicClient :: Text -> [Text] -> Text -> RegisteredClient
mkPublicClient clientId redirectUris scope =
    mkRegisteredClient clientId redirectUris ["authorization_code", "refresh_token"] ["code"] scope "none" Nothing

mkConfidentialClient :: Text -> Text -> [Text] -> Text -> RegisteredClient
mkConfidentialClient clientId secret redirectUris scope =
    mkRegisteredClient clientId redirectUris ["authorization_code", "refresh_token"] ["code"] scope "client_secret_post" (Just secret)

mkTrackingPersistence ::
    IO (RefreshTokenPersistence TestUser, IO [RefreshToken TestUser])
mkTrackingPersistence = do
    ref <- newIORef ([] :: [RefreshToken TestUser])
    let persist token =
            atomicModifyIORef' ref $ \tokens -> (token : tokens, ())
        delete tokenValue =
            atomicModifyIORef' ref $ \tokens ->
                (filter ((/= tokenValue) . refresh_token_value) tokens, ())
        lookupToken tokenValue = do
            tokens <- readIORef ref
            pure $ find ((== tokenValue) . refresh_token_value) tokens
    pure
        ( RefreshTokenPersistence
            { persistRefreshToken = persist
            , deleteRefreshToken = delete
            , lookupRefreshToken = lookupToken
            }
        , reverse <$> readIORef ref
        )

mkState ::
    RefreshTokenPersistence TestUser ->
    [RegisteredClient] ->
    [(Text, AuthCode TestUser)] ->
    IO (MVar (OAuthState TestUser))
mkState persistence clients codes =
    newMVar
        OAuthState
            { auth_codes = Map.fromList codes
            , refresh_token_persistence = persistence
            , registered_clients =
                Map.fromList $ fmap (\c -> (registered_client_id c, c)) clients
            , oauth_url = "https://auth.example.com"
            , oauth_port = 443
            , login_form_renderer = defaultLoginFormRenderer
            }

mkJWTSettings :: IO JWTSettings
mkJWTSettings = defaultJWTSettings <$> generateKey

jwtContext :: JWTSettings -> Context '[JWTSettings]
jwtContext settings = settings :. EmptyContext

formAuthContext :: Context '[TestAuthSettings]
formAuthContext = TestAuthSettings :. EmptyContext

runHandler :: Handler a -> IO (Either ServerError a)
runHandler = Internal.runHandler

encodeForm :: [(Text, Text)] -> LBS.ByteString
encodeForm fields =
    let fragment (k, v) = k <> "=" <> v
        body = T.intercalate "&" (map fragment fields)
     in LBS.fromStrict (TE.encodeUtf8 body)

emptyOAuthState :: IO (MVar (OAuthState TestUser))
emptyOAuthState = do
    persistence <- mkDefaultRefreshTokenPersistence
    newMVar (initOAuthState @TestUser "http://localhost:8080" 8080 persistence defaultLoginFormRenderer)

createTestContext :: IO (Context '[JWTSettings, TestAuthSettings])
createTestContext = do
    jwt <- mkJWTSettings
    pure (jwt :. TestAuthSettings :. EmptyContext)

createTestApplication :: IO (MVar (OAuthState TestUser), Context '[JWTSettings, TestAuthSettings], Application)
createTestApplication = do
    stateVar <- emptyOAuthState
    ctx <- createTestContext
    let app = serveWithContext (Proxy :: Proxy OAuthAPI) ctx (oAuthAPI stateVar ctx)
    pure (stateVar, ctx, app)

addRegisteredClientToState :: MVar (OAuthState TestUser) -> RegisteredClient -> IO ()
addRegisteredClientToState st client =
    void $
        modifyMVar st $ \s -> do
            let updated =
                    s
                        { registered_clients =
                            Map.insert (registered_client_id client) client (registered_clients s)
                        }
            pure (updated, ())

addAuthCodeToState :: MVar (OAuthState TestUser) -> AuthCode TestUser -> IO ()
addAuthCodeToState st ac =
    void $
        modifyMVar st $ \s -> do
            let updated = s{auth_codes = Map.insert (auth_code_value ac) ac (auth_codes s)}
            pure (updated, ())

addRefreshTokenToState :: MVar (OAuthState TestUser) -> RefreshToken TestUser -> IO ()
addRefreshTokenToState st rt =
    void $
        modifyMVar st $ \s -> do
            persistRefreshToken (refresh_token_persistence s) rt
            pure (s, ())
