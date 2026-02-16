{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Module:      Web.OAuth2.RegisterAPI
-- Copyright:   (c) DPella AB 2025
-- License:     MPL-2.0
-- Maintainer:  <matti@dpella.io>, <lobo@dpella.io>
--
-- OAuth 2.1 Dynamic Client Registration for DPella.
--
-- This module implements dynamic client registration as defined in RFC 7591.
-- It allows OAuth clients to register themselves programmatically with the
-- DPella authorization server.
--
-- Registered clients receive a unique client_id that must be used in all
-- subsequent OAuth flows. The registration process collects client metadata
-- including redirect URIs, grant types, and requested scopes.
module Web.OAuth2.RegisterAPI where

import Control.Concurrent.MVar
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (ExceptT, runExceptT, throwE)
import Data.Aeson
import Data.ByteString.Char8 qualified as BS8
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Text qualified as T
import GHC.Generics
import Network.URI qualified as URI
import Web.OAuth2.Types
import Servant
import Text.Read (readMaybe)

-- | Servant API type for the OAuth dynamic client registration endpoint.
--
-- Accepts a JSON request body with client metadata and returns
-- the registered client information including the assigned client_id.
type RegisterAPI =
  "register"
    :> ReqBody '[JSON] ClientRegistrationRequest
    :> PostCreated '[JSON] ClientRegistrationResponse
  :<|>
  "register"
    :> Capture "client_id" Text
    :> Header "Authorization" Text
    :> Get '[JSON] ClientRegistrationResponse
  :<|>
  "register"
    :> Capture "client_id" Text
    :> Header "Authorization" Text
  :> ReqBody '[JSON] ClientRegistrationRequest
  :> Put '[JSON] ClientRegistrationResponse
  :<|>
  "register"
    :> Capture "client_id" Text
    :> Header "Authorization" Text
    :> Verb 'DELETE 204 '[JSON] NoContent

-- | Request payload for dynamic client registration.
--
-- Contains the client metadata that should be registered with
-- the authorization server. Most fields are optional and will
-- use sensible defaults if not provided.
data ClientRegistrationRequest = ClientRegistrationRequest
  { client_name :: Text
  -- ^ Human-readable name of the client
  , redirect_uris :: [Text]
  -- ^ List of allowed redirect URIs for this client
  , grant_types :: Maybe [Text]
  -- ^ OAuth grant types the client will use (default: ["authorization_code", "refresh_token"])
  , response_types :: Maybe [Text]
  -- ^ OAuth response types the client will use (default: ["code"])
  , scope :: Maybe Text
  -- ^ Space-delimited list of scopes the client may request (default: "read write")
  , token_endpoint_auth_method :: Maybe Text
  -- ^ Client authentication method at token endpoint (default: "none")
  }
  deriving (Eq, Show, Generic)

instance FromJSON ClientRegistrationRequest

instance ToJSON ClientRegistrationRequest

-- | Response returned after successful client registration.
--
-- Contains all the registered client metadata including the
-- newly assigned client_id that must be used in OAuth flows.
data ClientRegistrationResponse = ClientRegistrationResponse
  { reg_client_id :: Text
  -- ^ Unique identifier assigned to the client
  , reg_client_name :: Text
  -- ^ Registered human-readable name
  , reg_client_secret :: Maybe Text
  -- ^ Secret issued to confidential clients (Nothing for public clients)
  , reg_client_secret_expires_at :: Maybe Int
  -- ^ Epoch seconds when the secret expires (Nothing means unspecified)
  , reg_redirect_uris :: [Text]
  -- ^ Registered redirect URIs
  , reg_grant_types :: [Text]
  -- ^ Allowed grant types for this client
  , reg_response_types :: [Text]
  -- ^ Allowed response types for this client
  , reg_scope :: Text
  -- ^ Maximum scope this client can request
  , reg_token_endpoint_auth_method :: Text
  -- ^ Required authentication method at token endpoint
  , reg_registration_access_token :: Text
  -- ^ Registration access token for subsequent client management
  , reg_registration_client_uri :: Text
  -- ^ URI where the client configuration can be managed
  }
  deriving (Eq, Show, Generic)

instance ToJSON ClientRegistrationResponse where
  toJSON ClientRegistrationResponse{..} =
    object $
      [ "client_id" .= reg_client_id
      , "client_name" .= reg_client_name
      , "redirect_uris" .= reg_redirect_uris
      , "grant_types" .= reg_grant_types
      , "response_types" .= reg_response_types
      , "scope" .= reg_scope
      , "token_endpoint_auth_method" .= reg_token_endpoint_auth_method
      , "registration_access_token" .= reg_registration_access_token
      , "registration_client_uri" .= reg_registration_client_uri
      ]
        <> maybe [] (\secret -> ["client_secret" .= secret]) reg_client_secret
        <> maybe [] (\expiry -> ["client_secret_expires_at" .= expiry]) reg_client_secret_expires_at

-- | Handle dynamic client registration requests.
--
-- This function:
--
-- 1. Generates a unique client_id with "client_" prefix
-- 2. Applies defaults for any optional parameters:
--    - grant_types: ["authorization_code", "refresh_token"]
--    - response_types: ["code"]
--    - scope: "read write"
--    - auth_method: "none"
-- 3. Stores the client registration in the OAuth state
-- 4. Returns the complete client registration details
--
registerServer :: forall usr. MVar (OAuthState usr) -> Server RegisterAPI
registerServer state_var =
  handleRegister state_var
    :<|> handleRegistrationGet state_var
    :<|> handleRegistrationUpdate state_var
    :<|> handleRegistrationDelete state_var

data NormalizedRegistration = NormalizedRegistration
  { normGrantTypes :: [Text]
  , normResponseTypes :: [Text]
  , normScope :: Text
  , normAuthMethod :: Text
  , normSecret :: Maybe Text
  }

-- | Handle dynamic client registration requests.
--
-- The client_id is generated using a secure random token generator.
handleRegister :: forall usr. MVar (OAuthState usr) -> ClientRegistrationRequest -> Handler ClientRegistrationResponse
handleRegister state_var request@ClientRegistrationRequest{..} = do
  normalized <- liftEitherIO =<< liftIO (normalizeRegistration Nothing request)
  client_id <- ("client_" <>) <$> liftIO generateToken
  registration_access_token <- liftIO generateToken
  response <-
    liftIO $
      modifyMVar state_var $ \s -> do
        let baseUrl = normalizeBaseUrl (oauth_url s) (oauth_port s)
            baseForPaths = stripTrailingSlash baseUrl
            registration_client_uri = appendPathSegment baseForPaths ("/register/" <> client_id)
            newClient =
              RegisteredClient
                { registered_client_id = client_id
                , registered_client_name = client_name
                , registered_client_secret = normSecret normalized
                , registered_client_redirect_uris = redirect_uris
                , registered_client_grant_types = normGrantTypes normalized
                , registered_client_response_types = normResponseTypes normalized
                , registered_client_scope = normScope normalized
                , registered_client_token_endpoint_auth_method = normAuthMethod normalized
                , registered_client_registration_access_token = Just registration_access_token
                }
            updatedState =
              s
                { registered_clients = Map.insert client_id newClient (registered_clients s)
                }
            responseValue =
              buildRegistrationResponse registration_client_uri registration_access_token newClient
        pure (updatedState, responseValue)
  pure response

-- | Retrieve metadata for an existing client registration (RFC 7592).
handleRegistrationGet
  :: forall usr
   . MVar (OAuthState usr)
  -> Text
  -> Maybe Text
  -> Handler ClientRegistrationResponse
handleRegistrationGet state_var clientId mAuth = do
  state <- liftIO $ readMVar state_var
  (baseUrl, managementToken, client) <- resolveManagedClient state clientId mAuth
  let registrationUri = appendPathSegment (stripTrailingSlash baseUrl) ("/register/" <> clientId)
  pure $ buildRegistrationResponse registrationUri managementToken client

-- | Update metadata for an existing client registration (RFC 7592).
handleRegistrationUpdate
  :: forall usr
   . MVar (OAuthState usr)
  -> Text
  -> Maybe Text
  -> ClientRegistrationRequest
  -> Handler ClientRegistrationResponse
handleRegistrationUpdate state_var clientId mAuth request@ClientRegistrationRequest{client_name = newName, redirect_uris = newRedirects} = do
  result <-
    liftIO $
      modifyMVar state_var $ \s -> do
        let baseUrl = normalizeBaseUrl (oauth_url s) (oauth_port s)
            baseForPaths = stripTrailingSlash baseUrl
        case Map.lookup clientId (registered_clients s) of
          Nothing ->
            pure (s, Left $ registrationNotFound clientId)
          Just existing -> do
            let authCheck = authorizeManagement existing mAuth
            case authCheck of
              Left err -> pure (s, Left err)
              Right token -> do
                normalizedResult <- normalizeRegistration (Just existing) request
                case normalizedResult of
                  Left err -> pure (s, Left err)
                  Right normalized -> do
                    let registration_client_uri = appendPathSegment baseForPaths ("/register/" <> clientId)
                        updatedClient =
                          existing
                            { registered_client_name = newName
                            , registered_client_secret = normSecret normalized
                            , registered_client_redirect_uris = newRedirects
                            , registered_client_grant_types = normGrantTypes normalized
                            , registered_client_response_types = normResponseTypes normalized
                            , registered_client_scope = normScope normalized
                            , registered_client_token_endpoint_auth_method = normAuthMethod normalized
                            }
                        newState =
                          s
                            { registered_clients = Map.insert clientId updatedClient (registered_clients s)
                            }
                        responseValue =
                          buildRegistrationResponse registration_client_uri token updatedClient
                    pure (newState, Right responseValue)
  either throwError pure result

-- | Remove an existing client registration (RFC 7592).
handleRegistrationDelete
  :: forall usr
   . MVar (OAuthState usr)
  -> Text
  -> Maybe Text
  -> Handler NoContent
handleRegistrationDelete state_var clientId mAuth = do
  result <-
    liftIO $
      modifyMVar state_var $ \s -> do
        case Map.lookup clientId (registered_clients s) of
          Nothing ->
            pure (s, Left $ registrationNotFound clientId)
          Just existing ->
            case authorizeManagement existing mAuth of
              Left err -> pure (s, Left err)
              Right _ ->
                let newState =
                      s
                        { registered_clients = Map.delete clientId (registered_clients s)
                        }
                in  pure (newState, Right NoContent)
  either throwError pure result

buildRegistrationResponse
  :: Text
  -> Text
  -> RegisteredClient
  -> ClientRegistrationResponse
buildRegistrationResponse registrationUri registrationToken RegisteredClient{..} =
  ClientRegistrationResponse
    { reg_client_id = registered_client_id
    , reg_client_name = registered_client_name
    , reg_client_secret = registered_client_secret
    , reg_client_secret_expires_at = Nothing
    , reg_redirect_uris = registered_client_redirect_uris
    , reg_grant_types = registered_client_grant_types
    , reg_response_types = registered_client_response_types
    , reg_scope = registered_client_scope
    , reg_token_endpoint_auth_method = registered_client_token_endpoint_auth_method
    , reg_registration_access_token = registrationToken
    , reg_registration_client_uri = registrationUri
    }

authorizeManagement :: RegisteredClient -> Maybe Text -> Either ServerError Text
authorizeManagement RegisteredClient{registered_client_registration_access_token = Nothing} _ =
  Left $ oauthErrorResponse err500 "server_error" (Just "Client missing management access token")
authorizeManagement RegisteredClient{registered_client_registration_access_token = Just expectedToken} mHeader =
  case extractBearerToken mHeader of
    Left err -> Left err
    Right provided ->
      if constTimeEq provided expectedToken
        then Right expectedToken
        else Left $ addBearerChallenge $ oauthErrorResponse err401 "invalid_token" (Just "Invalid management access token")

resolveManagedClient
  :: OAuthState usr
  -> Text
  -> Maybe Text
  -> Handler (Text, Text, RegisteredClient)
resolveManagedClient state clientId mAuth =
  case Map.lookup clientId (registered_clients state) of
    Nothing -> throwError $ registrationNotFound clientId
    Just rc ->
      case authorizeManagement rc mAuth of
        Left err -> throwError err
        Right token -> do
          let baseUrl = normalizeBaseUrl (oauth_url state) (oauth_port state)
          pure (baseUrl, token, rc)

normalizeRegistration
  :: Maybe RegisteredClient
  -> ClientRegistrationRequest
  -> IO (Either ServerError NormalizedRegistration)
normalizeRegistration existing ClientRegistrationRequest{..} = runExceptT $ do
  exceptEither $ validateRedirectUris redirect_uris
  let baseGrant = maybe ["authorization_code", "refresh_token"] registered_client_grant_types existing
      baseResponse = maybe ["code"] registered_client_response_types existing
      baseScope = maybe "read write" registered_client_scope existing
      baseAuth = maybe "none" registered_client_token_endpoint_auth_method existing
      grantTypes = fromMaybe baseGrant grant_types
      responseTypes = fromMaybe baseResponse response_types
      resolvedScope = fromMaybe baseScope scope
      resolvedAuthMethod = fromMaybe baseAuth token_endpoint_auth_method
  exceptEither $ validateAuthMethod resolvedAuthMethod
  secret <-
    case resolvedAuthMethod of
      "none" -> pure Nothing
      "client_secret_post" ->
        case existing of
          Just RegisteredClient{registered_client_secret = Just existingSecret, registered_client_token_endpoint_auth_method = "client_secret_post"} ->
            pure (Just existingSecret)
          _ -> Just <$> liftIO generateToken
      _ -> pure Nothing
  pure
    NormalizedRegistration
      { normGrantTypes = grantTypes
      , normResponseTypes = responseTypes
      , normScope = resolvedScope
      , normAuthMethod = resolvedAuthMethod
      , normSecret = secret
      }

validateAuthMethod :: Text -> Either ServerError ()
validateAuthMethod method
  | method `elem` ["none", "client_secret_post"] = Right ()
  | otherwise =
      Left $ invalidMetadataError "Unsupported token_endpoint_auth_method; expected \"none\" or \"client_secret_post\""

validateRedirectUris :: [Text] -> Either ServerError ()
validateRedirectUris uris
  | null uris = Left $ invalidMetadataError "redirect_uris must include at least one absolute URI"
  | otherwise = foldl' step (Right ()) uris
  where
    step acc uriText = acc >> checkUri uriText

    checkUri uriText =
      case URI.parseURI (T.unpack uriText) of
        Just parsed
          | not (null (URI.uriScheme parsed)) ->
              ensureNoFragment parsed >> ensureScheme parsed
        _ -> Left $ invalidMetadataError "redirect_uri is not an absolute URI"

    ensureNoFragment parsed =
      if null (URI.uriFragment parsed)
        then Right ()
        else Left $ invalidMetadataError "redirect_uris must not contain URI fragments"

    ensureScheme parsed =
      case URI.uriScheme parsed of
        "https:" -> ensureAuthority parsed
        "http:" ->
          case URI.uriAuthority parsed of
            Just auth
              | isLoopbackHost (T.pack (URI.uriRegName auth)) -> Right ()
              | otherwise -> Left $ invalidMetadataError "http redirect_uris are only allowed for loopback clients"
            Nothing -> Left $ invalidMetadataError "redirect_uris must include a network host component"
        _ -> Left $ invalidMetadataError "redirect_uris must use https scheme"

    ensureAuthority parsed =
      case URI.uriAuthority parsed of
        Just _ -> Right ()
        Nothing -> Left $ invalidMetadataError "redirect_uri must include authority (host)"

    isLoopbackHost hostName =
      hostName == "localhost"
        || hostName == "[::1]"
        || hostName == "::1"
        || isIPv4Loopback hostName

    isIPv4Loopback host =
      case traverse (readMaybe . T.unpack) (T.splitOn "." host) of
        Just [a, b, c, d]
          | a == (127 :: Int)
          , all (\o -> o >= 0 && o <= 255) [b, c, d] -> True
        _ -> False

extractBearerToken :: Maybe Text -> Either ServerError Text
extractBearerToken Nothing =
  Left $ addBearerChallenge $ oauthErrorResponse err401 "invalid_token" (Just "Missing Authorization header")
extractBearerToken (Just headerValue) =
  case T.words headerValue of
    ["Bearer", token] -> tokenOrError token
    ["bearer", token] -> tokenOrError token
    _ -> Left $ addBearerChallenge $ oauthErrorResponse err401 "invalid_token" (Just "Malformed Authorization header")
  where
    tokenOrError tok
      | T.null tok = Left $ addBearerChallenge $ oauthErrorResponse err401 "invalid_token" (Just "Missing bearer token")
      | otherwise = Right tok

registrationNotFound :: Text -> ServerError
registrationNotFound clientId =
  oauthErrorResponse err404 "invalid_client" (Just ("Unknown client_id: " <> clientId))

invalidMetadataError :: Text -> ServerError
invalidMetadataError msg =
  oauthErrorResponse err400 "invalid_client_metadata" (Just msg)

addBearerChallenge :: ServerError -> ServerError
addBearerChallenge err =
  let headerName = "WWW-Authenticate"
      challengeHeader = (headerName, BS8.pack "Bearer realm=\"oauth\"")
      filteredHeaders = filter ((/= headerName) . fst) (errHeaders err)
  in  err{errHeaders = challengeHeader : filteredHeaders}

exceptEither :: Either ServerError a -> ExceptT ServerError IO a
exceptEither = either throwE pure

liftEitherIO :: Either ServerError a -> Handler a
liftEitherIO = either throwError pure
