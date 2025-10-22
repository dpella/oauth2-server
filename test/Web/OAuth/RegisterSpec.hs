{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.OAuth.RegisterSpec (tests) where

import Control.Concurrent.MVar (MVar, readMVar)
import Data.Aeson
import Data.Aeson.Key (toText)
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KM
import Data.ByteString.Char8 qualified as BS8
import Data.ByteString.Lazy qualified as LBS
import Data.Foldable (toList)
import Data.Map.Strict qualified as Map
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Network.HTTP.Types (HeaderName, hAuthorization, hContentType, methodDelete, methodPost, methodPut, status200, status201, status204, status400, status401, status404)
import Network.Wai (Application, requestHeaders, requestMethod)
import Network.Wai.Test
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth.TestUtils
import Web.OAuth.Types

tests :: TestTree
tests =
  testGroup
    "Register endpoint"
    [ appliesDefaultsForPublicClients
    , issuesSecretForConfidentialClients
    , exposesManagementCredentials
    , managementGetReturnsClientMetadata
    , managementRejectsInvalidToken
    , managementUpdateAppliesChanges
    , managementDeleteRemovesClient
    , honorsRequestedScope
    , rejectsEmptyRedirectUris
    , rejectsRelativeRedirectUris
    , rejectsInsecureRedirectUris
    , acceptsExtendedLoopbackRedirects
    , rejectsUnsupportedAuthMethod
    ]

withApp :: (MVar (OAuthState TestUser) -> Application -> IO a) -> IO a
withApp action = do
  (stateVar, _ctx, app) <- createTestApplication
  action stateVar app

registerClient :: Application -> Value -> IO SResponse
registerClient app payload = do
  let req =
        SRequest
          ( setPath defaultRequest "/register"
              ){ requestMethod = methodPost
               , requestHeaders = [(hContentType, "application/json")]
               }
          (encode payload)
  runSession (srequest req) app

extractObject :: LBS.ByteString -> IO Object
extractObject body =
  case eitherDecode body of
    Left err -> assertFailure ("Failed to decode registration response: " <> err)
    Right (Object o) -> pure o
    Right _ -> assertFailure "Expected JSON object in registration response"

decodeRegistrationError :: LBS.ByteString -> IO OAuthError
decodeRegistrationError body =
  case eitherDecode body of
    Left err -> assertFailure ("Failed to decode registration error: " <> err)
    Right val -> pure val

appliesDefaultsForPublicClients :: TestTree
appliesDefaultsForPublicClients = testCase "fills defaults for omitted fields" $
  withApp $ \stateVar app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Minimal App" :: Text)
            , "redirect_uris" .= ["http://localhost:4000/callback" :: Text]
            ]
        )
    simpleStatus res @?= status201
    obj <- extractObject (simpleBody res)
    let getTextField key =
          case KM.lookup key obj of
            Just (String t) -> pure t
            _ -> assertFailure ("Missing text field: " <> T.unpack (toText key))
        getTextArray key =
          case KM.lookup key obj of
            Just (Array arr) ->
              pure [t | String t <- toList arr]
            _ -> assertFailure ("Missing array field: " <> T.unpack (toText key))
    clientId <- getTextField "client_id"
    assertBool "client_id non-empty" (not (T.null clientId))
    tokenMethod <- getTextField "token_endpoint_auth_method"
    tokenMethod @?= "none"
    grants <- getTextArray "grant_types"
    grants @?= ["authorization_code", "refresh_token"]
    responses <- getTextArray "response_types"
    responses @?= ["code"]
    scopeVal <- getTextField "scope"
    scopeVal @?= "read write"
    regToken <- getTextField "registration_access_token"
    assertBool "registration_access_token non-empty" (not (T.null regToken))
    regUri <- getTextField "registration_client_uri"
    assertBool "registration_client_uri includes client id" (clientId `T.isInfixOf` regUri)
    assertBool "client_secret absent" (KM.lookup "client_secret" obj == Nothing)
    assertBool "client_secret_expires_at absent" (KM.lookup "client_secret_expires_at" obj == Nothing)

    st <- readMVar stateVar
    case Map.lookup clientId (registered_clients st) of
      Just c -> do
        registered_client_grant_types c @?= ["authorization_code", "refresh_token"]
        registered_client_secret c @?= Nothing
        registered_client_registration_access_token c @?= Just regToken
      Nothing -> assertFailure "Client not persisted in state"

issuesSecretForConfidentialClients :: TestTree
issuesSecretForConfidentialClients = testCase "returns secret for confidential registration and stores it" $
  withApp $ \stateVar app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Confidential" :: Text)
            , "redirect_uris" .= ["https://localhost/callback" :: Text]
            , "grant_types" .= ["authorization_code" :: Text]
            , "token_endpoint_auth_method" .= ("client_secret_post" :: Text)
            ]
        )
    simpleStatus res @?= status201
    obj <- extractObject (simpleBody res)
    secretField <-
      case KM.lookup "client_secret" obj of
        Just (String s) -> pure s
        _ -> assertFailure "client_secret missing"
    let expiryField = KM.lookup "client_secret_expires_at" obj
    assertBool "expiry omitted" (expiryField == Nothing)
    clientId <-
      case KM.lookup "client_id" obj of
        Just (String cid) -> pure cid
        _ -> assertFailure "client_id missing"
    assertBool "secret non-empty" (not (T.null secretField))
    registrationToken <-
      case KM.lookup "registration_access_token" obj of
        Just (String tok) -> pure tok
        _ -> assertFailure "registration_access_token missing"

    st <- readMVar stateVar
    case Map.lookup clientId (registered_clients st) of
      Nothing -> assertFailure "Client not persisted for confidential registration"
      Just client -> do
        registered_client_secret client @?= Just secretField
        registered_client_token_endpoint_auth_method client @?= "client_secret_post"
        registered_client_registration_access_token client @?= Just registrationToken

exposesManagementCredentials :: TestTree
exposesManagementCredentials = testCase "includes management token and URI in response" $
  withApp $ \stateVar app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Management App" :: Text)
            , "redirect_uris" .= ["http://localhost:4000/callback" :: Text]
            ]
        )
    simpleStatus res @?= status201
    obj <- extractObject (simpleBody res)
    clientId <-
      case KM.lookup "client_id" obj of
        Just (String cid) -> pure cid
        _ -> assertFailure "client_id missing"
    managementToken <-
      case KM.lookup "registration_access_token" obj of
        Just (String tok) -> pure tok
        _ -> assertFailure "registration_access_token missing"
    managementUri <-
      case KM.lookup "registration_client_uri" obj of
        Just (String uriTxt) -> pure uriTxt
        _ -> assertFailure "registration_client_uri missing"
    managementUri @?= "http://localhost:8080/register/" <> clientId
    st <- readMVar stateVar
    case Map.lookup clientId (registered_clients st) of
      Nothing -> assertFailure "Client not persisted"
      Just client ->
        registered_client_registration_access_token client @?= Just managementToken

managementGetReturnsClientMetadata :: TestTree
managementGetReturnsClientMetadata = testCase "management GET returns stored metadata" $
  withApp $ \_ app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Mgmt GET" :: Text)
            , "redirect_uris" .= ["http://localhost:4000/callback" :: Text]
            ]
        )
    simpleStatus res @?= status201
    regObj <- extractObject (simpleBody res)
    clientId <- requireTextField "client_id" regObj
    managementToken <- requireTextField "registration_access_token" regObj
    getRes <-
      runSession
        ( srequest
            ( SRequest
                ( setPath defaultRequest (registrationPath clientId)
                    ){ requestHeaders = [bearerHeader managementToken]
                     }
                LBS.empty
            )
        )
        app
    simpleStatus getRes @?= status200
    getObj <- extractObject (simpleBody getRes)
    KM.lookup "client_id" getObj @?= Just (String clientId)
    KM.lookup "registration_access_token" getObj @?= Just (String managementToken)
    KM.lookup "registration_client_uri" getObj @?= Just (String ("http://localhost:8080/register/" <> clientId))

managementRejectsInvalidToken :: TestTree
managementRejectsInvalidToken = testCase "management endpoints reject missing or invalid tokens" $
  withApp $ \_ app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Mgmt Invalid" :: Text)
            , "redirect_uris" .= ["http://localhost:4000/callback" :: Text]
            ]
        )
    simpleStatus res @?= status201
    regObj <- extractObject (simpleBody res)
    clientId <- requireTextField "client_id" regObj
    -- Missing header
    resMissing <-
      runSession
        ( srequest
            ( SRequest
                ( setPath defaultRequest (registrationPath clientId)
                    ){ requestHeaders = []
                     }
                LBS.empty
            )
        )
        app
    simpleStatus resMissing @?= status401
    -- Wrong token
    resWrong <-
      runSession
        ( srequest
            ( SRequest
                ( setPath defaultRequest (registrationPath clientId)
                    ){ requestHeaders = [bearerHeader "not-the-token"]
                     }
                LBS.empty
            )
        )
        app
    simpleStatus resWrong @?= status401

managementUpdateAppliesChanges :: TestTree
managementUpdateAppliesChanges = testCase "PUT replaces client metadata and persists" $
  withApp $ \stateVar app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Mgmt Update" :: Text)
            , "redirect_uris" .= ["https://localhost/callback" :: Text]
            , "scope" .= ("read write" :: Text)
            ]
        )
    simpleStatus res @?= status201
    regObj <- extractObject (simpleBody res)
    clientId <- requireTextField "client_id" regObj
    managementToken <- requireTextField "registration_access_token" regObj
    let updatePayload =
          object
            [ "client_name" .= ("Mgmt Update v2" :: Text)
            , "redirect_uris" .= ["https://localhost/updated" :: Text]
            , "scope" .= ("profile email" :: Text)
            , "grant_types" .= ["authorization_code", "refresh_token" :: Text]
            , "response_types" .= ["code" :: Text]
            , "token_endpoint_auth_method" .= ("none" :: Text)
            ]
    updateRes <-
      runSession
        ( srequest
            ( SRequest
                ( setPath defaultRequest (registrationPath clientId)
                    ){ requestMethod = methodPut
                     , requestHeaders =
                        [ bearerHeader managementToken
                        , (hContentType, "application/json")
                        ]
                     }
                (encode updatePayload)
            )
        )
        app
    simpleStatus updateRes @?= status200
    updateObj <- extractObject (simpleBody updateRes)
    KM.lookup "scope" updateObj @?= Just (String "profile email")
    KM.lookup "client_name" updateObj @?= Just (String "Mgmt Update v2")
    st <- readMVar stateVar
    case Map.lookup clientId (registered_clients st) of
      Nothing -> assertFailure "Client missing after update"
      Just client -> do
        registered_client_scope client @?= "profile email"
        registered_client_redirect_uris client @?= ["https://localhost/updated"]

managementDeleteRemovesClient :: TestTree
managementDeleteRemovesClient = testCase "DELETE removes client and subsequent GET returns 404" $
  withApp $ \stateVar app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Mgmt Delete" :: Text)
            , "redirect_uris" .= ["http://localhost:4000/callback" :: Text]
            ]
        )
    simpleStatus res @?= status201
    regObj <- extractObject (simpleBody res)
    clientId <- requireTextField "client_id" regObj
    managementToken <- requireTextField "registration_access_token" regObj
    deleteRes <-
      runSession
        ( srequest
            ( SRequest
                ( setPath defaultRequest (registrationPath clientId)
                    ){ requestMethod = methodDelete
                     , requestHeaders = [bearerHeader managementToken]
                     }
                LBS.empty
            )
        )
        app
    simpleStatus deleteRes @?= status204
    st <- readMVar stateVar
    Map.lookup clientId (registered_clients st) @?= Nothing
    afterDelete <-
      runSession
        ( srequest
            ( SRequest
                ( setPath defaultRequest (registrationPath clientId)
                    ){ requestHeaders = [bearerHeader managementToken]
                     }
                LBS.empty
            )
        )
        app
    simpleStatus afterDelete @?= status404

honorsRequestedScope :: TestTree
honorsRequestedScope = testCase "persists provided scope field" $
  withApp $ \stateVar app -> do
    let customScope = "profile email"
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Scoped App" :: Text)
            , "redirect_uris" .= ["https://localhost/callback" :: Text]
            , "scope" .= customScope
            ]
        )
    simpleStatus res @?= status201
    obj <- extractObject (simpleBody res)
    case KM.lookup "scope" obj of
      Just (String scopeVal) -> scopeVal @?= customScope
      _ -> assertFailure "scope field missing in response"
    case KM.lookup "client_id" obj of
      Just (String cid) -> do
        st <- readMVar stateVar
        case Map.lookup cid (registered_clients st) of
          Nothing -> assertFailure "registered client missing from state"
          Just client -> registered_client_scope client @?= customScope
        metadataRes <-
          runSession
            ( srequest
                (SRequest (setPath defaultRequest "/.well-known/oauth-authorization-server") LBS.empty)
            )
            app
        simpleStatus metadataRes @?= status200
        metadataObj <-
          case eitherDecode (simpleBody metadataRes) of
            Left err -> assertFailure ("Failed to decode metadata: " <> err)
            Right (Object o) -> pure o
            Right _ -> assertFailure "Metadata response not an object"
        case KM.lookup "scopes_supported" metadataObj of
          Just (Array arr) ->
            let scopes = [t | String t <- toList arr]
            in  assertBool "metadata scopes include custom scope tokens" (all (`elem` scopes) (T.words customScope))
          _ -> assertFailure "scopes_supported missing from metadata"
      _ -> assertFailure "client_id missing in response"

rejectsEmptyRedirectUris :: TestTree
rejectsEmptyRedirectUris = testCase "rejects registrations without redirect URIs" $
  withApp $ \_ app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("No Redirects" :: Text)
            , "redirect_uris" .= ([] :: [Text])
            ]
        )
    simpleStatus res @?= status400
    err <- decodeRegistrationError (simpleBody res)
    Web.OAuth.Types.error err @?= "invalid_client_metadata"

registrationPath :: Text -> BS8.ByteString
registrationPath clientId = BS8.concat ["/register/", TE.encodeUtf8 clientId]

bearerHeader :: Text -> (HeaderName, BS8.ByteString)
bearerHeader token = (hAuthorization, TE.encodeUtf8 ("Bearer " <> token))

requireTextField :: Text -> Object -> IO Text
requireTextField key obj =
  case KM.lookup (Key.fromText key) obj of
    Just (String val) -> pure val
    _ -> assertFailure ("Missing text field: " <> T.unpack key)

rejectsUnsupportedAuthMethod :: TestTree
rejectsUnsupportedAuthMethod = testCase "rejects token auth methods the server cannot fulfill" $
  withApp $ \_ app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Bad Auth" :: Text)
            , "redirect_uris" .= ["https://localhost/callback" :: Text]
            , "token_endpoint_auth_method" .= ("client_secret_basic" :: Text)
            ]
        )
    simpleStatus res @?= status400
    err <- decodeRegistrationError (simpleBody res)
    Web.OAuth.Types.error err @?= "invalid_client_metadata"

rejectsRelativeRedirectUris :: TestTree
rejectsRelativeRedirectUris = testCase "rejects non-absolute redirect URIs" $
  withApp $ \_ app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Relative Redirect" :: Text)
            , "redirect_uris" .= ["/callback" :: Text]
            ]
        )
    simpleStatus res @?= status400
    err <- decodeRegistrationError (simpleBody res)
    Web.OAuth.Types.error err @?= "invalid_client_metadata"

rejectsInsecureRedirectUris :: TestTree
rejectsInsecureRedirectUris = testCase "rejects non-loopback http redirect URIs" $
  withApp $ \_ app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Insecure Redirect" :: Text)
            , "redirect_uris" .= ["http://example.com/callback" :: Text]
            ]
        )
    simpleStatus res @?= status400
    err <- decodeRegistrationError (simpleBody res)
    Web.OAuth.Types.error err @?= "invalid_client_metadata"

acceptsExtendedLoopbackRedirects :: TestTree
acceptsExtendedLoopbackRedirects = testCase "accepts any 127.0.0.0/8 redirect host" $
  withApp $ \_ app -> do
    res <-
      registerClient
        app
        ( object
            [ "client_name" .= ("Loopback" :: Text)
            , "redirect_uris" .= ["http://127.10.20.30/callback" :: Text]
            ]
        )
    simpleStatus res @?= status201
