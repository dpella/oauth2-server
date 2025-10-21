{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Web.OAuth.RegisterSpec (tests) where

import Control.Concurrent.MVar (MVar, readMVar)
import Data.Aeson
import Data.Aeson.Key (toText)
import Data.Aeson.KeyMap qualified as KM
import Data.ByteString.Lazy qualified as LBS
import Data.Foldable (toList)
import Data.Map.Strict qualified as Map
import Data.Scientific (toBoundedInteger)
import Data.Text (Text)
import Data.Text qualified as T
import Network.HTTP.Types (hContentType, methodPost, status200)
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
    simpleStatus res @?= status200
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
    KM.lookup "client_secret" obj @?= Just Null
    KM.lookup "client_secret_expires_at" obj @?= Just Null

    st <- readMVar stateVar
    case Map.lookup clientId (registered_clients st) of
      Just c -> do
        registered_client_grant_types c @?= ["authorization_code", "refresh_token"]
        registered_client_secret c @?= Nothing
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
    simpleStatus res @?= status200
    obj <- extractObject (simpleBody res)
    secretField <-
      case KM.lookup "client_secret" obj of
        Just (String s) -> pure s
        _ -> assertFailure "client_secret missing"
    expiryField <-
      case KM.lookup "client_secret_expires_at" obj of
        Just (Number n) ->
          case toBoundedInteger @Int n of
            Just i -> pure i
            Nothing -> assertFailure "client_secret_expires_at not an integer"
        _ -> assertFailure "client_secret_expires_at missing"
    clientId <-
      case KM.lookup "client_id" obj of
        Just (String cid) -> pure cid
        _ -> assertFailure "client_id missing"
    assertBool "secret non-empty" (not (T.null secretField))
    expiryField @?= 0

    st <- readMVar stateVar
    case Map.lookup clientId (registered_clients st) of
      Nothing -> assertFailure "Client not persisted for confidential registration"
      Just client -> do
        registered_client_secret client @?= Just secretField
        registered_client_token_endpoint_auth_method client @?= "client_secret_post"
