{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Web.OAuth2.MetadataSpec (tests) where

import Control.Concurrent.MVar (MVar, modifyMVar_)
import Data.Aeson (Value (..), eitherDecode)
import Data.Aeson.KeyMap qualified as KM
import Data.ByteString.Lazy qualified as LBS
import Data.Foldable (toList)
import Network.HTTP.Types (status200)
import Network.Wai (Application)
import Network.Wai.Test
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth2.TestUtils
import Web.OAuth2.Types

tests :: TestTree
tests =
  testGroup
    "Metadata endpoint"
    [ returnsExpectedEndpoints
    , handlesExplicitPortGracefully
    ]

withApp :: (MVar (OAuthState TestUser) -> Application -> IO a) -> IO a
withApp action = do
  (stateVar, _ctx, app) <- createTestApplication
  action stateVar app

fetchMetadata :: Application -> IO Value
fetchMetadata app = do
  res <-
    runSession
      (srequest (SRequest (setPath defaultRequest "/.well-known/oauth-authorization-server") LBS.empty))
      app
  simpleStatus res @?= status200
  case eitherDecode (simpleBody res) of
    Left err -> assertFailure ("Failed to decode metadata: " <> err)
    Right val -> pure val

returnsExpectedEndpoints :: TestTree
returnsExpectedEndpoints = testCase "returns issuer and endpoints for default configuration" $
  withApp $ \_ app -> do
    val <- fetchMetadata app
    case val of
      Object obj -> do
        KM.lookup "issuer" obj @?= Just (String "http://localhost:8080")
        KM.lookup "authorization_endpoint" obj @?= Just (String "http://localhost:8080/authorize")
        KM.lookup "token_endpoint" obj @?= Just (String "http://localhost:8080/token")
        KM.lookup "registration_endpoint" obj @?= Just (String "http://localhost:8080/register")
        case KM.lookup "token_endpoint_auth_methods_supported" obj of
          Just (Array arr) ->
            toList arr @?= [String "none", String "client_secret_post"]
          _ -> assertFailure "token_endpoint_auth_methods_supported missing"
      _ -> assertFailure "metadata response not an object"

handlesExplicitPortGracefully :: TestTree
handlesExplicitPortGracefully = testCase "does not duplicate port when oauth_url already includes it" $
  withApp $ \stateVar app -> do
    modifyMVar_ stateVar $ \s -> pure s{oauth_url = "https://dpella.example:8443/", oauth_port = 8443}
    val <- fetchMetadata app
    case val of
      Object obj -> do
        KM.lookup "issuer" obj @?= Just (String "https://dpella.example:8443/")
        KM.lookup "authorization_endpoint" obj @?= Just (String "https://dpella.example:8443/authorize")
        KM.lookup "token_endpoint" obj @?= Just (String "https://dpella.example:8443/token")
      _ -> assertFailure "metadata response not an object"
