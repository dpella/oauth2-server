{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}

module Web.OAuth2.TokenSpec (tests) where

import Control.Concurrent.Async (concurrently)
import Control.Concurrent.MVar (MVar, readMVar)
import Crypto.Hash (SHA256 (..), hashWith)
import Data.Aeson (Value (..), eitherDecode)
import Data.Aeson.KeyMap qualified as KM
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as B64URL
import Data.ByteString.Char8 qualified as BS8
import Data.ByteString.Lazy qualified as LBS
import Data.List (sort)
import Data.Map.Strict qualified as Map
import Data.Maybe (isJust, isNothing)
import Data.Text (Text)
import Data.Text.Encoding qualified as TE
import Data.Time.Clock
import Network.HTTP.Types (hContentType, methodPost, status200, status400, status401)
import Network.Wai (Application, requestHeaders, requestMethod)
import Network.Wai.Test
import Servant.API.ResponseHeaders (getHeaders, getResponse)
import Test.Tasty
import Test.Tasty.HUnit
import Web.OAuth2.Internal (TokenRequest (..), TokenResponse (..), TokenResponseHeaders, handleTokenRequest)
import Web.OAuth2.TestUtils
import Web.OAuth2.Types hiding (error)
import Web.OAuth2.Types qualified as OAuthTypes

tests :: TestTree
tests =
    testGroup
        "Token endpoint"
        [ tokenEndpointIntegrationTests
        , handlerLevelTests
        ]

tokenEndpointIntegrationTests :: TestTree
tokenEndpointIntegrationTests =
    testGroup
        "Integration"
        [ rejectsMissingVerifier
        , rejectsInvalidVerifier
        , rejectsExpiredAuthCode
        , confidentialClientsRequireSecret
        , rejectsUnknownRefreshToken
        , rejectsRefreshScopeEscalation
        , authorizationCodeSingleUseConcurrent
        , refreshTokenSingleUseConcurrent
        , rejectsDisallowedGrantType
        , rejectsRefreshTokenClientMismatch
        , pkceS256AcceptsValidVerifier
        , pkceDefaultsToPlainWhenMethodOmitted
        , rejectsUnsupportedPkceMethod
        ]

handlerLevelTests :: TestTree
handlerLevelTests =
    testGroup
        "Handler behaviour"
        [ noRefreshTokenIssuedForClientsWithoutGrant
        , refreshTokenIssuedWhenAllowed
        ]

withFreshApp :: (MVar (OAuthState TestUser) -> Application -> IO a) -> IO a
withFreshApp action = do
    (stateVar, _ctx, app) <- createTestApplication
    action stateVar app

decodeOAuthError :: LBS.ByteString -> IO OAuthError
decodeOAuthError body =
    case eitherDecode body of
        Left err -> assertFailure ("Failed to decode OAuthError: " <> err)
        Right val -> pure val

postToken :: Application -> LBS.ByteString -> IO SResponse
postToken app body = do
    let req =
            SRequest
                (setPath defaultRequest "/token")
                    { requestMethod = methodPost
                    , requestHeaders = [(hContentType, "application/x-www-form-urlencoded")]
                    }
                body
    runSession (srequest req) app

mkAuthCodeEntry ::
    Text ->
    Text ->
    Text ->
    Text ->
    UTCTime ->
    Maybe Text ->
    Maybe Text ->
    AuthCode TestUser
mkAuthCodeEntry value clientId redirect scope expiry challenge method =
    AuthCode
        { auth_code_value = value
        , auth_code_client_id = clientId
        , auth_code_user = testUser
        , auth_code_redirect_uri = redirect
        , auth_code_scope = scope
        , auth_code_expiry = expiry
        , auth_code_challenge = challenge
        , auth_code_challenge_method = method
        }

rejectsMissingVerifier :: TestTree
rejectsMissingVerifier = testCase "enforces PKCE code_verifier when challenge stored" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-1" ["http://localhost:4000/cb"] "read write")
        now <- getCurrentTime
        let authCode = mkAuthCodeEntry "code-pkce" "pub-1" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "challenge") (Just "plain")
        addAuthCodeToState stateVar authCode
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-pkce")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "pub-1")
                    ]
                )
        simpleStatus res @?= status400
        lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_request"

rejectsInvalidVerifier :: TestTree
rejectsInvalidVerifier = testCase "rejects mismatched code_verifier" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-2" ["http://localhost:4000/cb"] "read")
        now <- getCurrentTime
        let authCode = mkAuthCodeEntry "code-wrong" "pub-2" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "correct") (Just "plain")
        addAuthCodeToState stateVar authCode
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-wrong")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "pub-2")
                    , ("code_verifier", "incorrect")
                    ]
                )
        simpleStatus res @?= status400
        lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_grant"
        OAuthTypes.error_description errResp @?= Just "Invalid code verifier"

rejectsExpiredAuthCode :: TestTree
rejectsExpiredAuthCode = testCase "rejects expired authorization codes" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-3" ["http://localhost:4000/cb"] "read")
        now <- getCurrentTime
        let authCode = mkAuthCodeEntry "code-expired" "pub-3" "http://localhost:4000/cb" "read" (addUTCTime (-30) now) (Just "verifier") (Just "plain")
        addAuthCodeToState stateVar authCode
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-expired")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "pub-3")
                    , ("code_verifier", "verifier")
                    ]
                )
        simpleStatus res @?= status400
        lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_grant"
        OAuthTypes.error_description errResp @?= Just "Authorization code expired"

confidentialClientsRequireSecret :: TestTree
confidentialClientsRequireSecret = testCase "confidential clients must provide client_secret" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkConfidentialClient "conf-1" "top-secret" ["http://localhost:4000/cb"] "read")
        now <- getCurrentTime
        let authCode = mkAuthCodeEntry "code-conf" "conf-1" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "secret") Nothing
        addAuthCodeToState stateVar authCode
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-conf")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "conf-1")
                    , ("code_verifier", "secret")
                    ]
                )
        simpleStatus res @?= status401
        lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_client"
        st <- readMVar stateVar
        Map.member "code-conf" (auth_codes st) @?= True

rejectsUnknownRefreshToken :: TestTree
rejectsUnknownRefreshToken = testCase "rejects refresh_token grant when token missing" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-4" ["http://localhost:4000/cb"] "read")
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "refresh_token")
                    , ("refresh_token", "does-not-exist")
                    , ("client_id", "pub-4")
                    ]
                )
        simpleStatus res @?= status400
        lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_grant"

rejectsRefreshScopeEscalation :: TestTree
rejectsRefreshScopeEscalation = testCase "rejects refresh token with scope outside client allowance" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-5" ["http://localhost:4000/cb"] "read")
        let refreshTok =
                RefreshToken
                    { refresh_token_value = "rt-1"
                    , refresh_token_client_id = "pub-5"
                    , refresh_token_user = testUser
                    , refresh_token_scope = "write"
                    }
        addRefreshTokenToState stateVar refreshTok
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "refresh_token")
                    , ("refresh_token", "rt-1")
                    , ("client_id", "pub-5")
                    ]
                )
        simpleStatus res @?= status400
        lookup hContentType (simpleHeaders res) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_scope"

authorizationCodeSingleUseConcurrent :: TestTree
authorizationCodeSingleUseConcurrent = testCase "authorization codes cannot be redeemed concurrently" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-6" ["http://localhost:4000/cb"] "read")
        now <- getCurrentTime
        let authCode = mkAuthCodeEntry "code-concurrent" "pub-6" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "verifier") (Just "plain")
            body =
                encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-concurrent")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "pub-6")
                    , ("code_verifier", "verifier")
                    ]
        addAuthCodeToState stateVar authCode
        (resA, resB) <- concurrently (postToken app body) (postToken app body)
        let statuses = sort [simpleStatus resA, simpleStatus resB]
        statuses @?= [status200, status400]
        let (failureRes, successRes) = if simpleStatus resA == status400 then (resA, resB) else (resB, resA)
        lookup hContentType (simpleHeaders failureRes) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse failureRes
        errResp <- decodeOAuthError (simpleBody failureRes)
        OAuthTypes.error errResp @?= "invalid_grant"
        simpleStatus successRes @?= status200
        assertNoStoreHeadersResponse successRes
        stateAfter <- readMVar stateVar
        Map.member "code-concurrent" (auth_codes stateAfter) @?= False

refreshTokenSingleUseConcurrent :: TestTree
refreshTokenSingleUseConcurrent = testCase "refresh tokens rotate under concurrent use" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-7" ["http://localhost:4000/cb"] "read")
        let originalToken =
                RefreshToken
                    { refresh_token_value = "rt-concurrent"
                    , refresh_token_client_id = "pub-7"
                    , refresh_token_user = testUser
                    , refresh_token_scope = "read"
                    }
            body =
                encodeForm
                    [ ("grant_type", "refresh_token")
                    , ("refresh_token", "rt-concurrent")
                    , ("client_id", "pub-7")
                    ]
        addRefreshTokenToState stateVar originalToken
        (resA, resB) <- concurrently (postToken app body) (postToken app body)
        let statuses = sort [simpleStatus resA, simpleStatus resB]
        statuses @?= [status200, status400]
        let (failureRes, successRes) = if simpleStatus resA == status400 then (resA, resB) else (resB, resA)
        lookup hContentType (simpleHeaders failureRes) @?= Just "application/json; charset=utf-8"
        assertNoStoreHeadersResponse failureRes
        errResp <- decodeOAuthError (simpleBody failureRes)
        OAuthTypes.error errResp @?= "invalid_grant"
        simpleStatus successRes @?= status200
        assertNoStoreHeadersResponse successRes
        successValue <-
            case eitherDecode (simpleBody successRes) :: Either String Value of
                Left err -> assertFailure ("Failed to decode success token response: " <> err)
                Right val -> pure val
        newRefresh <-
            case successValue of
                Object obj ->
                    case KM.lookup "refresh_token" obj of
                        Just (String t) -> pure t
                        _ -> assertFailure "refresh_token missing from successful response"
                _ -> assertFailure "Expected object in token response"
        assertBool "rotation produced new token" (newRefresh /= refresh_token_value originalToken)
        stateAfter <- readMVar stateVar
        let persistence = refresh_token_persistence stateAfter
        oldToken <- lookupRefreshToken persistence (refresh_token_value originalToken)
        assertBool "old refresh token removed" (isNothing oldToken)
        newToken <- lookupRefreshToken persistence newRefresh
        assertBool "new refresh token persisted" (isJust newToken)

noRefreshTokenIssuedForClientsWithoutGrant :: TestTree
noRefreshTokenIssuedForClientsWithoutGrant =
    testCase "authorization_code clients without refresh grant do not receive refresh tokens" $ do
        (persistence, readPersisted) <- mkTrackingPersistence
        let client =
                mkRegisteredClient
                    "public-client"
                    ["https://client.example/callback"]
                    ["authorization_code"]
                    ["code"]
                    "read"
                    "none"
                    Nothing
        expiry <- addUTCTime 600 <$> getCurrentTime
        let user = testUser
            authCode = mkAuthCode "auth-code-1" client user expiry "https://client.example/callback" (Just "verifier") Nothing
        stateVar <- mkState persistence [client] [("auth-code-1", authCode)]
        jwtSettings <- mkJWTSettings
        let tokenRequest =
                TokenRequest
                    { grant_type = "authorization_code"
                    , code = Just "auth-code-1"
                    , refresh_token = Nothing
                    , redirect_uri = Just "https://client.example/callback"
                    , client_id = "public-client"
                    , client_secret = Nothing
                    , code_verifier = Just "verifier"
                    }
        result <- runHandler $ handleTokenRequest stateVar (jwtContext jwtSettings) tokenRequest
        tokenResponseHeaders <-
            either (assertFailure . ("Token handler failed: " <>) . show) pure result
        let tokenResponse = getResponse tokenResponseHeaders
        assertBool "refresh_token should be omitted" (isNothing (refresh_token_resp tokenResponse))
        persisted <- readPersisted
        assertBool "no refresh token should be persisted" (null persisted)
        stateAfter <- readMVar stateVar
        assertBool "authorization code should be cleared" (null (auth_codes stateAfter))
        assertNoStoreHeadersFromHeaders tokenResponseHeaders

refreshTokenIssuedWhenAllowed :: TestTree
refreshTokenIssuedWhenAllowed =
    testCase "authorization_code clients with refresh grant receive refresh tokens" $ do
        (persistence, readPersisted) <- mkTrackingPersistence
        let client =
                mkRegisteredClient
                    "confidential-client"
                    ["https://conf.example/cb"]
                    ["authorization_code", "refresh_token"]
                    ["code"]
                    "read"
                    "none"
                    Nothing
        expiry <- addUTCTime 600 <$> getCurrentTime
        let user = testUser
            authCode = mkAuthCode "auth-code-2" client user expiry "https://conf.example/cb" (Just "verifier") Nothing
        stateVar <- mkState persistence [client] [("auth-code-2", authCode)]
        jwtSettings <- mkJWTSettings
        let tokenRequest =
                TokenRequest
                    { grant_type = "authorization_code"
                    , code = Just "auth-code-2"
                    , refresh_token = Nothing
                    , redirect_uri = Just "https://conf.example/cb"
                    , client_id = "confidential-client"
                    , client_secret = Nothing
                    , code_verifier = Just "verifier"
                    }
        result <- runHandler $ handleTokenRequest stateVar (jwtContext jwtSettings) tokenRequest
        tokenResponseHeaders <-
            either (assertFailure . ("Token handler failed: " <>) . show) pure result
        let tokenResponse = getResponse tokenResponseHeaders
        assertBool "refresh_token should be present" (isJust (refresh_token_resp tokenResponse))
        persisted <- readPersisted
        assertEqual "a refresh token should be persisted" 1 (length persisted)
        stateAfter <- readMVar stateVar
        assertBool "authorization code should be cleared" (null (auth_codes stateAfter))
        assertNoStoreHeadersFromHeaders tokenResponseHeaders

assertNoStoreHeadersFromHeaders :: TokenResponseHeaders -> Assertion
assertNoStoreHeadersFromHeaders headers = do
    let actualHeaders = fmap (BS8.unpack . snd) (getHeaders headers)
    assertBool "Cache-Control no-store" ("no-store" `elem` actualHeaders)
    assertBool "Pragma no-cache" ("no-cache" `elem` actualHeaders)

assertNoStoreHeadersResponse :: SResponse -> Assertion
assertNoStoreHeadersResponse res = do
    lookup "Cache-Control" (simpleHeaders res) @?= Just "no-store"
    lookup "Pragma" (simpleHeaders res) @?= Just "no-cache"

rejectsDisallowedGrantType :: TestTree
rejectsDisallowedGrantType = testCase "rejects grant_type not in client's allowed grants" $
    withFreshApp $ \stateVar app -> do
        let client = mkRegisteredClient "authonly" ["http://localhost:4000/cb"] ["authorization_code"] ["code"] "read" "none" Nothing
        addRegisteredClientToState stateVar client
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "refresh_token")
                    , ("refresh_token", "rt-any")
                    , ("client_id", "authonly")
                    ]
                )
        simpleStatus res @?= status400
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "unauthorized_client"

rejectsRefreshTokenClientMismatch :: TestTree
rejectsRefreshTokenClientMismatch = testCase "rejects refresh token issued to a different client" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "client-a" ["http://localhost:4000/cb"] "read")
        addRegisteredClientToState stateVar (mkPublicClient "client-b" ["http://localhost:4000/cb"] "read")
        let refreshTok =
                RefreshToken
                    { refresh_token_value = "rt-stolen"
                    , refresh_token_client_id = "client-a"
                    , refresh_token_user = testUser
                    , refresh_token_scope = "read"
                    }
        addRefreshTokenToState stateVar refreshTok
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "refresh_token")
                    , ("refresh_token", "rt-stolen")
                    , ("client_id", "client-b")
                    ]
                )
        simpleStatus res @?= status400
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_grant"
        OAuthTypes.error_description errResp @?= Just "Client ID mismatch"

-- | Compute a PKCE S256 challenge from a verifier.
s256Challenge :: Text -> Text
s256Challenge verifier =
    let hash = hashWith SHA256 (TE.encodeUtf8 verifier)
        hashBytes = BS.pack (BA.unpack hash)
     in TE.decodeUtf8 (B64URL.encodeUnpadded hashBytes)

pkceS256AcceptsValidVerifier :: TestTree
pkceS256AcceptsValidVerifier = testCase "accepts valid S256 PKCE code_verifier" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-s256" ["http://localhost:4000/cb"] "read")
        now <- getCurrentTime
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            challenge = s256Challenge verifier
            authCode = mkAuthCodeEntry "code-s256" "pub-s256" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just challenge) (Just "S256")
        addAuthCodeToState stateVar authCode
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-s256")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "pub-s256")
                    , ("code_verifier", verifier)
                    ]
                )
        simpleStatus res @?= status200
        assertNoStoreHeadersResponse res

pkceDefaultsToPlainWhenMethodOmitted :: TestTree
pkceDefaultsToPlainWhenMethodOmitted = testCase "PKCE defaults to plain verification when method is omitted" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-nomethod" ["http://localhost:4000/cb"] "read")
        now <- getCurrentTime
        let verifier = "my-plain-verifier"
            authCode = mkAuthCodeEntry "code-nomethod" "pub-nomethod" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just verifier) Nothing
        addAuthCodeToState stateVar authCode
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-nomethod")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "pub-nomethod")
                    , ("code_verifier", verifier)
                    ]
                )
        simpleStatus res @?= status200
        assertNoStoreHeadersResponse res

rejectsUnsupportedPkceMethod :: TestTree
rejectsUnsupportedPkceMethod = testCase "rejects unsupported PKCE code_challenge_method" $
    withFreshApp $ \stateVar app -> do
        addRegisteredClientToState stateVar (mkPublicClient "pub-badmethod" ["http://localhost:4000/cb"] "read")
        now <- getCurrentTime
        let authCode = mkAuthCodeEntry "code-badmethod" "pub-badmethod" "http://localhost:4000/cb" "read" (addUTCTime 600 now) (Just "challenge") (Just "RS256")
        addAuthCodeToState stateVar authCode
        res <-
            postToken
                app
                ( encodeForm
                    [ ("grant_type", "authorization_code")
                    , ("code", "code-badmethod")
                    , ("redirect_uri", "http://localhost:4000/cb")
                    , ("client_id", "pub-badmethod")
                    , ("code_verifier", "challenge")
                    ]
                )
        simpleStatus res @?= status400
        assertNoStoreHeadersResponse res
        errResp <- decodeOAuthError (simpleBody res)
        OAuthTypes.error errResp @?= "invalid_grant"
