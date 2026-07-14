package io.dalang.sso;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Client for the Dalang SSO OAuth 2.0 / OpenID Connect provider.
 *
 * <p>Drives the Authorization Code + PKCE flow against a self-hosted Dalang SSO
 * instance. Mirrors the Google OAuth client shape: you configure a client_id,
 * client_secret, and redirect_uri, then build an authorize URL, exchange the
 * returned code for tokens, refresh tokens, and fetch userinfo.
 */
public final class SsoClient {

    /** Response from the token endpoint. */
    public static final class Tokens {
        public final String accessToken;
        public final String tokenType;
        public final long expiresIn;
        public final String refreshToken; // nullable
        public final String idToken;      // nullable
        public final String scope;

        Tokens(String accessToken, String tokenType, long expiresIn,
               String refreshToken, String idToken, String scope) {
            this.accessToken = accessToken;
            this.tokenType = tokenType;
            this.expiresIn = expiresIn;
            this.refreshToken = refreshToken;
            this.idToken = idToken;
            this.scope = scope;
        }
    }

    /** Response from the userinfo endpoint. */
    public static final class UserInfo {
        public final String sub;
        public final String email;

        UserInfo(String sub, String email) {
            this.sub = sub;
            this.email = email;
        }
    }

    /** Thrown when the token endpoint returns a 4xx {error, error_description}. */
    public static final class OAuthException extends RuntimeException {
        public final String code;
        public final String description;

        OAuthException(String code, String description) {
            super("oauth error: " + code + " — " + description);
            this.code = code;
            this.description = description;
        }
    }

    private final String baseUrl;
    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * @param baseUrl the SSO instance root, e.g. "https://sso.example.com"
     */
    public SsoClient(String baseUrl, String clientId, String clientSecret, String redirectUri) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.http = HttpClient.newHttpClient();
    }

    /** Build the URL to redirect the user's browser to for consent. */
    public String authorizeUrl(String scope, String state, Pkce pkce) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        params.put("scope", scope);
        params.put("state", state);
        if (pkce != null) {
            params.put("code_challenge", pkce.challenge);
            params.put("code_challenge_method", "S256");
        }
        return baseUrl + "/oauth/authorize?" + formEncode(params);
    }

    /** Exchange an authorization code for tokens. Pass null pkce to skip PKCE. */
    public Tokens exchangeCode(String code, Pkce pkce) throws IOException, InterruptedException {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", redirectUri);
        form.put("client_id", clientId);
        form.put("client_secret", clientSecret);
        if (pkce != null) {
            form.put("code_verifier", pkce.verifier);
        }
        return postToken(form);
    }

    /** Exchange a refresh token for a fresh set of tokens. */
    public Tokens refresh(String refreshToken) throws IOException, InterruptedException {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        form.put("client_id", clientId);
        form.put("client_secret", clientSecret);
        return postToken(form);
    }

    /** Fetch the profile for a given access token. */
    public UserInfo userInfo(String accessToken) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/oauth/userinfo"))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() >= 400) {
            throw new IOException("userinfo request failed (" + resp.statusCode() + "): " + resp.body());
        }
        JsonNode json = mapper.readTree(resp.body());
        return new UserInfo(text(json, "sub"), text(json, "email"));
    }

    private Tokens postToken(Map<String, String> form) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/oauth/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        JsonNode json = mapper.readTree(resp.body());
        if (resp.statusCode() >= 400) {
            throw new OAuthException(text(json, "error"), text(json, "error_description"));
        }
        return new Tokens(
                text(json, "access_token"),
                json.has("token_type") ? json.get("token_type").asText() : "Bearer",
                json.has("expires_in") ? json.get("expires_in").asLong() : 0L,
                json.hasNonNull("refresh_token") ? json.get("refresh_token").asText() : null,
                json.hasNonNull("id_token") ? json.get("id_token").asText() : null,
                text(json, "scope"));
    }

    private static String text(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.get(field).asText() : "";
    }

    /** URL-form-encode a map as key=value&key=value. */
    private static String formEncode(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }
}
