package br.com.gabriel;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.utils.MediaType;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

@Provider
@Path("/realms/{realm}/auth/{deliveryOption}")
public class SmsAuthResourceProvider implements RealmResourceProvider {
	private static final Logger logger = Logger.getLogger(SmsAuthResourceProvider.class.getName());

	private static final int VERIFICATION_CODE_LENGTH = 6;
	private static final int VERIFICATION_CODE_TTL = 300; // 5 minutes
	private static final ArrayList<String> VALID_DELIVERY_OPTIONS= new ArrayList<>(List.of("sms", "email"));

	private final KeycloakSession session;

	public SmsAuthResourceProvider(KeycloakSession session) {
		this.session = session;
	}

	@Override
	public Object getResource() {
		return this;
	}

	@Override
	public void close() {
	}

	@GET
	@Path("test")
	public Response test() {
		logger.info("Test endpoint called");
		return Response.ok("SMS Auth provider is working!").build();
	}

	@POST
	@Path("init")
	@Produces(MediaType.APPLICATION_JSON)
	public Response initAuth(
		@PathParam("realm") String realmName,
		@PathParam("deliveryOption") String deliveryOption,
		@FormParam("phoneNumber") String phoneNumber,
		@FormParam("email") String email,
		@FormParam("client_id") String clientId){

		try {

			if(!VALID_DELIVERY_OPTIONS.contains(deliveryOption)){
				logger.severe("Invalid deliveryOption: " + deliveryOption);
				throw new WebApplicationException("The delivery option: " + deliveryOption + "isn't supported.", Response.Status.BAD_REQUEST);
			}

			// Validate and find required entities
			RealmModel realm = findRealm(realmName);
			ClientModel client = findClient(realm, clientId);
			UserModel user;

			if(phoneNumber != null && !phoneNumber.isEmpty()){
				user = findUserByPhone(realm, phoneNumber);
			} else {
				user = session.users().getUserByEmail(realm, email);
			}

			// Create authentication session
			AuthenticationSessionModel authSession = createAuthSession(realm, client, user);

			switch (deliveryOption) {
				case "email": {
					Map<String, Object> mailBodyAttributes = new HashMap<>();
					mailBodyAttributes.put("username", user.getUsername());
					mailBodyAttributes.put("code", authSession.getAuthNote("code"));
					mailBodyAttributes.put("ttl", VERIFICATION_CODE_TTL);
					List<Object> subjectParams = List.of(realmName);
					try {
						EmailTemplateProvider emailProvider = (EmailTemplateProvider) session.getProvider(EmailTemplateProvider.class);
						emailProvider.setRealm(realm);
						emailProvider.setUser(user);
						emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
					} catch (EmailException emailException) {
						logger.severe("Failed to send email: " + emailException.getMessage());
					}
					break;
				}
				case "sms": {
					sendVerificationSms(phoneNumber, authSession.getAuthNote("code"));
					break;
				}
				default: {
					throw new WebApplicationException("Invalid deliveryOption: " + deliveryOption, Response.Status.BAD_REQUEST);
				}
			}

			// Prepare response
			return Response.ok()
				.entity(Map.of(
					"message", deliveryOption + " sent successfully",
					"expires_in", VERIFICATION_CODE_TTL,
					"session_id", authSession.getParentSession().getId()
				))
				.build();

		} catch (WebApplicationException e) {
			return e.getResponse();
		} catch (Exception e) {
			logger.warning("Failed to initialize SMS authentication: " + e.getMessage());
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(Map.of("error", "Authentication initialization failed"))
				.build();
		}
	}

	@POST
	@Path("verify")
	@Produces(MediaType.APPLICATION_JSON)
	public Response verify(
		@PathParam("realm") String realmName,
		@FormParam("code") String enteredCode,
		@FormParam("session_id") String sessionId) {

		logger.info("Starting SMS verification");

		try {
			// Validate and find required entities
			RealmModel realm = findRealm(realmName);
			AuthenticationSessionModel authSession = findAuthenticationSession(realm, sessionId);

			// Validate verification code
			validateVerificationCode(authSession, enteredCode);

			// Prepare session context
			prepareSessionContext(realm, authSession);

			// Generate and return access token
			return createAccessTokenResponse(realm, authSession);

		} catch (WebApplicationException e) {
			return e.getResponse();
		} catch (Exception e) {
			logger.warning("Verification failed: " + e.getMessage());
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(Map.of("error", "Verification failed"))
				.build();
		}
	}

	private RealmModel findRealm(String realmName) {
		RealmModel realm = session.realms().getRealmByName(realmName);
		if (realm == null) {
			throw createWebApplicationException("Realm not found", Response.Status.BAD_REQUEST);
		}
		session.getContext().setRealm(realm);
		return realm;
	}

	private ClientModel findClient(RealmModel realm, String clientId) {
		ClientModel client = realm.getClientByClientId(clientId);
		if (client == null) {
			throw createWebApplicationException("Client not found", Response.Status.BAD_REQUEST);
		}
		return client;
	}

	private UserModel findUserByPhone(RealmModel realm, String phoneNumber) {
		return session.users().searchForUserByUserAttributeStream(realm, "phoneNumber", phoneNumber)
			.findFirst()
			.orElseThrow(() -> createWebApplicationException("No user found with this phone number", Response.Status.NOT_FOUND));
	}

	private AuthenticationSessionModel createAuthSession(
		RealmModel realm,
		ClientModel client,
		UserModel user) {

		AuthenticationSessionModel authSession = session.getProvider(AuthenticationSessionProvider.class)
			.createRootAuthenticationSession(realm)
			.createAuthenticationSession(client);

		String code = SecretGenerator.getInstance().randomString(VERIFICATION_CODE_LENGTH, SecretGenerator.DIGITS);
		logger.info("Generated verification code: " + code);

		authSession.setAuthNote("code", code);
		authSession.setAuthNote("ttl", String.valueOf(System.currentTimeMillis() + (VERIFICATION_CODE_TTL * 1000L)));
		authSession.setAuthNote("auth_username", user.getUsername());

		return authSession;
	}

	private void sendVerificationSms(String phoneNumber, String code) {
		try {
			String smsText = String.format("Your verification code is: %s (valid for %d minutes)",
				code, VERIFICATION_CODE_TTL / 60);

			Map<String, String> smsConfig = new HashMap<>();
			smsConfig.put("gateway", "test");

			SmsServiceFactory.get(smsConfig).send(phoneNumber, smsText);
			logger.info("SMS sent successfully to " + phoneNumber);
		} catch (Exception e) {
			throw createWebApplicationException("Failed to send SMS", Response.Status.INTERNAL_SERVER_ERROR);
		}
	}

	private AuthenticationSessionModel findAuthenticationSession(RealmModel realm, String sessionId) {
		if (sessionId == null) {
			throw createWebApplicationException("Session ID is required", Response.Status.BAD_REQUEST);
		}

		return session.getProvider(AuthenticationSessionProvider.class)
			.getRootAuthenticationSession(realm, sessionId)
			.getAuthenticationSessions()
			.values()
			.stream()
			.findFirst()
			.orElseThrow(() -> createWebApplicationException("No matching authentication session found", Response.Status.BAD_REQUEST));
	}

	private void validateVerificationCode(AuthenticationSessionModel authSession, String enteredCode) {
		String storedCode = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (storedCode == null || ttl == null) {
			throw createWebApplicationException("Invalid authentication session", Response.Status.INTERNAL_SERVER_ERROR);
		}

		if (!enteredCode.equals(storedCode)) {
			throw createWebApplicationException("Invalid verification code", Response.Status.UNAUTHORIZED);
		}

		if (Long.parseLong(ttl) < System.currentTimeMillis()) {
			throw createWebApplicationException("Verification code expired", Response.Status.BAD_REQUEST);
		}
	}

	private void prepareSessionContext(RealmModel realm, AuthenticationSessionModel authSession) {
		ClientModel client = authSession.getClient();
		session.getContext().setRealm(realm);
		session.getContext().setClient(client);
	}

	private Response createAccessTokenResponse(RealmModel realm, AuthenticationSessionModel authSession) {
		try {
			ClientModel client = authSession.getClient();
			String username = authSession.getAuthNote("auth_username");
			UserModel user = session.users().getUserByUsername(realm, username);

			// Create authentication event
			EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());

			// Create token manager
			TokenManager tokenManager = new TokenManager();

			// Create user session
			UserSessionModel userSession = session.sessions().createUserSession(
				realm, user, username, null, "bearer-only", false, null, null);

			// Create or get client session
			AuthenticatedClientSessionModel clientSession =
				userSession.getAuthenticatedClientSessionByClient(client.getId());
			if (clientSession == null) {
				clientSession = session.sessions().createClientSession(realm, client, userSession);
			}

			// Create ClientSessionContext
			ClientSessionContext clientSessionCtx =
				DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, session);

			// Generate access token
			AccessToken token = tokenManager.createClientAccessToken(
				session, realm, client, user, userSession, clientSessionCtx);

			// Create response with tokens
			AccessTokenResponse accessTokenResponse = tokenManager.responseBuilder(
					realm, client, event, session, userSession, clientSessionCtx)
				.accessToken(token)
				.build();

			return Response.ok(accessTokenResponse).build();

		} catch (Exception e) {
			logger.warning("Token generation failed: " + e.getMessage());
			throw createWebApplicationException(
				"Token generation failed",
				Response.Status.INTERNAL_SERVER_ERROR
			);
		}
	}

	private WebApplicationException createWebApplicationException(String message, Response.Status status) {
		return new WebApplicationException(
			Response.status(status)
				.entity(Map.of("error", message))
				.build()
		);
	}
}
