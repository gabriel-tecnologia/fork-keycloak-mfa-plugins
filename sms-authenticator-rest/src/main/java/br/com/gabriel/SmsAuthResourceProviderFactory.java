package br.com.gabriel;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@AutoService(RealmResourceProviderFactory.class)
public class SmsAuthResourceProviderFactory implements RealmResourceProviderFactory {
	public static final String PROVIDER_ID = "sms-auth";

	@Override
	public RealmResourceProvider create(KeycloakSession keycloakSession) {
		return new SmsAuthResourceProvider(keycloakSession);
	}

	@Override
	public void init(Config.Scope scope) {
		// No initialization needed
	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
		// No post-initialization needed
	}

	@Override
	public void close() {
		// No resources to close
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}
}
