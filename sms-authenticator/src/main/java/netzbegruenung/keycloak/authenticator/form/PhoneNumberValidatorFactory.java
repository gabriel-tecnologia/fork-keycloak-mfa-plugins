package netzbegruenung.keycloak.authenticator.form;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class PhoneNumberValidatorFactory implements FormActionFactory {

	private static final PhoneNumberValidator SINGLETON = new PhoneNumberValidator();

	@Override
	public String getDisplayType() {
		return SINGLETON.getDisplayType();
	}

	@Override
	public String getReferenceCategory() {
		return SINGLETON.getReferenceCategory();
	}

	@Override
	public boolean isConfigurable() {
		return SINGLETON.isConfigurable();
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return new AuthenticationExecutionModel.Requirement[]{
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.DISABLED,
			AuthenticationExecutionModel.Requirement.ALTERNATIVE
		};
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return "Validates phone number format and stores it in user attributes.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return SINGLETON.getConfigProperties();
	}

	@Override
	public FormAction create(KeycloakSession keycloakSession) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope scope) {

	}

	@Override
	public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

	}

	@Override
	public void close() {

	}

	@Override
	public String getId() {
		return SINGLETON.getId();
	}
}
