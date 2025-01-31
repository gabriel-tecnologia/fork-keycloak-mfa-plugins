package netzbegruenung.keycloak.authenticator.form;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class PhoneNumberValidator implements FormAction {
	public static final String PROVIDER_ID = "phone-number-validator";
	public static final String PHONE_FIELD = "phone_number";
	private static final Pattern PHONE_PATTERN = Pattern.compile("^\\+?[1-9]\\d{1,14}$");

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

	static {
		ProviderConfigProperty property = new ProviderConfigProperty();
		property.setName("phone_required");
		property.setLabel("Required");
		property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
		property.setHelpText("Is phone number required?");
		CONFIG_PROPERTIES.add(property);
	}

	@Override
	public void buildPage(FormContext formContext, LoginFormsProvider loginFormsProvider) {
		loginFormsProvider.setAttribute("phone_number", "");
	}

	@Override
	public void validate(ValidationContext validationContext) {
		MultivaluedMap<String, String> formData = validationContext.getHttpRequest().getDecodedFormParameters();
		String phoneNumber = formData.getFirst(PHONE_FIELD);

		if (isPhoneRequired(validationContext) && (phoneNumber == null || phoneNumber.trim().isEmpty())) {
			validationContext.error("Phone number is required.");
			validationContext.validationError(formData, List.of(new FormMessage(PHONE_FIELD, "Please enter your phone number")));
			return;
		}

		if (phoneNumber != null && !phoneNumber.trim().isEmpty() && !PHONE_PATTERN.matcher(phoneNumber).matches()) {
			validationContext.error("Invalid phone number format.");
			validationContext.validationError(formData, List.of(new FormMessage(PHONE_FIELD, "Please enter a valid phone number in E.164 format")));
			return;
		}

		validationContext.success();
	}

	private boolean isPhoneRequired(ValidationContext context) {
		return Boolean.parseBoolean(context.getAuthenticatorConfig().getConfig().get("phone_required"));
	}

	@Override
	public void success(FormContext formContext) {
		UserModel user = formContext.getUser();
		MultivaluedMap<String, String> formData = formContext.getHttpRequest().getDecodedFormParameters();
		String phoneNumber = formData.getFirst(PHONE_FIELD);

		if (phoneNumber != null && !phoneNumber.trim().isEmpty()) {
			user.setAttribute(PHONE_FIELD, List.of(phoneNumber));
		}
	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

	}

	@Override
	public void close() {

	}

	public String getDisplayType() {
		return "Phone Number Validation";
	}

	public String getReferenceCategory() {
		return "phone";
	}

	public boolean isConfigurable() {
		return true;
	}

	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

	public String getId() {
		return PROVIDER_ID;
	}
}
