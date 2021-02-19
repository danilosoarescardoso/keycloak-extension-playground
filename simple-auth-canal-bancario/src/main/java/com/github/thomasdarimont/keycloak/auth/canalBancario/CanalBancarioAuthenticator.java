package com.github.thomasdarimont.keycloak.auth.canalBancario;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialInput;
import org.keycloak.events.Errors;

import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.MultivaluedMap;
import java.util.LinkedList;
import java.util.List;

public class CanalBancarioAuthenticator implements Authenticator{

    private static final Logger LOG = Logger.getLogger(CanalBancarioAuthenticator.class);


    public CanalBancarioAuthenticator(KeycloakSession session){
        // configure from session
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        action(context);
    }


    protected UserModel lookupUser(AuthenticationFlowContext context, String username) {

        try {
            return KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);

            // Could happen during federation import
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
        }

        return null;
    }

    protected Response setDuplicateUserChallenge(AuthenticationFlowContext context, String eventError, String loginFormError, AuthenticationFlowError authenticatorError) {
        context.getEvent().error(eventError);
        Response challengeResponse = context.form()
                .setError(loginFormError).createLoginUsernamePassword();
        context.failureChallenge(authenticatorError, challengeResponse);
        return challengeResponse;
    }

    private boolean validatePasswordForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String username = formData.getFirst("username");
        UserModel user = lookupUser(context, username);
        if (username == null || user == null) {
            /* TODO emitir erro quando usuário/senha não existirem */
            return false;
        }

        String password = formData.getFirst("password");
        if (password == null || password.isEmpty()) {
            //failWithInvalidCredentials(context, null);
            return false;
        }

        List<CredentialInput> credentials = new LinkedList<>();
        credentials.add(UserCredentialModel.password(password));

        if (!context.getSession().userCredentialManager().isValid(context.getRealm(), user, credentials)) {
            //failWithInvalidCredentials(context, user);
            return false;
        }

        context.setUser(user);

        return true;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            context.resetFlow();
            return;
        }
        if (!validatePasswordForm(context, formData)) {
            return;
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {
        // NOOP
    }
}
