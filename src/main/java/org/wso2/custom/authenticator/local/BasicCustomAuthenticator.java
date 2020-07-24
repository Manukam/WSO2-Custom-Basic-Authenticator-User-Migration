/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.custom.authenticator.local;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.custom.authenticator.local.internal.BasicCustomAuthenticatorServiceComponent500;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Username Password based Authenticator
 */
public class BasicCustomAuthenticator extends BasicAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);

    private boolean enableUserMigration;
    private String oldUserStoreDomain;
    private String newUserStoreDomain;
    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        super.processAuthenticationResponse(request, response, context);

        enableUserMigration = Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap().get(
                CustomAuthenticatorConstants.AUTHENTICATOR_PROPERTY_ENABLE_USER_MIGRATION));
        oldUserStoreDomain = getAuthenticatorConfig().getParameterMap().get(
                CustomAuthenticatorConstants.AUTHENTICATOR_PROPERTY_OLD_USER_STORE_DOMAIN);
        newUserStoreDomain = getAuthenticatorConfig().getParameterMap().get(
                CustomAuthenticatorConstants.AUTHENTICATOR_PROPERTY_NEW_USER_STORE_DOMAIN);

        String username = request.getParameter(CustomAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(CustomAuthenticatorConstants.PASSWORD);

        username = UserCoreUtil.addDomainToName(username, UserCoreUtil.getDomainFromThreadLocal());

        Map<String, Object> authProperties = context.getProperties();
        authProperties.put(PASSWORD_PROPERTY, password);

        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        authProperties.put("user-tenant-domain", tenantDomain);

        if (enableUserMigration && username.startsWith(oldUserStoreDomain + "/")) {
            log.info("Custom Authenticator: User in Old user store. need to migrate ");
            String migratedUsername = migrateUser(request);
            log.info("Custom Authenticator: User migration done. " + migratedUsername);
            if (migratedUsername != null) {
                username = migratedUsername + "@" + tenantDomain;
            }
        }

        username = FrameworkUtils.prependUserStoreDomainToName(username);

        context.setSubject(username);

    }

    public String migrateUser(HttpServletRequest httpServletRequest) {

        //Read the username and password from the the original request
        String username = httpServletRequest.getParameter(CustomAuthenticatorConstants.USER_NAME);
        String password = httpServletRequest.getParameter(CustomAuthenticatorConstants.PASSWORD);

        try {
            //Read tenant id from the user name.
            int tenantId = IdentityUtil.getTenantIdOFUser(username);
            UserRealm userRealm = null;
            try {
                //Ge the user realm to the given tenant.
                userRealm = BasicCustomAuthenticatorServiceComponent500.getRealmService().getTenantUserRealm(tenantId);
                if (userRealm == null) {
                    String errorMessage = "Cannot find the user realm for the given tenant: " + tenantId + "  " + username;
                    throw new AuthenticationFailedException(errorMessage);
                }
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                String errorMessage = "Cannot find the user realm for the given tenant: " + tenantId + " " + username;
                throw new AuthenticationFailedException(errorMessage, e);
            }

            String oldUserName = oldUserStoreDomain + "/" + username;

            log.info("Custom Authenticator: newUserStoreDomain : " + newUserStoreDomain);
            log.info("Custom Authenticator: oldUserStoreDomain : " + oldUserStoreDomain);
            log.info("Custom Authenticator: oldUserName : " + oldUserName);

            UserStoreManager userStoreManager = null;
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();

            //Get the current user claims URIs list.
            String[] currentClaims = userStoreManager.getClaimManager().getAllClaimUris();

            Map<String, String> userClaims = null;
            try {
                //Read the existing user claims from the old user store domain
                userClaims = userStoreManager.getUserClaimValues(oldUserName, currentClaims,
                        CustomAuthenticatorConstants.DEFAULT_PROFILE);
            } catch (UserStoreException e) {
                String errorMessage = "Error occurred while getting the existing user claims from the "
                        + CustomAuthenticatorConstants.AUTHENTICATOR_PROPERTY_OLD_USER_STORE_DOMAIN + " user store domain.";
                throw new AuthenticationFailedException(errorMessage, e);
            }

            if (log.isDebugEnabled()) {
                for (String uri : userClaims.keySet()) {
                    log.debug("Old Userstore Claim : " + uri + " value : " + userClaims.get(uri));
                }
            }

            try {

                String newUserName = UserCoreUtil.removeDomainFromName(username);
                //Provision the old user which was exist in the old user store to the new user store.
                userStoreManager.addUser(newUserStoreDomain + "/" + newUserName, password, new String[0],
                        userClaims, CustomAuthenticatorConstants.DEFAULT_PROFILE);

                UserCoreUtil.setDomainInThreadLocal(newUserStoreDomain);
                return newUserName;

            } catch (UserStoreException e) {
                String errorMessage = "Error occurred while migrating the old user to the "
                        + CustomAuthenticatorConstants.AUTHENTICATOR_PROPERTY_NEW_USER_STORE_DOMAIN + " user store domain.";
                throw new AuthenticationFailedException(errorMessage, e);
            }

        } catch (Exception e) {
            // Avoid failing authentication due to errors in the user migration
            log.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public String getName() {
        return CustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return CustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}