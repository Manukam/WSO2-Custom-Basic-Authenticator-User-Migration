# WSO2-Custom-Basic-Authenticator-User-Migration

Migrate users from the old userstore (default embedded ldap and h2 db) seamlessly without asking users to create new passwords
Steps to deploy

Build the component by running `mvn clean install`
Copy following jar file which can be found in target directory of the component into **<IS_HOME>/repository/components/dropins/**
`org.wso2.custom.authenticator.local-1.0.0.jar`

Add following block under `<AuthenticatorConfigs>` in **<IS_HOME>/repository/conf/identity/application-authentication.xml**
   
```
 <AuthenticatorConfig name="MultiAttributeAuthenticator" enabled="true">
        <Parameter name="EnableUserMigration">true</Parameter>
        <Parameter name="OldUserStoreDomain">OLDUSERSTORE</Parameter>
        <Parameter name="NewUserStoreDomain">PRIMARY</Parameter>
        <Parameter name="AuthMechanism">basic</Parameter>
 </AuthenticatorConfig>
 ```
  
Use `CustomAuthenticator` in authentication steps in Local and Outbound authentication config of the service providers instead of `basic`
Explanation of the configuration parameters

`EnableUserMigration`: Specifies whether to migrate users from the old userstore to new userstore
`OldUserStoreDomain`: Userstore domain of the secodnary userstore which is pointed to the old userstore.
`NewUserStoreDomain`: Where the users should be migrated to from the old usersore
`AuthMechanism`: This is to tell identity server to consider this authenticator also using the "basic" auth mechanism. This is useful if you are trying to SSO with other service providers which are using default basic authenticator.
