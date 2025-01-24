package org.wso2.carbon.identity.application.authenticator.adapter.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.wso2.carbon.identity.action.execution.model.ResponseData;

import java.util.List;

/**
 * This class holds the data of the authenticated user, which are presented in response from the external
 * authentication service.
 */
public class AuthenticatedUserData implements ResponseData {

    @JsonProperty("user")
    private User user;

    @JsonCreator
    public AuthenticatedUserData(@JsonProperty("user") User user) {
        this.user = user;
    }

    public AuthenticatedUserData() {
    }

    public User getUser() {
        return user;
    }

    /**
     * This class holds the data of the authenticated user.
     */
    public static class User {

        @JsonProperty("id")
        private String id;

        @JsonProperty("groups")
        private List<String> groups;

        @JsonProperty("claims")
        private List<Claim> claims;

        @JsonProperty("userStore")
        private UserStore userStore;

        public User() {
        }

        @JsonCreator
        public User(
                @JsonProperty("id") String id,
                @JsonProperty("groups") List<String> groups,
                @JsonProperty("claims") List<Claim> claims,
                @JsonProperty("userStore") UserStore userStore) {
            this.id = id;
            this.groups = groups;
            this.claims = claims;
            this.userStore = userStore;
        }

        public String getId() {
            return id;
        }

        public List<String> getGroups() {
            return groups;
        }

        public List<Claim> getClaims() {
            return claims;
        }

        public UserStore getUserStore() {
            return userStore;
        }
    }

    /**
     * This class holds the data of the claims of the authenticated user.
     */
    public static class Claim {

        @JsonProperty("uri")
        private String uri;

        @JsonProperty("value")
        private String value;

        public Claim() {
        }

        @JsonCreator
        public Claim(
                @JsonProperty("uri") String uri,
                @JsonProperty("value") String value) {
            this.uri = uri;
            this.value = value;
        }

        public String getUri() {
            return uri;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * This class holds the data of the user store of the authenticated user.
     */
    public static class UserStore {

        @JsonProperty("id")
        private String id;

        @JsonProperty("name")
        private String name;

        public UserStore() {
        }

        @JsonCreator
        public UserStore(
                @JsonProperty("id") String id,
                @JsonProperty("name") String name) {
            this.id = id;
            this.name = name;
        }

        public String getId() {
            return id;
        }

        public String getName() {
            return name;
        }
    }
}
