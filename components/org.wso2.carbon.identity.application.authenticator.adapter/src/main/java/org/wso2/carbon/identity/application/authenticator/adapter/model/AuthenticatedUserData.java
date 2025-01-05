package org.wso2.carbon.identity.application.authenticator.adapter.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.action.execution.model.UserClaim;
import org.wso2.carbon.identity.action.execution.model.UserStore;

import java.io.IOException;

/**
 * This class holds the data of the authenticated user, which are presented in the request and response to
 * the external authentication service.
 */
public class AuthenticatedUserData {

    @JsonProperty("id")
    private final String id;

    @JsonProperty("groups")
    private final String[] groups;

    @JsonProperty("claims")
    @JsonDeserialize(using = UserClaimDeserializer.class)
    private UserClaim[] claims;

    @JsonProperty("userStore")
    @JsonDeserialize(using = UserStoreDeserializer.class)
    private final UserStore userStore;

    private String sub;

    @JsonCreator
    public AuthenticatedUserData(
            @JsonProperty("id") String id,
            @JsonProperty("groups") String[] groups,
            @JsonProperty("claims") UserClaim[] claims,
            @JsonProperty("userStore") UserStore userStore
    ) {
        this.id = id;
        this.groups = groups;
        this.userStore = userStore;
        resolveUserClaims(claims);
    }

    public String getId() {

        return id;
    }

    public String[] getGroups() {

        return groups;
    }

    public UserClaim[] getClaims() {

        return claims;
    }

    public UserStore getUserStore() {

        return userStore;
    }

    public String getSub() {

        return sub;
    }

    private void resolveUserClaims(UserClaim[] claims) {

        for (UserClaim claim : claims) {
            if (StringUtils.isBlank(claim.getName()) || StringUtils.isBlank(claim.getValue())) {
                throw new IllegalArgumentException("Claim name and value are mandatory for all user claims.");
            }
            if (claim.getName().equalsIgnoreCase("sub")) {
                sub = claim.getValue();
            }
        }
        this.claims = claims;
    }

    /**
     * Custom deserializer for UserClaim array.
     */
    private static class UserClaimDeserializer extends JsonDeserializer<UserClaim[]> {

        @Override
        public UserClaim[] deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            JsonNode node = parser.getCodec().readTree(parser);

            if (!node.isArray()) {
                throw new IllegalArgumentException("Expected an array of UserClaim objects");
            }

            UserClaim[] claims = new UserClaim[node.size()];
            for (int i = 0; i < node.size(); i++) {
                JsonNode claimNode = node.get(i);
                String name = claimNode.get("name").asText();
                String value = claimNode.get("value").asText();
                claims[i] = new UserClaim(name, value);
            }

            return claims;
        }
    }

    /**
     * Custom deserializer for UserStore object.
     */
    private static class UserStoreDeserializer extends JsonDeserializer<UserStore> {

        @Override
        public UserStore deserialize(JsonParser parser, DeserializationContext context) throws IOException {

            JsonNode node = parser.getCodec().readTree(parser);
            String name = node.get("name").asText(null);

            return new UserStore(name);
        }
    }
}
