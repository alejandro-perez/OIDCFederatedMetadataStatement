package org.geant.oidcfed;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * This class allows getting and validating federated metadata statements, as defined in the OIDC federation draft.
 */
public class FederatedMetadataStatement {
    /**
     * Indicates the maximum amount of clock skew (in seconds) that we allow to verify JWT signatures
     */
    public static int MAX_CLOCK_SKEW = 60;

    /**
     * Indicates whether an object is a subset of another one, according to the OIDC Federation draft.
     *
     * @param obj1 One object.
     * @param obj2 Another object.
     * @return True if obj1 is a subset of obj2. False otherwise.
     */
    private static boolean isSubset(Object obj1, Object obj2) {
        if (!obj1.getClass().equals(obj2.getClass()))
            return false;
        else if (obj1 instanceof String)
            return obj1.equals(obj2);
        else if (obj1 instanceof Integer)
            return (Integer) obj1 <= (Integer) obj2;
        else if (obj1 instanceof Double)
            return (Double) obj1 <= (Double) obj2;
        else if (obj1 instanceof Long)
            return (Long) obj1 <= (Long) obj2;
        else if (obj1 instanceof Boolean)
            return obj1 == obj2;
        else if (obj1 instanceof JSONArray) {
            JSONArray list1 = (JSONArray) obj1;
            JSONArray list2 = (JSONArray) obj2;
            for (int i = 0; i < list1.length(); i++) {
                boolean found = false;
                for (int j = 0; j < list2.length(); j++) {
                    if (list1.get(i).equals(list2.get(j))) {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    return false;
            }
            return true;
        } else if (obj1 instanceof JSONObject) {
            JSONObject jobj1 = (JSONObject) obj1;
            JSONObject jobj2 = (JSONObject) obj2;
            for (Iterator<String> iter = jobj1.keys(); iter.hasNext(); ) {
                String key = iter.next();
                if (!jobj2.has(key) || !isSubset(jobj1.get(key), jobj2.get(key)))
                    return false;
            }
            return true;
        }
        return false;
    }

    /**
     * Flatten two metadata statements into one, following the rules from the OIDC federation draft.
     *
     * @param upper MS(n)
     * @param lower MS(n-1)
     * @return A flattened version of both statements.
     * @throws InvalidStatementException when there is a policy break and upper MS tries to overwrite lower MS
     *                                   breaking the policies from the OIDC federation draft.
     */
    private static JSONObject flatten(JSONObject upper, JSONObject lower) throws InvalidStatementException {
        String[] use_lower = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"};
        String[] use_upper = {"signing_keys", "signing_keys_uri", "metadata_statement_uris", "kid",
                "metadata_statements", "usage"};
        List<String> use_lower_list = Arrays.asList(use_lower);
        List<String> use_upper_list = Arrays.asList(use_upper);

        /* result starts as a copy of lower MS */
        JSONObject flattened = new JSONObject(lower.toString());
        for (Iterator<String> iter = upper.keys(); iter.hasNext(); ) {
            String claim_name = iter.next();
            if (use_lower_list.contains(claim_name))
                continue;

            /* If the claim does not exist on lower, or it is marked as "use_upper", or is a
               subset of lower, then use upper's one -> OK */
            if (lower.opt(claim_name) == null
                    || use_upper_list.contains(claim_name)
                    || isSubset(upper.get(claim_name), lower.get(claim_name))) {
                flattened.put(claim_name, upper.get(claim_name));
            }

            /* Else -> policy breach */
            else {
                throw new InvalidStatementException("Policy breach with claim: " + claim_name
                        + ". Lower value=" + lower.get(claim_name) + ". Upper value=" + upper.get(claim_name));
            }
        }
        return flattened;
    }

    /**
     * Verifies the signature of a JWT using the indicated keys.
     *
     * @param signedJWT Signed JWT
     * @param keys      Keys that can be used to verify the token
     * @throws InvalidStatementException when the JWT is not valid or the signature cannot be validated
     */
    private static void verifySignature(SignedJWT signedJWT, JWKSet keys) throws InvalidStatementException {
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(
                signedJWT.getHeader().getAlgorithm(), new ImmutableJWKSet(keys));
        DefaultJWTClaimsVerifier cverifier = new DefaultJWTClaimsVerifier();
        /* Allow some clock skew as testing platform examples are static */
        cverifier.setMaxClockSkew(FederatedMetadataStatement.MAX_CLOCK_SKEW);
        jwtProcessor.setJWTClaimsSetVerifier(cverifier);
        jwtProcessor.setJWSKeySelector(keySelector);
        try {
            jwtProcessor.process(signedJWT, null);
        } catch (BadJOSEException | JOSEException e) {
            throw new InvalidStatementException(e.getMessage());
        }
    }

    /**
     * Collects inner metadata statement for a specific Federation Operator, either from "metadata_statements"
     * or from "metadata_statatement_uris".
     *
     * @param payload Metadata statement containing inner metadata statements
     * @param fed_op  Name of the Federation Operator
     * @return A MS for the specified FO. Null if not found
     * @throws InvalidStatementException when a "metadata_statement_uris" key cannot be downloaded
     */
    private static String getMetadataStatement(JSONObject payload, String fed_op) throws InvalidStatementException {
        JSONObject ms = payload.optJSONObject("metadata_statements");
        JSONObject ms_uris = payload.optJSONObject("metadata_statement_uris");
        if (ms != null && ms.has(fed_op))
            return ms.getString(fed_op);
        if (ms_uris != null && ms_uris.has(fed_op)) {
            System.out.println("Getting MS for " + fed_op + " from " + ms_uris.getString(fed_op));
            System.out.println(payload.toString());
            try {
                return IOUtils.toString(new URL(ms_uris.getString(fed_op)).openStream(), Charset.defaultCharset());
            } catch (IOException e) {
                throw new InvalidStatementException(e.getMessage());
            }
        }
        return null;
    }

    /**
     * Decodes, verifies and flattens a compounded MS for a specific federation operator
     *
     * @param ms_jwt    Encoded JWT representing a signed metadata statement
     * @param fed_op    Name of the Federator Operator
     * @param root_keys Collection of JWSK of the accepted FO
     * @return A flattened and verified MS
     * @throws InvalidStatementException When the compounded statement is invalid (invalid signature, flattening, etc.)
     */
    private static JSONObject verifyMetadataStatement(String ms_jwt, String fed_op, JSONObject root_keys)
            throws InvalidStatementException {
        try {
            /* Parse the signed JWT */
            SignedJWT signedJWT = SignedJWT.parse(ms_jwt);

            /* Create an empty JWKS to store gathered keys from the inner MSs */
            JWKSet keys = new JWKSet();

            /* Convert nimbus JSON object to org.json.JSONObject for simpler processing */
            JSONObject payload = new JSONObject(signedJWT.getPayload().toString());

            System.out.println("Inspecting MS signed by: " + payload.getString("iss")
                    + " with KID:" + signedJWT.getHeader().getKeyID());

            /* Collect inner MS (JWT encoded) */
            String inner_ms_jwt = getMetadataStatement(payload, fed_op);

            /* This will hold the result of the verification/decoding/flattening */
            JSONObject result;

            /* If there are more MSs, recursively analyzed them and return the flattened version
             * with the inner payload */
            if (inner_ms_jwt != null) {
                /* Recursion here to get a verified and flattened version of inner_ms */
                JSONObject inner_ms_flattened = verifyMetadataStatement(inner_ms_jwt, fed_op, root_keys);

                /* add signing keys */
                JWKSet inner_ms_sigkeys = JWKSet.parse(inner_ms_flattened.getJSONObject("signing_keys").toString());
                keys.getKeys().addAll(inner_ms_sigkeys.getKeys());
                result = flatten(payload, inner_ms_flattened);
            }
            /* If there are no inner metadata statements, this is MS0 and root keys must be used for
             * validating the signature. Result will be the decoded payload */
            else {
                keys = JWKSet.parse(root_keys.getJSONObject(fed_op).toString());
                result = payload;
            }

            /* verify the signature using the collected keys */
            verifySignature(signedJWT, keys);
            System.out.println("Successful validation of signature of " + payload.getString("iss")
                    + " with KID:" + signedJWT.getHeader().getKeyID());
            return result;
        } catch (ParseException e) {
            throw new InvalidStatementException(e.getMessage());
        }
    }

    /**
     * Given an unsigned metadata statement document (either Server dicovery document or Client dynamic registration
     * one, get a federated/signed version of it (if available)
     *
     * @param unsigned_ms Unsigned metadata statement
     * @param root_keys   JSON Object containing an entry per accepted FO, each one with a JWKS
     * @return A metadatata statement which has been validated using a supported FO.
     * @throws InvalidStatementException When there is a problem with the validation of the federated MS
     */
    public static JSONObject getFederatedConfiguration(JSONObject unsigned_ms, JSONObject root_keys)
            throws InvalidStatementException {
        // Iterate over the trusted FOs
        for (Iterator<String> it = root_keys.keys(); it.hasNext(); ) {
            String fed_op = it.next();
            System.out.println("Looking for a valid metadata_statement for " + fed_op);
            String ms_jwt = getMetadataStatement(unsigned_ms, fed_op);
            if (ms_jwt != null) {
                JSONObject ms_flattened = verifyMetadataStatement(ms_jwt, fed_op, root_keys);
                System.out.println("Statement for federation id " + fed_op);
                System.out.println(ms_flattened.toString(2));
                return ms_flattened;
            }
        }
        throw new InvalidStatementException("There are no metadata_statements for any trusted FO");
    }
}
