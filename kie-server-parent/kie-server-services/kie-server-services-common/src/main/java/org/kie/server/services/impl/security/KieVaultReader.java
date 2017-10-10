package org.kie.server.services.impl.security;

import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

public class KieVaultReader {
    private static final Logger logger = LoggerFactory.getLogger(KieVaultReader.class);

    private static final Pattern VAULT_PATTERN = Pattern.compile("VAULT::.*::.*::.*");

    private KieVaultReader() {
    }

    public static boolean isVaultFormat(String str) {
        return str != null && VAULT_PATTERN.matcher(str).matches();
    }

    public static String decryptValue(String encryptedValue) throws SecurityException {
        String value = null;

        if (!isVaultFormat(encryptedValue)) {
            throw new SecurityException("Password is not in vault format.");
        }

        String[] tokens = tokens(encryptedValue);
        String vaultBlock = tokens[1];
        String attributeName = tokens[2];
        byte[] sharedKey = null;
        if ( tokens.length > 3){
            sharedKey = tokens[3].getBytes(StandardCharsets.UTF_8);
        }
        try {
            SecurityVault vault = SecurityVaultFactory.get();

            boolean exists = vault.exists(vaultBlock, attributeName);
            if (exists) {
                char[] pass = vault.retrieve(vaultBlock, attributeName, sharedKey);
                value = String.valueOf(pass);
            } else {
                throw new SecurityException(
                        String.format("Attribute %s does not exist in vaultblock %s",
                                attributeName, vaultBlock));
            }
        } catch (Exception ex) {
            logger.warn("Error while reading vault", ex);
        }
        return value;
    }

    private static String[] tokens(String vaultString) {
        StringTokenizer tokenizer = new StringTokenizer(vaultString, "::");
        int length = tokenizer.countTokens();
        String[] tokens = new String[length];
        int index = 0;
        while (tokenizer.hasMoreTokens()) {
            tokens[index++] = tokenizer.nextToken();
        }
        return tokens;
    }
}