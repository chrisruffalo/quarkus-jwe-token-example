package io.github.chrisruffalo.jwe.exception;

public class StoredKeyToKeyPairException extends Exception {

    public StoredKeyToKeyPairException() {
    }

    public StoredKeyToKeyPairException(String message) {
        super(message);
    }

    public StoredKeyToKeyPairException(String message, Throwable cause) {
        super(message, cause);
    }

    public StoredKeyToKeyPairException(Throwable cause) {
        super(cause);
    }

    public StoredKeyToKeyPairException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
