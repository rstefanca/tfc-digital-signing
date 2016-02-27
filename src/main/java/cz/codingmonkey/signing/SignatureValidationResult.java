package cz.codingmonkey.signing;

import org.jetbrains.annotations.NotNull;

import java.security.cert.X509Certificate;

/**
 * @author Richard Stefanca
 */
public class SignatureValidationResult
{
    public static final SignatureValidationResult FAILED = new SignatureValidationResult(null);

    private final boolean isValid;
    private final X509Certificate certificate;

    private SignatureValidationResult(X509Certificate certificate) {
        this.isValid = certificate != null;
        this.certificate = certificate;
    }

    public boolean isValid() {
        return isValid;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    @NotNull
    public static SignatureValidationResult success(@NotNull X509Certificate certificate) {
        return new SignatureValidationResult(certificate);
    }

    @NotNull
    public static SignatureValidationResult fail() {
        return FAILED;
    }
}
