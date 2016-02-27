package cz.codingmonkey.signing;

import java.security.cert.X509CRL;
import java.util.List;

/**
 * @author Richard Stefanca
 */
public interface CRLProvider {
    /**
     * Vrací seznam revokačních listů
     * @return seznam revokačních listů
     * @throws Exception výjimka
     */
    List<X509CRL> getX509CRLList() throws Exception;
}
