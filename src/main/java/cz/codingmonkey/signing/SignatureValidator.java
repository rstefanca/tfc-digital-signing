package cz.codingmonkey.signing;

import org.w3c.dom.NodeList;

import java.security.cert.X509Certificate;

/**
 * Interface pro validaci xml
 *
 * @author Richard Stefanca
 */
public interface SignatureValidator {
    /**
     * Validuje xml dokument
     *
     * @param sigNodes <Signature> elementy
     * @return certificate
     * @throws Exception
     */
    X509Certificate validateXmlDocument(NodeList sigNodes) throws Exception;
}
