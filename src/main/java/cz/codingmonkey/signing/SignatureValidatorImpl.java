package cz.codingmonkey.signing;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.*;
import java.security.cert.*;
import java.security.cert.CertificateRevokedException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/**
 * @author Richard Stefanca
 */
public class SignatureValidatorImpl implements SignatureValidator {

    private static Logger logger = LoggerFactory.getLogger(SignatureValidatorImpl.class);

    private final CRLProvider crlProvider;
    private final KeyStore keyStore;

    public SignatureValidatorImpl(@NotNull CRLProvider crlProvider, @NotNull KeyStore keyStore) {
        this.crlProvider = crlProvider;
        this.keyStore = keyStore;
    }

    @Override
    public X509Certificate validateXmlDocument(NodeList sigNodes) throws Exception {
        KeyValueKeySelector keySelector = new KeyValueKeySelector();
        DOMValidateContext valContext = new DOMValidateContext(keySelector, sigNodes.item(0));
        valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
        XMLSignatureFactory validateFactory = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = validateFactory.unmarshalXMLSignature(valContext);
        try {
            boolean coreValidity = signature.validate(valContext);

            if (!coreValidity) {
                boolean sv = signature.getSignatureValue().validate(valContext);
                if (logger.isDebugEnabled()) {
                    logger.debug("Signature failed core validation");
                    logger.debug("signature validation status: " + sv);

                }
                if (!sv) {
                    Iterator i = signature.getSignedInfo().getReferences().iterator();
                    for (int j = 0; i.hasNext(); j++) {
                        boolean refValid = ((Reference) i.next()).validate(valContext);
                        if (logger.isDebugEnabled()) {
                            logger.debug("ref[" + j + "] validity status: " + refValid);
                        }
                    }
                }
                return null;
            }

            KeyAndCertificateSelectorResult keySelectorResult = (KeyAndCertificateSelectorResult) signature.getKeySelectorResult();
            X509Certificate x509Certificate = keySelectorResult.getX509Certificate();
            if (x509Certificate == null) {
                List<X509Certificate> certificates = getCertificates(signature.getKeyInfo());
                getCertPathValidatorResult(certificates);
                x509Certificate = findSubjectCertificate(certificates, (PublicKey) keySelectorResult.getKey());
            }

            return x509Certificate;

        } catch (XMLSignatureException xmlSignatureException) {
            Throwable cause = xmlSignatureException.getCause();
            if (cause instanceof KeySelectorException) {
                Throwable innerCause = cause.getCause();
                if (innerCause != null) {
                    throw (Exception) innerCause;
                }
            }

            throw xmlSignatureException;
        }
    }

    private List<X509Certificate> getCertificates(KeyInfo keyInfo) throws Exception {
        List list = keyInfo.getContent();
        List<X509Certificate> certs = new ArrayList<X509Certificate>();

        for (Object data : list) {
            if (data instanceof X509Data) {
                X509Data dOMX509Data = (X509Data) data;
                List dOMX509DataContentList = dOMX509Data.getContent();
                for (Object contentData : dOMX509DataContentList) {
                    if (contentData instanceof X509Certificate) {
                        X509Certificate x509CertImpl = (X509Certificate) contentData;
                        x509CertImpl.checkValidity();
                        checkRevocation(x509CertImpl);
                        certs.add(x509CertImpl);
                    }
                }
            }
        }

        return certs;
    }

    private CertPathValidatorResult getCertPathValidatorResult(List<X509Certificate> certs) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException, CertPathValidatorException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        CertPath certPath = certFactory.generateCertPath(certs);
        CertPathValidator pathValidator = CertPathValidator.getInstance("PKIX");
        PKIXParameters params = new PKIXParameters(keyStore);
        params.setRevocationEnabled(false);
        return pathValidator.validate(certPath, params);
    }

    @NotNull
    private X509Certificate findSubjectCertificate(List<X509Certificate> certs, PublicKey publicKey) throws CertificateNotFoundException {
        for (X509Certificate cert : certs) {
            if (publicKey.equals(cert.getPublicKey())) {
                return cert;
            }
        }
        throw new CertificateNotFoundException();
    }

    private void checkRevocation(X509Certificate x509Certificate) throws Exception {
        for (X509CRL x509crl : crlProvider.getX509CRLList()) {
            X509CRLEntry entry = x509crl.getRevokedCertificate(x509Certificate);
            if (entry != null) {
                throw new CertificateRevokedException(entry.getRevocationDate(),
                        entry.getRevocationReason(),
                        entry.getCertificateIssuer(),
                        new HashMap<String, Extension>());
            }
        }
    }

    private class KeyValueKeySelector extends KeySelector {

        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                                        Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
                throws KeySelectorException {

            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();

            // Otestujem zdali je verejny klic umisten v RSAKeyValue elementu
            PublicKey pk;
            for (Object aList : list) {
                XMLStructure xmlStructure = (XMLStructure) aList;
                if (xmlStructure instanceof KeyValue) {
                    try {
                        pk = ((KeyValue) xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new KeyAndCertificateSelectorResult(pk);
                    }
                }
            }

            // V pripade ze neni pritomen RSAKeyValue element ziskame verejny klic z certifikatu

            try {
                List<X509Certificate> certs = getCertificates(keyInfo);
                CertPathValidatorResult validate = getCertPathValidatorResult(certs);
                if (validate instanceof PKIXCertPathValidatorResult) {
                    PublicKey publicKey = ((PKIXCertPathValidatorResult) validate).getPublicKey();
                    if (algEquals(sm.getAlgorithm(), publicKey.getAlgorithm())) {
                        X509Certificate selectedCertificate = findSubjectCertificate(certs, publicKey);
                        return new KeyAndCertificateSelectorResult(publicKey, selectedCertificate);
                    }
                }
            } catch (Exception ex) {
                throw new KeySelectorException(ex);
            }

            throw new KeySelectorException("No KeyValue element found!");
        }

        boolean algEquals(String algURI, String algName) {
            return algName.equalsIgnoreCase("DSA") && (algURI.equalsIgnoreCase("http://www.w3.org/2009/xmldsig11#dsa-sha256")) ||
                    algName.equalsIgnoreCase("RSA") && (algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")) ||
                    algName.equalsIgnoreCase("RSA") && (algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") ||
                            algName.equalsIgnoreCase("RSA") && (algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")));
        }
    }



    private static class KeyAndCertificateSelectorResult implements KeySelectorResult {

        private final Key pk;
        private final X509Certificate x509Certificate;

        KeyAndCertificateSelectorResult(Key pk) {
            this(pk, null);
        }

        KeyAndCertificateSelectorResult(Key pk, X509Certificate x509Certificate) {
            this.pk = pk;
            this.x509Certificate = x509Certificate;
        }

        @Override
        public Key getKey() {
            return pk;
        }

        public X509Certificate getX509Certificate() {
            return x509Certificate;
        }
    }
}
