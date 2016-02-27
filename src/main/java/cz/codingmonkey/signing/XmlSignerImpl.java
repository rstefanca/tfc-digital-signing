package cz.codingmonkey.signing;

import org.jetbrains.annotations.NotNull;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.security.Key;
import java.util.Collections;

/**
 * @author Richard Stefanca
 */
public class XmlSignerImpl implements XmlSigner {

    private final XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");

    private final Key key;
    private final KeyInfo keyInfo;

    public XmlSignerImpl(@NotNull Key key, @NotNull KeyInfo keyInfo) {
        this.key = key;
        this.keyInfo = keyInfo;
    }

    @Override
    public void sign(Document doc) throws Exception {
        DOMSignContext domSignContext = new DOMSignContext(key, doc.getDocumentElement());
        domSignContext.putNamespacePrefix(XMLSignature.XMLNS, "dsig");
        Reference ref = signatureFactory.newReference("",
                signatureFactory.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                null,
                null);

        SignedInfo si = signatureFactory.newSignedInfo(
                signatureFactory.newCanonicalizationMethod
                        (CanonicalizationMethod.INCLUSIVE,
                                (C14NMethodParameterSpec) null),
                signatureFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(ref));
        signatureFactory.newXMLSignature(si, keyInfo).sign(domSignContext);
    }
}
