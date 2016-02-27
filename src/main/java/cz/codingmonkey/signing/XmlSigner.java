package cz.codingmonkey.signing;

import org.w3c.dom.Document;

/**
 * @author Richard Stefanca
 */
public interface XmlSigner {
    void sign(Document doc) throws Exception;
}
