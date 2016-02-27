package cz.codingmonkey.signing;

import org.jetbrains.annotations.NotNull;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import java.io.FileInputStream;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Richard Stefanca
 */
public abstract class KeyStoreUtils {

    public static KeyStore load(@NotNull String path, @NotNull String password) throws Exception {
        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(new FileInputStream(path), password.toCharArray());

        return jks;
    }

    public static KeyInfo getKeyInfo(@NotNull KeyStore keyStore, @NotNull String certAlias) throws KeyException, KeyStoreException {
        X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(certAlias);
        List<Object> x509dataList = new ArrayList<Object>();
        x509dataList.add(x509Certificate.getSubjectX500Principal().getName());
        x509dataList.add(x509Certificate);
        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        List<XMLStructure> keyInfoList = new ArrayList<XMLStructure>();
        KeyValue keyValue = keyInfoFactory.newKeyValue(x509Certificate.getPublicKey());
        keyInfoList.add(keyValue);
        keyInfoList.add(keyInfoFactory.newX509Data(x509dataList));
        return keyInfoFactory.newKeyInfo(keyInfoList);
    }
}
