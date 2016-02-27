package cz.codingmonkey.signing;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

/**
 * Třída pro načítání revokačních listů
 *
 * @author Richard Stefanca
 */
public class FileSystemCRLProvider implements CRLProvider {
    private Logger log = LoggerFactory.getLogger(getClass());
    private final String crlFolder;

    /**
     * Konstruktor
     *
     * @param crlFolder adresář s CRL
     */
    public FileSystemCRLProvider(@NotNull String crlFolder) {
        this.crlFolder = crlFolder;
    }

    /**
     * @see CRLProvider
     */
    @Override
    @NotNull
    public List<X509CRL> getX509CRLList() throws Exception {
        log.info("Nacitam revocation listy z adresare {}", crlFolder);
        String[] files = getCLRFiles();
        final List<X509CRL> list = new ArrayList<X509CRL>(files.length);
        if (files.length > 0) {
            log.info("Soubory s revocation listy: {}", StringUtils.join(files, ", "));
            InputStream inStream = null;
            try {
                for (String fileName : files) {
                    File file = new File(crlFolder + File.separator + fileName);
                    log.debug("Nacitam {}...", file);
                    inStream = new FileInputStream(file);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    list.add((X509CRL) cf.generateCRL(inStream));
                    log.debug("{} nacten", file);
                }
            } catch (Throwable e) {
                log.error("Error loading CRL files", e);
                throw new Exception("Nelze nacist revocation listy");
            } finally {
                if (inStream != null) {
                    try {
                        inStream.close();
                    } catch (IOException ex) {
                        log.error("Neocekavana chyba", ex);
                    }
                }
            }
            log.info("Revocation listy nacteny");
        } else {
            log.info("Adresar {} neobsahuje zadne soubory *.crl", crlFolder);
        }

        return list;
    }

    @NotNull
    private String[] getCLRFiles() throws DirectoryNotFoundException {
        File dir = new File(crlFolder);
        if (!dir.exists()) throw new DirectoryNotFoundException(crlFolder, "Adresar nebyl nalezen - zkontroluj parametr crlFolder");
        return dir.list(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.toLowerCase().endsWith(".crl");
            }
        });
    }
}
