package cz.codingmonkey.signing;

/**
 * @author Richard Stefanca
 */
public class DirectoryNotFoundException extends Exception {

    private final String dir;

    /**
     * Vytvori vyjimku
     *
     * @param dir adresare, ktery se nepodarilo najit
     */
    public DirectoryNotFoundException(String dir) {
       this(dir, "Adresar " + dir + " nebyl nalezen");
    }

    public DirectoryNotFoundException(String dir, String message) {
        super(message);
        this.dir = dir;
    }

    public String getDir() {
        return dir;
    }
}
