package cz.codingmonkey.signing;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class FileSystemCRLProviderTest {

    @Test
    public void testGetX509CRLList_ok() throws Exception {
        FileSystemCRLProvider provider = new FileSystemCRLProvider("crls");
        assertEquals(2, provider.getX509CRLList().size());
    }

    @Test(expected = DirectoryNotFoundException.class)
    public void testGetX509CRLList_dir_not_found() throws Exception {
        FileSystemCRLProvider provider = new FileSystemCRLProvider("crls1");
        assertEquals(2, provider.getX509CRLList().size());
    }
}