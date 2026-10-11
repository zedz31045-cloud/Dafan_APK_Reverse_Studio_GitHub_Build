package com.dafan.reverse;

import static org.junit.Assert.*;
import org.junit.Test;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

public class ApkAnalyzerTest {
    @Test public void sha256KnownVector() throws Exception {
        String result = ApkAnalyzer.sha256(new ByteArrayInputStream("abc".getBytes("UTF-8")));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", result);
    }
    @Test public void printableStringsAreCollected() {
        List<String> out = new ArrayList<>();
        ApkAnalyzer.collectAsciiStrings("hello\u0000ab\u0000World-123\u0000".getBytes(), out, 10);
        assertTrue(out.contains("hello"));
        assertTrue(out.contains("World-123"));
        assertFalse(out.contains("ab"));
    }
}
