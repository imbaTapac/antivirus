package com.antivirus.scanner.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;

public final class SignatureUtils {
    final static Logger log = LoggerFactory.getLogger(SignatureUtils.class);

    public static byte[] byteSignature(File file) throws IOException {
        byte[] signature = new byte[64];
        boolean isSignature = false;
        boolean endOfFile = false;
        long pointer = (long) Math.abs(file.length() / 1.5);
        long fileLength = file.length();
        RandomAccessFile raf = new RandomAccessFile(file, "r");
        while (!isSignature) {
            log.info("Read malware " + file.getName());
            int freeSpace = 0;
            raf.seek(pointer);
            raf.readFully(signature, 0, signature.length);
            for (int i = 0; i < 8; i++) {
                if (freeSpace > 4) {
                    break;
                }
                if (signature[i] == 0 || signature[i] == -112) {
                    freeSpace++;
                }
            }
            if (freeSpace <= 4) {
                isSignature = true;
            } else {
                if (pointer + 128 <= fileLength - signature.length && !endOfFile) {
                    pointer += 128;
                } else if (endOfFile) {
                    pointer -= 128;
                } else {
                    endOfFile = true;
                }

            }
        }
        return signature;
    }

    public static String checksum(byte[] signature, MessageDigest md) {
        StringBuilder hashSum = new StringBuilder();
        for (byte b : md.digest(signature)) {
            hashSum.append(String.format("%02X", b));
        }

        return hashSum.toString();
    }
}
