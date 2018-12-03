package com.antivirus.scanner;

import java.util.Arrays;

public class DOSHeader {
    private final byte[] signatureExpected = new byte[] {0x4D, 0x5A};

    private byte[] DOSSignature;
    private int checksum;
    private int PEOffset;

    public DOSHeader(){
    }


    public byte[] getDOSSignature() {
        return DOSSignature;
    }

    public void setDOSSignature(byte[] DOSSignature) {
        this.DOSSignature = DOSSignature;
    }

    public int getChecksum() {
        return checksum;
    }

    public void setChecksum(int checksum) {
        this.checksum = checksum;
    }

    public int getPEOffset() {
        return PEOffset;
    }

    public void setPEOffset(int PEOffset) {
        this.PEOffset = PEOffset;
    }

    public boolean isValid(){
        return Arrays.equals(DOSSignature,signatureExpected);
    }
}
