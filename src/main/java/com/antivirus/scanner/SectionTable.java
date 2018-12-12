package com.antivirus.scanner;

public class SectionTable {
    public static final long objectTableSize = 40;

    private char[] objectName;
    private int virtualSize;
    private int virtualAddress;
    private int physicalSize;
    private int physicalOffset;
    private char reserved;
    private String[] sectionFlags;

    public SectionTable(){

    }

    public char[] getObjectName() {
        return objectName;
    }

    public void setObjectName(char[] objectName) {
        this.objectName = objectName;
    }

    public int getVirtualSize() {
        return virtualSize;
    }

    public void setVirtualSize(int virtualSize) {
        this.virtualSize = virtualSize;
    }

    public int getVirtualAddress() {
        return virtualAddress;
    }

    public void setVirtualAddress(int virtualAddress) {
        this.virtualAddress = virtualAddress;
    }

    public int getPhysicalSize() {
        return physicalSize;
    }

    public void setPhysicalSize(int physicalSize) {
        this.physicalSize = physicalSize;
    }

    public int getPhysicalOffset() {
        return physicalOffset;
    }

    public void setPhysicalOffset(int physicalOffset) {
        this.physicalOffset = physicalOffset;
    }

    public char getReserved() {
        return reserved;
    }

    public void setReserved(char reserved) {
        this.reserved = reserved;
    }

    public String[] getSectionFlags() {
        return sectionFlags;
    }

    public void setSectionFlags(String[] sectionFlags) {
        this.sectionFlags = sectionFlags;
    }
}
