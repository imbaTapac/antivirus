package com.antivirus.scanner;

import java.util.List;

public class PE {
    private DOSHeader dosHeader;
    private DOSStub dosStub;
    private PEHeader peHeader;
    private List<SectionTable> sectionTable;

    public PE(DOSHeader dosHeader, DOSStub dosStub, PEHeader peHeader) {
        this.dosHeader = dosHeader;
        this.dosStub = dosStub;
        this.peHeader = peHeader;
    }

    public DOSHeader getDosHeader() {
        return dosHeader;
    }

    public void setDosHeader(DOSHeader dosHeader) {
        this.dosHeader = dosHeader;
    }

    public DOSStub getDosStub() {
        return dosStub;
    }

    public void setDosStub(DOSStub dosStub) {
        this.dosStub = dosStub;
    }

    public PEHeader getPeHeader() {
        return peHeader;
    }

    public void setPeHeader(PEHeader peHeader) {
        this.peHeader = peHeader;
    }

    public List<SectionTable> getSectionTable() {
        return sectionTable;
    }

    public void setSectionTable(List<SectionTable> sectionTable) {
        this.sectionTable = sectionTable;
    }
}
