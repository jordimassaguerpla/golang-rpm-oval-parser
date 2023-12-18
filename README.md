# Golang RPM Oval Parser

This repository hosts a simple parser crafted for RPM Oval XML files, implemented in Go.

The code serves as an illustration of how to extract vulnerability definitions specifically tailored for RPM-based distributions from OVAL files.

## What is OVAL?
Find more information about the Open Vulnerability and Assessment Language (OVAL) [here](https://oval.cisecurity.org/).

## OVAL Files Resources
- SUSE: [SUSE OVAL Files](http://ftp.suse.com/pub/projects/security/oval/)
- RedHat: [RedHat OVAL Files](https://www.redhat.com/security/data/oval/)
- Oracle: [Oracle OVAL Files](https://linux.oracle.com/oval/)

## Usage
- Build the parser: `go build`
- Run it using: `./golang-rpm-oval-parser FILE.xml`
- Explore the test directory for sample files to test the parser's functionality.

Feel free to use this parser to efficiently extract vulnerability information from OVAL files for RPM-based distributions. Contributions and feedback are always appreciated!
