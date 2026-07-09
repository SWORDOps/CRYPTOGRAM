############################################################################################################

Certificates_PKCS7_v5_14_DoD

############################################################################################################

File Information:

The structure of the file names for files that contain certificates in this bundle follow this pattern:

certificates_pkcs7_[bundle version]_[group]_[subgroup information].[encoding].[file type]

where:
    'bundle version' is a PKE version identification number of the form Major_Minor_Release.
    'group' is a DoD PKI certificate grouping which is either DoD, ECA, JITC, SIPR, DIL, or WCF.
    'subgroup information' is additional details about which Root CA the file contains (with the Root's subordinates).
    'encoding' is the encoding scheme used in the file and is either der or pem.
    'file type' is the file extension which best fits the contents of the file.

There is a special file which supports the verification of this bundle. The file contains a CMS object which contains a
payload of file checksums included in this bundle and has been digitally signed by the DoD PKE code signing credential.
The structure of its file name follows this pattern:

certificates_pkcs7_[bundle version]_[group].sha256

where:
    'bundle version' is a PKE version identification number of the form Major_Minor_Release.
    'group' is a DoD PKI certificate grouping which is either DoD, ECA, JITC, SIPR, DIL, or WCF.

Verification:


To verify this PKCS#7 package please perform the following steps:


1)  Determine the Thumbprint on the DoD Root CA under which the signer was issued (the first DoD_PKE_CA_chain.pem certificate) using the following command:
openssl x509 -in DoD_PKE_CA_chain.pem -subject -issuer -fingerprint -noout

Verify that the output identifies a DoD root CA and that the issuer and subject lines are identical.  For example, output for a signer issued under DoD Root CA 6 would be:

subject= /C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 6
issuer= /C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 6
SHA1 Fingerprint=D3:7E:CF:61:C0:B4:ED:88:68:1E:F3:63:0C:4E:2F:C7:87:B3:7A:EF


2) Verify the SHA1 Fingerprint of the DoD Root CA identified in step 1 against the value posted at https://crl.disa.mil:

- Select the DoD root indicated in step 1 (e.g. DOD ROOT CA 6) from the list of CAs (listed alphabetically) and click "Submit Selection"
- Click "View" to view the certificate
- Scroll to the bottom of the certificate page and verify that the listed SHA-1 Certificate Fingerprint matches the value output in step 1 above.


3) Verify that only the DoD Root and one subordinate CA for the signing certificate are present in the DoD_PKE_CA_chain.pem file using the following command:
openssl crl2pkcs7 -nocrl -certfile DoD_PKE_CA_chain.pem | openssl pkcs7 -print_certs -noout

Verify that the output matches the output from step 1, e.g. for a signing certificate chaining via DOD EMAIL CA-73 to DoD Root CA 6:

subject=/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 6
issuer=/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 6

subject=/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DOD EMAIL CA-73
issuer=/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 6

Confirm that only two certificates are listed - one DoD Root CA (issuer and subject line values are identical) and one subordinate CA (issuer matches the DoD Root CA entry and subject is different).


4) Verify the S/MIME signature on Certificates_PKCS7_v5_14_DoD.sha256 using the following command:

On Mac OSX:
$ openssl smime -verify -in Certificates_PKCS7_v5_14_DoD.sha256 -inform DER -CAfile DoD_PKE_CA_chain.pem | shasum -a 256 -c

Verify the following output:
Verification successful


On Linux:
$ openssl smime -verify -in Certificates_PKCS7_v5_14_DoD.sha256 -inform DER -CAfile DoD_PKE_CA_chain.pem | dos2unix | sha256sum -c

Verify the following output:
Verification successful


On Windows:

Verify the signature on the hash file:
> openssl smime -verify -in Certificates_PKCS7_v5_14_DoD.sha256 -inform DER -CAfile DoD_PKE_CA_chain.pem

Verify the following output:
Verification successful

Then for each file listed in the output of the openssl smime -verify command, generate a local hash:
> certutil -hashfile FILENAME sha256

Verify that the output matches the hash listed for the file in the Certificates_PKCS7_v5_14_DoD.sha256 openssl smime -verify output.


############################################################################################################

Usage:

Openssl - To export CA certificates to a concatenated PEM file for use as an openssl CAfile (named e.g. GROUPREPLACE_CAs.pem), use the following command:
openssl pkcs7 -in Certificates_PKCS7_v5_14_DoD.der.p7b -inform der -print_certs -out GROUPREPLACE_CAs.pem

For more detailed instructions find our Getting Started with Firefox on Linux guide on our DoD Cyber Exchange PKI-PKE site. End Users > Web Browsers > Mozilla Firefox