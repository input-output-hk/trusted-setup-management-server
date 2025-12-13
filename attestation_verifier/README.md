# Attestation CLI

Allows to verify the AMD-SEV-SNP attestation that was generated after creating your SRS5, using the official Azure Attestation SDK.

Example: 

```bash
$ ./AttestationClient -v attestation.txt -p policy.json
```

## Compiling the CLI

Use the below command to install the `build-essential` package. This package will install everything required for compiling our sample application written in C++.
```sh
$ sudo apt-get install build-essential
```

Install the below packages
```sh
$ sudo apt-get install libcurl4-openssl-dev
$ sudo apt-get install libjsoncpp-dev
$ sudo apt-get install libboost-all-dev
$ sudo apt-get install cmake
$ sudo apt install nlohmann-json3-dev
```

Download the attestation package from the following location - https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/

Use the below command to install the attestation package
```sh
$ sudo dpkg -i azguestattestation1_1.1.0_amd64.deb
```

Once the above packages have been installed, use the below steps to build the app

```sh
$ cmake .
$ make
```
