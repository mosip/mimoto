
# Install Onboarder

* Execute redis install script
```
cd redis
./install.sh
```
* Execute Onboarder install script
```
cd ../partner-onboarder
./install.sh
 ```
* During the execution of the `install.sh` script, a prompt appears requesting information for the S3 bucket, including its name and URL.
* Once the job is completed, log in to S3 / NFS and check the reports. There should not be any failures.
* Note: If you are running the Onboarder in a separate INJI cluster, update the extraEnvVars section accordingly in [values.yaml](../partner-onboarder/values.yaml).

# Install mimoto
* Execute mimoto install script

```
cd mimoto
./install.sh
  ```
* During the execution of the `install.sh` script, a prompt appears requesting information regarding the presence of a public domain and a valid SSL certificate on the server.
* If the server lacks a public domain and a valid SSL certificate, it is advisable to select the `n` option. Opting it will enable the `init-container` with an `emptyDir` volume and include it in the deployment process.
* The init-container will proceed to download the server's self-signed SSL certificate and mount it to the specified location within the container's Java keystore (i.e., `cacerts`) file.
* This particular functionality caters to scenarios where the script needs to be employed on a server utilizing self-signed SSL certificates.

## For Onboarding new Issuer for VCI:

- create a folder "certs" in the root and a file "oidckeystore.p12" inside certs and store the keys as different aliases for every issuers. for more details refer [here](https://docs.mosip.io/inji/inji-mobile-wallet/customization-overview/credential_providers)
