# inji Deployment in Kubernetes Environment
## Overview
* This guide will walk you through the deployment process of the Esignet application.
* The setup involves creating
  * Kubernetes cluster
  * Setting up Nginx
  * Installing Istio
  * Configuring storage class
  * Configuring the necessary dependent services
  * Deploying Esignet services
## Deployment
### K8 cluster
* Kubernetes cluster should be ready with storage class and ingress configured properly.
* Below is the document containing steps to create and configure K8 cluster.
  * __Onprem RKE CLuster__ : Create RKE K8 cluster using mentioned [steps](https://github.com/mosip/k8s-infra/tree/v1.2.0.2/mosip/on-prem#mosip-k8s-cluster-setup-using-rke).
      * __Persistence__ : Setup storage class as per [steps](https://github.com/mosip/k8s-infra/tree/v1.2.0.1/mosip/on-prem#storage-classes).
      * __Istio service mesh__ : Setup Istio service mesh using [steps](https://github.com/mosip/k8s-infra/tree/v1.2.0.2/mosip/on-prem#istio-for-service-discovery-and-ingress).
      * __Nginx__ : Setup and configure nginx as per [steps](https://github.com/mosip/k8s-infra/blob/v1.2.0.2/mosip/on-prem/nginx).
      * __Logging__ : Setup logging as per [steps](https://github.com/mosip/k8s-infra/tree/v1.2.0.2/logging).
      * __Monitoring__ : Setup monitoring consisting elasticsearch, kibana, grafana using [steps](https://github.com/mosip/k8s-infra/tree/v1.2.0.2/monitoring).
  * __AWS EKS cluster__ : Create AWS EKS cluster using mentioned [steps](https://github.com/mosip/k8s-infra/tree/main/mosip/aws#mosip-cluster-on-amazon-eks).
      * __Persistence__ : Setup storage class as per [steps](https://github.com/mosip/k8s-infra/tree/main/mosip/aws#persistence).
      * __Ingress and Loadbalancer__ : Setup nginx and configure NLB for exposing services outside using [steps](https://github.com/mosip/k8s-infra/tree/main/mosip/aws#ingress-and-load-balancer-lb).
      * __Logging__ : Setup logging as per [steps](https://github.com/mosip/k8s-infra/tree/v1.2.0.2/logging).
      * __Monitoring__ : Setup monitoring consisting elasticsearch, kibana, grafana using [steps](https://github.com/mosip/k8s-infra/tree/v1.2.0.2/monitoring).

### Install Pre-requisites
* `global` configmap: For inji K8's env, `global` configmap in `default` namespace contains Domain related information. Follow below steps to add domain details for `global` configmap.
    * Copy `global-cm.yaml.sample` to `global-cm.yaml`.
    * Update the domain names in `global-cm.yaml` correctly for your environment.
  ````
  kubectl -n default apply -f global-cm.yaml
  ````
* Install minio
    * Execute minio install script
   ```
  cd object-store/minio
  ./install.sh
  ```
    * Create secrets for config server
  ```
   cd ..
  ./cred.sh
  ```
### Install artifactory

   ```
    cd artifactory
    ./install.sh
   ``` 
### Install config server
* Execute config-server install script
  ```
  cd config-server
  ./install.sh
  ```
    * Review values.yaml and make sure git repository parameters are as per your installation.

### install Onboarder
* Execute Onboarder install script
  ```
  cd partner-onboarder
  ./install.sh
  ```
* During the execution of the `install.sh` script, a prompt appears requesting information for the S3 bucket, including its name and URL.
* Once the job is completed, log in to S3 / NFS and check the reports. There should not be any failures.

### install mimoto
* Execute mimoto install script

  ```
  cd mimoto
  ./install.sh
  ```
* During the execution of the `install.sh` script, a prompt appears requesting information regarding the presence of a public domain and a valid SSL certificate on the server.
* If the server lacks a public domain and a valid SSL certificate, it is advisable to select the `n` option. Opting it will enable the `init-container` with an `emptyDir` volume and include it in the deployment process.
* The init-container will proceed to download the server's self-signed SSL certificate and mount it to the specified location within the container's Java keystore (i.e., `cacerts`) file.
* This particular functionality caters to scenarios where the script needs to be employed on a server utilizing self-signed SSL certificates.

### For Onboarding new Issuer for VCI:

- create a folder "certs" in the root and a file "oidckeystore.p12" inside certs and store the keys as different aliases for every issuers. for more details refer [here](https://docs.mosip.io/inji/inji-mobile-wallet/customization-overview/credential_providers)
