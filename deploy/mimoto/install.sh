#!/bin/bash
# Installs mimoto service
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

NS=injiweb
CHART_VERSION=0.0.1-develop
KEYGEN_CHART_VERSION=1.3.0-beta.2
SOFTHSM_NS=softhsm
SOFTHSM_CHART_VERSION=1.3.0-beta.2

echo Create $NS namespace
kubectl create ns $NS

function installing_mimoto() {
  echo Istio label
  kubectl label ns $NS istio-injection=enabled --overwrite
  helm repo add mosip https://mosip.github.io/mosip-helm
  helm repo update

  echo Copy Configmaps
  COPY_UTIL=../copy_cm_func.sh
  $COPY_UTIL configmap inji-stack-config default $NS
  $COPY_UTIL configmap artifactory-share artifactory $NS
  $COPY_UTIL configmap config-server-share config-server $NS
  $COPY_UTIL configmap redis-config redis $NS

  echo Copy Secrets
  $COPY_UTIL secret redis redis $NS
  $COPY_UTIL secret db-common-secrets postgres $NS

  echo "Do you have public domain & valid SSL? (Y/n) "
  echo "Y: if you have public domain & valid ssl certificate"
  echo "n: If you don't have a public domain and a valid SSL certificate. Note: It is recommended to use this option only in development environments."
  read -p "" flag

  if [ -z "$flag" ]; then
    echo "'flag' was not provided; EXITING;"
    exit 1;
  fi
  ENABLE_INSECURE=''
  if [ "$flag" = "n" ]; then
    ENABLE_INSECURE='--set enable_insecure=true';
  fi

  echo "Do you want to use SoftHSM or .p12 keystore for key management?"
  echo "1) SoftHSM"
  echo "2) .p12 keystore"
  echo "3) External HSM"
  read -p "Enter 1, 2 or 3 [default: 2]: " keystore_choice
  keystore_choice=${keystore_choice:-2}

  if [[ "$keystore_choice" == "1" ]]; then
    echo Installing SoftHSM
    helm -n $SOFTHSM_NS install softhsm-mimoto mosip/softhsm -f softhsm-values.yaml --version $SOFTHSM_CHART_VERSION --wait

    echo Copy SoftHSM configMap and Secret to $NS and config-server
    $COPY_UTIL configmap softhsm-mimoto-share softhsm $NS
    $COPY_UTIL secret softhsm-mimoto softhsm config-server
    $COPY_UTIL secret softhsm-mimoto softhsm $NS
    kubectl -n config-server set env --keys=security-pin --from secret/softhsm-mimoto deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_MIMOTO_

  elif [[ "$keystore_choice" == "2" ]]; then
    volume_size=200M
    volume_mount_path='/home/mosip/encryption'
    PVC_CLAIM_NAME='mimoto-keygen-keymanager'
    MIMOTO_KEYGEN_HELM_ARGS='--set springConfigNameEnv="mimoto"'
    MIMOTO_HELM_ARGS=''

    if kubectl -n $NS get pvc "$PVC_CLAIM_NAME" >/dev/null 2>&1; then
      echo "PVC $PVC_CLAIM_NAME already exists. Skipping keygen job."
    else
      echo "Creating new PVC and running keygen job"
      MIMOTO_KEYGEN_HELM_ARGS="--set persistence.enabled=true  \
               --set volumePermissions.enabled=true \
               --set persistence.size=$volume_size \
               --set persistence.mountDir=\"$volume_mount_path\" \
               --set springConfigNameEnv='mimoto' \
               --set persistence.pvc_claim_name=\"$PVC_CLAIM_NAME\" \
               --set keysDir=\"$volume_mount_path\" \
               --set keyStore.fileName=\"encryptionkeystore.p12\" \
               --set skipIfFileExists=true"

      echo "MIMOTO KEYGEN HELM ARGS $MIMOTO_KEYGEN_HELM_ARGS"
      echo "Running mimoto keygen"
      helm -n $NS install mimoto-keygen mosip/keygen -f keygen-mimoto.yaml $MIMOTO_KEYGEN_HELM_ARGS --wait --wait-for-jobs --version $KEYGEN_CHART_VERSION
    fi

  elif [[ "$keystore_choice" == "3" ]]; then
    echo "Setting up External HSM configuration"
    read -p "Please provide the URL where externalhsm client zip is located: " externalhsmclient
    read -p "Please provide the host URL for externalhsm: " externalhsmhosturl
    read -p "Please provide the password for the externalhsm: " externalhsmpassword

    kubectl create configmap softhsm-mimoto-share --from-literal=hsm_client_zip_url_env="$externalhsmclient" --from-literal=PKCS11_PROXY_SOCKET="$externalhsmhosturl" -n softhsm --dry-run=client -o yaml | kubectl apply -f -
    kubectl create secret generic softhsm-mimoto --from-literal=security-pin="$externalhsmpassword" -n softhsm --dry-run=client -o yaml | kubectl apply -f -
    $COPY_UTIL configmap softhsm-mimoto-share softhsm $NS
    $COPY_UTIL secret softhsm-mimoto softhsm config-server
    $COPY_UTIL secret softhsm-mimoto softhsm $NS
    kubectl -n config-server set env --keys=security-pin --from secret/softhsm-mimoto deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_MIMOTO_
  else
    echo "Invalid option. Please choose 1, 2, or 3."
    exit 1
  fi

  echo  "Copy secrets to config-server namespace"
  ../copy_cm_func.sh secret mimoto-wallet-binding-partner-api-key injiweb config-server
  ../copy_cm_func.sh secret mimoto-oidc-partner-clientid injiweb config-server

  echo Updating mimoto-oidc-keystore-password value
  ../copy_cm_func.sh secret mimoto-oidc-keystore-password injiweb config-server

  kubectl -n config-server set env --keys=mimoto-wallet-binding-partner-api-key --from secret/mimoto-wallet-binding-partner-api-key deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=mimoto-oidc-partner-clientid --from secret/mimoto-oidc-partner-clientid deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=mimoto-oidc-keystore-password --from secret/mimoto-oidc-keystore-password deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_

  kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status

  echo "Please proceed with generating the Google Client ID and Secret Key required for integration."
  read -p "Please enter the Google Client ID: " clientId

  if [ -z "$clientId" ]; then
    echo "'clientId' was not provided; EXITING;"
    exit 1;
  fi
  read -p "Please enter the Google Secret Key: " secretKey

  if [ -z "$secretKey" ]; then
    echo "'secretKey' was not provided; EXITING;"
    exit 1;
  fi


  echo Installing mimoto
  helm -n $NS install mimoto mosip/mimoto  --version $CHART_VERSION -f values.yaml $ENABLE_INSECURE \
    --set mimoto.secrets.google-client.MOSIP_INJIWEB_GOOGLE_CLIENT_ID="$clientId" \
    --set mimoto.secrets.google-client.MOSIP_INJIWEB_GOOGLE_CLIENT_SECRET="$secretKey"

  kubectl -n $NS  get deploy -o name |  xargs -n1 -t  kubectl -n $NS rollout status

  echo Installed mimoto

  return 0
}

# set commands for error handling.
set -e
set -o errexit   ## set -e : exit the script if any statement returns a non-true return value
set -o nounset   ## set -u : exit the script if you try to use an uninitialised variable
set -o errtrace  # trace ERR through 'time command' and other functions
set -o pipefail  # trace ERR through pipes
installing_mimoto   # calling function
