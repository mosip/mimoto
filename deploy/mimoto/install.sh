#!/bin/bash
# Installs mimoto service
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

NS=injiweb
CHART_VERSION=0.0.1-develop
KEYGEN_CHART_VERSION=1.3.0-beta.2

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

  echo  "Copy secrets to config-server namespace"
  ../copy_cm_func.sh secret mimoto-wallet-binding-partner-api-key injiweb config-server
  ../copy_cm_func.sh secret mimoto-oidc-partner-clientid injiweb config-server

  echo Updating mimoto-oidc-keystore-password value
  ../copy_cm_func.sh secret mimoto-oidc-keystore-password injiweb config-server

  kubectl -n config-server set env --keys=mimoto-wallet-binding-partner-api-key --from secret/mimoto-wallet-binding-partner-api-key deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=mimoto-oidc-partner-clientid --from secret/mimoto-oidc-partner-clientid deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=mimoto-oidc-keystore-password --from secret/mimoto-oidc-keystore-password deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_

  kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status

  default_enable_volume=true  # Default to true for mimoto
  read -p "Would you like to enable volume (true/false) : [ default : true ] : " enable_volume
  enable_volume=${enable_volume:-$default_enable_volume}
  MIMOTO_KEYGEN_HELM_ARGS='--set springConfigNameEnv="mimoto"'
  MIMOTO_HELM_ARGS=''

  if [[ $enable_volume == 'true' ]]; then
    default_volume_size=200M
    read -p "Provide the size for volume [ default : 200M ]" volume_size
    volume_size=${volume_size:-$default_volume_size}
    volume_mount_path='/home/mosip/encryption'
    PVC_CLAIM_NAME='mimoto-keygen-keymanager'

    # Check if PVC already exists
    if kubectl -n $NS get pvc "$PVC_CLAIM_NAME" >/dev/null 2>&1; then
      echo "PVC $PVC_CLAIM_NAME already exists. Skipping keygen job."
      # Verify if the keystore file exists in the PVC (this would require a temporary pod to check)
      # For simplicity, we'll assume if PVC exists, the keystore is there
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
               --set skipIfFileExists=true"  # Add this flag to skip if file exists

      echo "MIMOTO KEYGEN HELM ARGS $MIMOTO_KEYGEN_HELM_ARGS"
      echo "Running mimoto keygen"
      helm -n $NS install mimoto-keygen mosip/keygen $MIMOTO_KEYGEN_HELM_ARGS --wait --wait-for-jobs --version $KEYGEN_CHART_VERSION
    fi
  fi
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
