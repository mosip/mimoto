#!/bin/bash
# Installs mimoto service
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

NS=mimoto
MIMOTO_CHART_VERSION=0.14.0

echo Create $NS namespace
kubectl create ns $NS

function installing_mimoto() {
  echo Istio label
  kubectl label ns $NS istio-injection=enabled --overwrite
  helm repo add mosip https://mosip.github.io/mosip-helm
  helm repo update

  echo Copy Configmaps
  COPY_UTIL=../copy_cm_func.sh
  $COPY_UTIL configmap global default $NS
  $COPY_UTIL configmap artifactory-share artifactory $NS
  $COPY_UTIL configmap inji-config-server-share config-server $NS

  echo Copy Secrets
  $COPY_UTIL secret keycloak-client-secrets keycloak $NS

  echo "Do you have public domain & valid SSL? (Y/n) "
  echo "Y: if you have public domain & valid ssl certificate"
  echo "n: If you don't have a public domain and a valid SSL certificate. Note: It is recommended to use this option only in development environments."
  read -p "" flag

  if [ -z "$flag" ]; then
    echo "'flag' was provided; EXITING;"
    exit 1;
  fi
  ENABLE_INSECURE=''
  if [ "$flag" = "n" ]; then
    ENABLE_INSECURE='--set enable_insecure=true';
  fi

  echo  "Copy secrets to config-server namespace"
  ../copy_cm_func.sh secret mimoto-wallet-binding-partner-api-key mimoto config-server
  ../copy_cm_func.sh secret mimoto-oidc-partner-clientid mimoto config-server

  echo Updating mimoto-oidc-keystore-password value
  ../copy_cm_func.sh secret mimoto-oidc-keystore-password mimoto config-server

  kubectl -n config-server set env --keys=mimoto-wallet-binding-partner-api-key --from secret/mimoto-wallet-binding-partner-api-key deployment/inji-config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=mimoto-oidc-partner-clientid --from secret/mimoto-oidc-partner-clientid deployment/inji-config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=mimoto-oidc-keystore-password --from secret/mimoto-oidc-keystore-password deployment/inji-config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_

  kubectl -n config-server rollout restart deployment inji-config-server
  kubectl -n config-server rollout status deployment inji-config-server

  echo Installing mimoto
  helm -n $NS install mimoto mosip/mimoto --version $MIMOTO_CHART_VERSION $ENABLE_INSECURE

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
