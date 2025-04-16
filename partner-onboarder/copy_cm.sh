#!/bin/bash
# Copy configmaps from other namespaces
# DST_NS: Destination namespace 

COPY_UTIL=./copy_cm_func.sh
DST_NS=injiweb

$COPY_UTIL configmap inji-stack-config default $DST_NS
$COPY_UTIL configmap keycloak-env-vars keycloak $DST_NS || { echo "Ignore the error if Keycloak is deployed externally and details of the same have been added to values.yaml."; true; }
$COPY_UTIL configmap keycloak-host keycloak $DST_NS || { echo "Ignore the error if Keycloak is deployed externally and details of the same have been added to values.yaml."; true; }
