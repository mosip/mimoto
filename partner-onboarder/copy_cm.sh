#!/bin/bash
# Copy configmaps from other namespaces
# DST_NS: Destination namespace 

COPY_UTIL=./copy_cm_func.sh
DST_NS=$( printenv NS )

$COPY_UTIL configmap inji-stack-config default $DST_NS
$COPY_UTIL configmap keycloak-env-vars keycloak $DST_NS || { echo "Ignore this error if Keycloak is deployed externally and its details have been added to values.yaml. If not, please update values.yaml as per the instructions in README.md."; true; }
$COPY_UTIL configmap keycloak-host keycloak $DST_NS || { echo "Ignore this error if Keycloak is deployed externally and its details have been added to values.yaml. If not, please update values.yaml as per the instructions in README.md."; true; }
