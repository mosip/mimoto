#!/bin/bash
# Copy configmaps from other namespaces
# DST_NS: Destination namespace

COPY_UTIL=./copy_cm_func.sh
DST_NS=mimoto

$COPY_UTIL configmap global default $DST_NS
$COPY_UTIL configmap artifactory-share artifactory $DST_NS
$COPY_UTIL configmap inji-config-server-share config-server $DST_NS