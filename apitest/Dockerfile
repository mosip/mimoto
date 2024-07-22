FROM openjdk:11

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME
LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001
ARG KUBECTL_VERSION=1.22.9

WORKDIR /home/${container_user}

ENV work_dir=/home/${container_user}

# Combine ADD, COPY, and file operations into a single layer
COPY . /temp

# Combine all RUN commands into a single layer
RUN apt-get -y update && \
    apt-get install -y unzip jq && \
    groupadd -g ${container_user_gid} ${container_user_group} && \
    useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/sh -m ${container_user} && \
    curl -LO "https://storage.googleapis.com/kubernetes-release/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/ && \
    chown -R ${container_user}:${container_user} /home/${container_user} /usr/local/openjdk-11/lib/security/cacerts && \
    chmod 644 /usr/local/openjdk-11/lib/security/cacerts && \
    chmod +x $work_dir/entrypoint.sh && \
    mv /temp/apitest/target/* $work_dir && \
    mv /temp/application.properties $work_dir && \
    mv /temp/Biometric\ Devices $work_dir/Biometric\ Devices && \
    mv /temp/resource $work_dir/resource && \
    mv /temp/entrypoint.sh $work_dir/entrypoint.sh && \
    rm -rf /temp

USER ${container_user_uid}:${container_user_gid}

WORKDIR ${work_dir}

EXPOSE 8083

ENV MODULES=
ENV ENV_USER=
ENV ENV_ENDPOINT=
ENV ENV_TESTLEVEL=smokeAndRegression

ENTRYPOINT ["./entrypoint.sh"]
