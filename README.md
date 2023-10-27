# mimoto
This is the mobile server backend supporting Inji.

## Requirements
- Java SE 11
- Maven

## Build
```shell
mvn clean package
```

## Run
```shell
mvn spring-boot:run -Dspring.profiles.active=local
```

## Deployment

### Install

1. Execute Onboarder install script 

```
cd partner-onboarder
./install.sh
```
* During the execution of the `install.sh` script, a prompt appears requesting information for the S3 bucket, including its name and URL.
* Once the job is completed, log in to S3 and check the reports. There should not be any failures.

2. Execute mimoto install script

```
cd helm/mimoto
./install.sh
```
* During the execution of the `install.sh` script, a prompt appears requesting information regarding the presence of a public domain and a valid SSL certificate on the server.
* If the server lacks a public domain and a valid SSL certificate, it is advisable to select the `n` option. Opting it will enable the `init-container` with an `emptyDir` volume and include it in the deployment process.
* The init-container will proceed to download the server's self-signed SSL certificate and mount it to the specified location within the container's Java keystore (i.e., `cacerts`) file.
* This particular functionality caters to scenarios where the script needs to be employed on a server utilizing self-signed SSL certificates.

### Docker compose stack folder structure:
- bin: service jar files
- conf: configuration files for docker services.
- data: using to store shared VC event and generated files.

Follow the build section to compile and get the mimoto-*.jar file in the target folder.

Copy jar files to bin folder. Websub (hub.jar) and safety net is optional, depends on the client app implementation.

### Configuration

conf/nginx/conf.d/mimoto.conf
```nginx
upstream mimoto-service {
    server mimoto-service:8088;
}

server {
    listen 80;
    listen [::]:80;

    access_log /var/log/nginx/mimoto-service.access.log main;

    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
    }

    location /v1/mimoto {
        proxy_pass http://mimoto-service/v1/mimoto;
        proxy_set_header Host $http_host; # required for docker client's sake
        proxy_set_header X-Real-IP $remote_addr; # pass on real client's IP
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

docker-compose.yml
```yaml
version: "3.9"
services:
    nginx:
        image: nginx:alpine
        volumes:
            - ./conf/nginx/proxy_params:/etc/nginx/proxy_params
            - ./conf/nginx/conf.d:/etc/nginx/conf.d
        hostname: nginx
        restart: always
        ports:
            - 80:80
        links:
            - mimoto-service
            - websub
            - safetynet
        depends_on:
            - mimoto-service

    mimoto-service:
        image: openjdk:11-jre-slim
        volumes:
            - ./bin:/opt/mimoto-service
            - ./data:/data
        hostname: mimoto-service
        restart: always
        command: >
        bash -c "cd /data && java -jar \
            -Dpublic.url=https://YOUR_PUBLIC_URL_FOR_MIMOTO_SERVICE \
            -Dcredential.data.path=/data \
            -Dmosip.event.delay-millisecs=5000 \
            -Dwebsub-resubscription-delay-millisecs=300000 \
            -Dsafetynet.api.key=GOOGLE_API_KEY \
            /opt/mimoto-service/mimoto-*.jar"
        expose:
            - 8088
```

Note:
- Replace public.url with your public accessible domain. For dev or local env ngrok is recommended.
- Google safetynet API key can be generate from Google Cloud Console.

### Run with docker-compose
```shell
docker-compose up -d
```

## Update

Copy and replace the new version of the jar files in the bin folder and restart the docker service.

```shell
docker-compose restart mimoto-service
```

## Credits
Credits listed [here](/Credits.md)
