# mimoto
This is the mobile server backend supporting mobileid.

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

## Deploy

### Docker compose stack folder structure:
- bin: service jar files
- conf: configuration files for docker services.
- data: using to store shared VC event and generated files.

Follow the build section to compile and get the mosip-resident-app-0.2.0-SNAPSHOT.jar file in the target folder.

Copy jar files to bin folder. Websub (hub.jar) and safety net is optional, depends on the client app implementation.

### Configuration

conf/nginx/conf.d/mosip-residentapp.conf
```nginx
upstream mosip-residentapp-service {
    server mosip-residentapp-service:8088;
}

server {
    listen 80;
    listen [::]:80;
    #server_name  resident-app.newlogic.dev;

    access_log /var/log/nginx/mosip-residentapp-service.access.log main;

    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
    }

    location /v1/resident {
        proxy_pass http://mosip-residentapp-service/v1/resident;
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
            - mosip-residentapp-service
            - websub
            - safetynet
        depends_on:
            - mosip-residentapp-service

    mosip-residentapp-service:
        image: openjdk:11-jre-slim
        volumes:
            - ./bin:/opt/mosip-residentapp-service
            - ./data:/data
        hostname: mosip-residentapp-service
        restart: always
        command: >
        bash -c "cd /data && java -jar \
            -Dpublic.url=https://resident-app.newlogic.dev \
            -Dcredential.data.path=/data \
            -Dmosip.event.delay-millisecs=5000 \
            -Dwebsub-resubscription-delay-millisecs=300000 \
            -Dsafetynet.api.key=GOOGLE_API_KEY \
            /opt/mosip-residentapp-service/mosip-resident-app-0.2.0-SNAPSHOT.jar"
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
docker-compose restart mosip-residentapp-service
```
