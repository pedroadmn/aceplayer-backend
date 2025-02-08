FROM maven:3.8.7-openjdk-18 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-slim
ARG PROFILE=docker
ARG APP_VERSION=1.0.1

WORKDIR /app
COPY --from=build /build/target/aceplayer-backend-*.jar /app/

#RUN APP_VERSION=$(ls /app | grep *.jar | awk 'NR==2{split($0,a,"-"); print a[3]}' | awk '{sub(/.jar$/,"")}1')\
#    && echo "Building container with BSN v-$version"
EXPOSE 8088

ENV DB_URL=jdbc:postgresql://postgres-sql-ace-player:5432/aceplayerdb
ENV MAILDEV_URL=localhost

ENV ACTIVE_PROFILE=${PROFILE}
ENV JAR_VERSION=${APP_VERSION}

CMD java -jar -Dspring.profiles.active=${ACTIVE_PROFILE} -Dspring.datasource.url=${DB_URL} aceplayer-backend-${JAR_VERSION}.jar