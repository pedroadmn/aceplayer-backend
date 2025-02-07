FROM maven:3.8.5-openjdk-17 AS build

WORKDIR .
COPY . .
RUN mvn clean package -DskipTests

FROM openjdk:17-jdk-slim

EXPOSE 8080

COPY --from=build /target/aceplayer-backend-0.0.1-SNAPSHOT.jar aceplayer.jar

ENTRYPOINT ["java", "-jar", "aceplayer.jar", "--spring.profiles.active=production"]