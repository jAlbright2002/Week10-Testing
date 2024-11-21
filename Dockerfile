FROM openjdk:21-jdk

WORKDIR /app

COPY target/TaskManagementRegistration-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]