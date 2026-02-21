# Local development

## Database (Docker Postgres)

Start Postgres:

```bash
docker compose up -d
```

View logs:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

## Run the application

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

## Run tests

```bash
./mvnw test
```
