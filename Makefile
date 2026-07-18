.PHONY: up down restart logs ps clean seed

up:
	cp -n .env.example .env || true
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

ps:
	docker compose ps

clean:
	docker compose down -v --remove-orphans

seed:
	docker compose exec postgres psql -U $${POSTGRES_USER} -d $${POSTGRES_DB} -f /docker-entrypoint-initdb.d/init.sql

health:
	@echo "Postgres:";    docker compose exec postgres pg_isready -U $${POSTGRES_USER}
	@echo "FalkorDB:";    docker compose exec falkordb redis-cli -a $${REDIS_PASSWORD} ping
	@echo "OpenSearch:";  curl -sf http://localhost:9200/_cluster/health | python3 -m json.tool
	@echo "ClickHouse:";  docker compose exec clickhouse clickhouse-client --user=$${CLICKHOUSE_USER} --password=$${CLICKHOUSE_PASSWORD} --query="SELECT 'ok'"
	@echo "NATS:";        curl -sf http://localhost:8222/healthz
	@echo "MinIO:";       curl -sf http://localhost:9000/minio/health/live && echo ok
