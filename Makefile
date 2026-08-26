.PHONY: help setup up down logs build test lint format clean

help:
	@echo "ThreatMesh development commands"
	@echo "  make setup   Create local environment files"
	@echo "  make up      Build and start the full stack"
	@echo "  make down    Stop the stack"
	@echo "  make test    Run backend and frontend tests"
	@echo "  make lint    Run static checks"

setup:
	@test -f .env || cp .env.example .env
	@test -f frontend/.env || cp frontend/.env.example frontend/.env

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

build:
	docker compose build

test:
	cd backend && python -m pytest
	cd frontend && npm test

lint:
	cd backend && python -m ruff check .
	cd frontend && npm run lint
	cd frontend && npm run typecheck

format:
	cd backend && python -m ruff format .
	cd frontend && npm run format

clean:
	docker compose down --remove-orphans
