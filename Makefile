COMPOSE ?= docker compose

.PHONY: help prepull build up insecure contained reset test check-spans llm

help:
	@echo "make prepull    baixa as imagens publicas e constroi as imagens locais"
	@echo "make insecure   demo sem controles: o .env chega no atacante"
	@echo "make contained  MCP, proxy, rede none e credencial"
	@echo "make reset      apaga containers, volumes deste lab e var/"
	@echo "make test       testes de unidade, sem Docker"
	@echo "make llm        opcional; exige AGENT_COMMAND"

prepull:
	$(COMPOSE) pull otel-collector tempo prometheus grafana tempo-init
	$(COMPOSE) build runtime squid

build:
	$(COMPOSE) build runtime squid

up: build
	./scripts/prepare.sh
	$(COMPOSE) up -d
	./scripts/wait_ready.sh

insecure: up
	./scripts/run_insecure.sh

contained: up
	./scripts/run_contained.sh

reset:
	./scripts/reset.sh

test:
	python3 -m unittest discover -s tests -v

check-spans:
	python3 -m lab.check_spans --profile clean var/otel/traces.json

llm:
	./scripts/run_llm.sh
