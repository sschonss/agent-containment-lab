COMPOSE ?= docker compose

.PHONY: help prepull build up insecure contained reset test check-spans llm

help:
	@echo "make prepull    baixa imagens, constroi as locais e puxa o modelo do Ollama"
	@echo "make insecure   demo sem controles: o .env chega no atacante"
	@echo "make contained  MCP, proxy, rede none e credencial"
	@echo "make reset      apaga containers, volumes de telemetria e var/; guarda o modelo"
	@echo "make test       testes de unidade, sem Docker"
	@echo "make llm        agente com Ollama nos dois modos (LLM_RUNS, LLM_MODE)"

prepull:
	$(COMPOSE) pull otel-collector tempo prometheus grafana tempo-init
	$(COMPOSE) --profile llm pull ollama
	$(COMPOSE) build runtime squid
	$(COMPOSE) --profile llm up -d ollama
	$(COMPOSE) --profile llm exec -T ollama ollama pull qwen2.5:3b

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

llm: up
	$(COMPOSE) --profile llm up -d ollama
	./scripts/run_llm.sh
