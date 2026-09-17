# Atajos del laboratorio WAAP (Fases 3-7) usando Podman.
ENGINE ?= podman
IMAGE ?= localhost/waap-tooling:latest
COMPOSE ?= podman compose
PROXY_URL ?= http://localhost:4000

# Ejecuta un comando dentro del contenedor de tooling con el repo montado.
RUN := $(ENGINE) run --rm --network=host --userns=keep-id --security-opt label=disable \
	-v $(CURDIR):/work -w /work $(IMAGE)

.PHONY: help tooling setup lab-up lab-up-detection lab-down wait-proxy phase3 phase4 phase5 phase6 phase7 collect shell all

help:
	@echo "Objetivos disponibles (Podman):"
	@echo "  make tooling            Construye la imagen localhost/waap-tooling (Python 3.12)"
	@echo "  make setup              Alias de tooling"
	@echo "  make shell              Abre una shell dentro del contenedor de tooling"
	@echo "  make lab-up             Levanta Juice Shop + proxy WAAP (WAF activo) y espera al proxy"
	@echo "  make lab-up-detection   Levanta el proxy en DetectionOnly (recoleccion Fase 3)"
	@echo "  make lab-down           Detiene el laboratorio"
	@echo "  make phase3             Genera trafico, entrena y evalua el modelo IA/ML"
	@echo "  make phase4             Casos RASP + latencia"
	@echo "  make phase5             Pipeline DevSecOps + verificacion rojo/verde"
	@echo "  make phase6             Matriz de evasion por capa"
	@echo "  make phase7             Observabilidad y metricas"
	@echo "  make collect            Organiza evidencias en logs/entrega/ + entrega.zip"
	@echo "  make all                tooling + lab-up + phase3..7 + collect + lab-down"

tooling:
	$(ENGINE) build -f tooling/Containerfile -t $(IMAGE) .

setup: tooling

shell: tooling
	$(RUN) bash

lab-up:
	@test -f .env || cp .env.example .env
	$(COMPOSE) up -d
	$(MAKE) wait-proxy

lab-up-detection:
	@test -f .env || cp .env.example .env
	MODSEC_RULE_ENGINE=DetectionOnly $(COMPOSE) up -d --force-recreate waap-proxy
	$(MAKE) wait-proxy

lab-down:
	$(COMPOSE) down

wait-proxy:
	@echo "Esperando al proxy WAAP en $(PROXY_URL) ..."
	@for i in $$(seq 1 60); do \
		if curl -fsS -o /dev/null "$(PROXY_URL)/" 2>/dev/null; then \
			echo "Proxy listo."; exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "ERROR: el proxy no respondio en $(PROXY_URL)"; exit 1

phase3: tooling
	$(RUN) bash -lc 'cd traffic_agent && python agent.py && python train_model.py && python evaluate_model.py'

phase4: tooling
	$(RUN) python app/run_rasp_tests.py

phase5: tooling
	$(RUN) python pipeline/run_pipeline.py
	$(RUN) python pipeline/verify_pipeline.py --mode sast

phase6: tooling
	$(RUN) python scripts/attack_matrix.py

phase7: tooling
	$(RUN) python observability/collect_metrics.py

collect: tooling
	$(RUN) python scripts/collect_evidence.py

all:
	$(MAKE) tooling
	$(MAKE) lab-up
	$(MAKE) phase3
	$(MAKE) phase4
	$(MAKE) phase5
	$(MAKE) phase6
	$(MAKE) phase7
	$(MAKE) collect
	$(MAKE) lab-down
