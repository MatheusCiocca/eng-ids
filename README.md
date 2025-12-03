# Avaliação de Desempenho e Integração de IDS (Snort, Suricata e Zeek) em Ambiente Físico

Este repositório contém os códigos, scripts de automação e resultados experimentais referentes ao trabalho final da disciplina de Engenharia de Sistemas de Detecção de Intrusões (IDS).

O projeto integra o contexto do GT-IoTEdu, cujo objetivo é o desenvolvimento de sondas de segurança para ambientes acadêmicos e IoT. O foco deste trabalho é a expansão da capacidade de monitoramento da sonda, anteriormente restrita ao IDS Zeek, através da adição e avaliação dos IDS Snort e Suricata.

## Objetivos

O objetivo principal é preparar e validar o ambiente físico de execução para a sonda inteligente do GT-IoTEdu. A validação busca comparar o desempenho computacional e a eficácia de detecção de três ferramentas de mercado: Zeek, Snort e Suricata.

Os objetivos específicos incluem:
1. Implementar o Snort, Zeek e o Suricata no mesmo hardware.
2. Replicar a metodologia de ataques utilizada em estudos anteriores (Torres et al.), migrando do ambiente de emulação (Docker) para um ambiente de hardware físico no laboratório da UNIPAMPA.
3. Avaliar o consumo de recursos (CPU e Memória) e a latência de detecção sob estresse real, visando suprir a lacuna de testes em arquitetura nativa.

## Metodologia

A metodologia baseia-se na reprodução dos vetores de ataque definidos no estudo de referência, porém alterando o ambiente de execução de virtualizado para físico para obter métricas de desempenho mais fiéis ao cenário de produção.

### Cenário de Testes
Os experimentos foram conduzidos na rede do laboratório da UNIPAMPA. A topologia física compreende:
* **Máquina Atacante:** Responsável pela injeção de tráfego malicioso.
* **Máquina Alvo:** Servidor vítima das requisições.
* **Sonda (Probe):** Hardware físico dedicado executando os IDSs em modo passivo (monitoramento de porta/TAP).

### Vetores de Ataque
Foram executados os cinco ataques padronizados no estudo de referência:

1. **DoS Attack:** Negação de serviço combinando GET Flood, POST Flood, Slowloris e Header Flood.
2. **Brute Force SSH:** Tentativa de força bruta contra o serviço SSH (usuário 'root') utilizando listas de senhas aleatórias.
3. **ICMP Flood:** Envio massivo de pacotes ICMP (1200 bytes) para saturação de banda e processamento.
4. **DNS Tunneling:** Simulação de exfiltração de dados via consultas DNS com subdomínios longos e de alta entropia.
5. **SQL Injection:** Exploração automática de vulnerabilidades SQL em modo batch.

## Arquitetura e Tecnologias

O sistema utiliza as seguintes tecnologias e ferramentas:

* **Motores de Detecção:**
    * Zeek (Foco em análise comportamental e logs transacionais).
    * Snort (Detecção baseada em assinatura).
    * Suricata (Detecção baseada em assinatura com multithreading).
* **Ferramentas de Auditoria e Ataque:**
    * Foi utilizado o comando `Docker stats` para monitorar o consumo da maquina Docker dos IDs.

## Resultados Experimentais

Os resultados detalhados encontram-se no diretório `benchmark_results` e incluem:
* Logs de alertas gerados por cada ferramenta.
* Tabelas de eficácia de detecção (Positivo/Negativo) para cada vetor.

A análise foca na viabilidade de execução simultânea das ferramentas no hardware físico e na comparação com os dados prévios obtidos em ambiente emulado.

## Como Executar

Instruções para reprodução dos experimentos:

1. TODO

## Referências Bibliográficas

* Torres, R. B., Mansilha, R. B., Kreutz, D. Análise de Desempenho e Eficácia da Sonda Zeek: Um Estudo Comparativo de Perfis de Execução sob Restrições de Recursos.
* Documentação Oficial do Snort, Suricata e Zeek.