# Avaliação de Desempenho e Integração de IDS (Snort, Suricata e Zeek) em Ambiente Físico

Este repositório contém os códigos, scripts de automação e resultados experimentais referentes ao trabalho final da disciplina de Engenharia de Sistemas de Detecção de Intrusões (IDS).

O projeto integra o contexto do GT-IoTEdu, cujo objetivo é o desenvolvimento de sondas de segurança para ambientes acadêmicos e IoT. O foco deste trabalho é a expansão da capacidade de monitoramento da sonda, anteriormente restrita ao IDS Zeek, através da adição e avaliação dos IDS Snort e Suricata.

## Objetivos

O objetivo principal é preparar e validar o ambiente físico de execução para a sonda inteligente do GT-IoTEdu. A validação busca comparar o desempenho computacional e a eficácia de detecção de três ferramentas de mercado: Zeek, Snort e Suricata.

Os objetivos específicos incluem:
1. Implementar o Snort, Zeek e o Suricata no mesmo hardware.
2. Implantar um testbed em um cenário real, simulando ataques a dispositivos conectados à rede, de forma a reproduzir um ambiente realista de ameaças e avaliar o desempenho dos IDSs em condições práticas.
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
    * Foi utilizado o comando `mpstat` para monitorar o uso de CPU e o comando `free` para monitorar o consumo de memória RAM durante os testes de benchmark dos IDSs.

## Resultados Obtidos

Os resultados experimentais foram coletados através da execução de cinco vetores de ataque padronizados contra três motores de detecção de intrusão: Snort, Suricata e Zeek. Os dados completos encontram-se no diretório [benchmark_results](benchmark_results).

### Resumo Executivo

A avaliação comparativa dos três IDSs sob carga de ataque revela diferentes perfis de desempenho e eficácia:

- **Zeek:** Especializado em análise comportamental e logging transacional, com alta capacidade de correlação de eventos. No entanto, apresentou maior latência em alguns cenários.
- **Snort:** Detecção baseada em assinatura com baixa latência e consumo moderado de recursos, sendo adequado para bloqueio em tempo real.
- **Suricata:** Balanceamento entre assinatura e multithreading, oferecendo escalabilidade em ambientes multi-core, com desempenho consistente em diferentes ataques.

### Resultados por Vetor de Ataque

#### 1. DoS Attack (GET/POST Flood, Slowloris, Header Flood)

**Arquivo:** [benchmark_results/snort/dos-http.txt](benchmark_results/snort/dos-http.txt), [benchmark_results/suricata/dos-http.txt](benchmark_results/suricata/dos-http.txt), [benchmark_results/zeek/dos-http.txt](benchmark_results/zeek/dos-http.txt)

| Métrica    | Snort      | Suricata   | Zeek       |
|------------|------------|------------|------------|
| Latência   | 2s         | 3s         | 17s        |
| Pico CPU   | 78%        | 93.18%     | 97.99%     |
| Pico RAM   | 1237 MB    | 1410 MB    | 1215 MB    |
| Log inicial| 40.5 MB    | 62.8 MB    | 189 bytes  |

**Análise:** Snort apresentou a menor latência e consumo de CPU, sendo o mais eficiente neste cenário. Suricata teve desempenho intermediário, enquanto Zeek apresentou alta latência e consumo de CPU, o que pode limitar sua aplicação em cenários de alta carga.

#### 2. Brute Force SSH

**Arquivo:** [benchmark_results/snort/brute-force.txt](benchmark_results/snort/brute-force.txt), [benchmark_results/suricata/brute-force.txt](benchmark_results/suricata/brute-force.txt), [benchmark_results/zeek/brute-force.txt](benchmark_results/zeek/brute-force.txt)

| Métrica    | Snort      | Suricata   | Zeek       |
|------------|------------|------------|------------|
| Latência   | 3s         | 2s         | 3s         |
| Pico CPU   | 20%        | 20.15%     | 60.95%     |
| Pico RAM   | 1174 MB    | 1320 MB    | 1261 MB    |
| Log inicial| 35 MB      | 62.8 MB    | 189 bytes  |

**Análise:** Suricata teve a menor latência, enquanto Snort e Zeek apresentaram desempenho semelhante. Zeek, no entanto, consumiu significativamente mais CPU, o que pode ser um ponto negativo em ambientes com recursos limitados.

#### 3. ICMP Flood (1200 bytes)

**Arquivo:** [benchmark_results/snort/ping-flood.txt](benchmark_results/snort/ping-flood.txt), [benchmark_results/suricata/ping-flood.txt](benchmark_results/suricata/ping-flood.txt), [benchmark_results/zeek/ping-flood.txt](benchmark_results/zeek/ping-flood.txt)

| Métrica    | Snort      | Suricata   | Zeek       |
|------------|------------|------------|------------|
| Latência   | 3s         | 2s         | 99s        |
| Pico CPU   | 6%         | 9.25%      | 4.82%      |
| Pico RAM   | 1119 MB    | 1298 MB    | 1157 MB    |
| Log inicial| 35 MB      | 62.8 MB    | 4 KB       |

**Análise:** Suricata teve a menor latência, enquanto Snort apresentou consumo de CPU mais eficiente. Zeek, apesar do baixo consumo de CPU, teve uma latência extremamente alta, tornando-o inadequado para este tipo de ataque.

#### 4. DNS Tunneling

**Arquivo:** [benchmark_results/snort/dns-tunneling.txt](benchmark_results/snort/dns-tunneling.txt), [benchmark_results/suricata/dns-tunneling.txt](benchmark_results/suricata/dns-tunneling.txt), [benchmark_results/zeek/dns-tunneling.txt](benchmark_results/zeek/dns-tunneling.txt)

| Métrica    | Snort      | Suricata   | Zeek       |
|------------|------------|------------|------------|
| Latência   | 3s         | 3s         | 2s         |
| Pico CPU   | 1%         | 0.51%      | 2.53%      |
| Pico RAM   | 1108 MB    | 1301 MB    | 1095 MB    |
| Log inicial| 40.5 MB    | 62.8 MB    | 866 bytes  |

**Análise:** Zeek teve a menor latência, enquanto Suricata apresentou o menor consumo de CPU. Snort teve desempenho intermediário, com consumo de recursos moderado.

#### 5. SQL Injection

**Arquivo:** [benchmark_results/snort/sql-injection.txt](benchmark_results/snort/sql-injection.txt), [benchmark_results/suricata/sql-injection.txt](benchmark_results/suricata/sql-injection.txt), [benchmark_results/zeek/sql-injection.txt](benchmark_results/zeek/sql-injection.txt)

| Métrica    | Snort      | Suricata   | Zeek       |
|------------|------------|------------|------------|
| Latência   | 4s         | 4s         | 5s         |
| Pico CPU   | 18%        | 5.97%      | 14.58%     |
| Pico RAM   | 1238 MB    | 1409 MB    | 1098 MB    |
| Log inicial| 53.5 MB    | 63.1 MB    | 2.6 KB     |

**Análise:** Suricata teve o menor consumo de CPU, enquanto Zeek apresentou o menor consumo de RAM. Snort teve desempenho equilibrado, mas com maior consumo de CPU.

### Análise Comparativa

#### Eficácia de Detecção

Todos os IDSs detectaram os ataques com sucesso, mas a latência de detecção variou significativamente entre eles. Zeek apresentou maior latência em ataques como DoS e ICMP Flood, enquanto Snort e Suricata tiveram desempenho mais consistente.

#### Consumo de Recursos

Suricata apresentou maior consumo de RAM em quase todos os cenários, enquanto Snort teve consumo de CPU mais eficiente. Zeek, apesar de consumir menos RAM, teve picos de CPU elevados em ataques como DoS.

#### Latência de Detecção

Snort e Suricata tiveram latências mais baixas na maioria dos cenários, enquanto Zeek apresentou alta latência em ataques como DoS e ICMP Flood, o que pode ser um ponto crítico em ambientes de produção.

### Conclusões

A análise demonstra que Snort e Suricata são mais adequados para cenários de alta carga devido à sua baixa latência e consumo equilibrado de recursos. Zeek, embora eficiente em análise comportamental, pode não ser ideal para ataques de alta intensidade devido à sua alta latência e consumo de CPU em alguns cenários.
