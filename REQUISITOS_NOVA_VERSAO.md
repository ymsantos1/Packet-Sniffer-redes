# Requisitos da Nova Versao do Packet-Sniffer

Baseado na proposta do arquivo `Definicao_Trabalho-redes.pdf`.

## Objetivo

Evoluir o `sniff-it.py` de um sniffer didatico focado em Ethernet/IPv4/TCP para
um analisador capaz de interpretar mais protocolos e detectar possiveis ataques
de ARP spoofing.

## Escopo Principal

- Portar e manter o codigo em Python 3.
- Capturar pacotes em Linux usando raw socket com `AF_PACKET`.
- Roteamento por `EtherType`, sem assumir que todo pacote e TCP.
- Interpretar cabecalhos de Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 e ARP.
- Detectar anomalias em pacotes ARP.
- Mostrar pacotes no terminal.
- Gravar a saida em arquivo `.log`.
- Permitir testes com leitura de arquivos `.pcap`.

## Protocolos e Campos

### Ethernet

Campos necessarios:

- MAC de destino.
- MAC de origem.
- EtherType.

Uso:

- Decidir se o pacote sera tratado como IPv4, IPv6 ou ARP.

### IPv4

Campos necessarios:

- Versao.
- Tamanho do cabecalho.
- TTL.
- Protocolo.
- IP de origem.
- IP de destino.

Uso:

- Roteamento interno para TCP, UDP ou ICMP.

### IPv6

Campos necessarios:

- Versao.
- Traffic class.
- Flow label.
- Payload length.
- Next header.
- Hop limit.
- IP de origem.
- IP de destino.

Uso:

- Roteamento interno para TCP, UDP ou ICMPv6.

### TCP

Campos necessarios:

- Porta de origem.
- Porta de destino.
- Numero de sequencia.
- Numero de confirmacao.
- Tamanho do cabecalho TCP.

### UDP

Campos necessarios:

- Porta de origem.
- Porta de destino.
- Tamanho.
- Checksum.

### ICMP

Campos necessarios:

- Tipo.
- Codigo.
- Checksum.

### ICMPv6

Campos necessarios:

- Tipo.
- Codigo.
- Checksum.

### ARP

Campos necessarios:

- Hardware type.
- Protocol type.
- HLEN.
- PLEN.
- Opcode.
- Sender MAC.
- Sender IP.
- Target MAC.
- Target IP.

## Detector de ARP Spoofing

Criar modulo separado:

```text
arp_detector.py
```

O modulo deve receber os campos ja interpretados do pacote ARP e manter estado
em memoria.

### Tabela IP-MAC

Manter tabela com associacoes observadas:

```text
IP -> MAC
MAC -> lista de IPs
```

Cada entrada deve guardar:

- IP.
- MAC.
- Data/hora da primeira observacao.
- Data/hora da ultima observacao.
- Quantidade de vezes observada.

### Regras de Deteccao

O detector deve alertar quando encontrar:

- Conflito de associacao IP-MAC: mesmo IP aparece com MAC diferente.
- ARPs nao solicitados repetidos dentro de uma janela de tempo.
- Mesmo MAC reivindicando varios IPs.

### Alertas

Para pacotes ARP anomalos, mostrar no terminal:

- Data/hora.
- Tipo de alerta.
- Motivo do alerta.
- Campos ARP relevantes.

Tambem gravar o alerta no arquivo `.log`.

## Entrada

### Captura ao Vivo

Entrada principal via raw socket em Linux:

```python
socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
```

Requer privilegio de root ou capacidade `CAP_NET_RAW`.

### Arquivo PCAP

Adicionar modo de teste por arquivo `.pcap`.

Uso esperado:

```bash
uv run sniff-it.py --pcap captura.pcap
```

Esse modo deve permitir validar parsers e detector sem depender de captura ao
vivo.

## Saida

### Terminal

Mostrar pacotes recebidos e campos interpretados.

Para ARP anomalos, incluir aviso junto ao pacote.

### Log

Gravar toda saida em arquivo `.log`.

Requisito minimo:

```bash
uv run sniff-it.py --log sniff-it.log
```

## Mudancas Necessarias no Codigo

- Reorganizar `sniff-it.py` para separar captura, parsing, deteccao e saida.
- Corrigir parsing atual para Python 3.
- Usar bytes corretamente, sem `ord()`.
- Usar `struct.unpack` para todos os cabecalhos.
- Criar dispatcher por `EtherType`.
- Criar dispatcher por campo `protocol` do IPv4.
- Criar dispatcher por campo `next header` do IPv6.
- Criar parsers para UDP, ICMP, IPv6, ICMPv6 e ARP.
- Criar `arp_detector.py`.
- Adicionar argumentos de linha de comando para captura ao vivo, PCAP e log.
- Adicionar tratamento de erro para pacotes curtos ou malformados.

## Validacao

### Parsers

Comparar os campos interpretados pelo programa com Wireshark ou `tshark` usando
a mesma captura `.pcap`.

### Detector ARP

Validar em ambiente controlado com maquinas virtuais.

Ferramentas sugeridas:

- `arpspoof`.
- `ettercap`.

Resultado esperado:

- Ataque ARP spoofing gera alerta.
- Trafego ARP legitimo comum nao gera excesso de alertas.

## Limitacoes Conhecidas

- Execucao focada em Linux.
- Captura ao vivo exige privilegio.
- Deteccao focada em ARP sobre IPv4/Ethernet.
- Pode haver falsos positivos em situacoes legitimas, como DHCP ou reinicio de
  maquinas.
- O sistema detecta ataques, mas nao bloqueia nem previne ataques.

## Ordem Sugerida de Implementacao

1. Finalizar portabilidade para Python 3.
2. Trocar captura para `AF_PACKET`.
3. Criar estruturas de dados para pacotes parseados.
4. Implementar dispatcher Ethernet.
5. Implementar parsers IPv4, IPv6 e ARP.
6. Implementar parsers TCP, UDP, ICMP e ICMPv6.
7. Implementar log.
8. Implementar leitura de `.pcap`.
9. Implementar `arp_detector.py`.
10. Validar com Wireshark/tshark.
11. Validar deteccao com ataque ARP spoofing em laboratorio.
