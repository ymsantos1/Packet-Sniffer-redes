# Sniff-It

Sniff-It é um analisador didático de pacotes de rede escrito em Python 3. Ele
interpreta quadros Ethernet capturados ao vivo no Linux ou lidos de arquivos
`.pcap`, mostra os campos principais no terminal e grava a mesma saída em um
arquivo de log.

O projeto também inclui um detector simples de anomalias ARP para apontar
possíveis sinais de ARP spoofing durante a análise.

## Funcionalidades

- Captura ao vivo em Linux usando raw socket `AF_PACKET`.
- Análise offline de arquivos `.pcap`, sem exigir privilégio de root.
- Suporte a PCAP com linktype Ethernet, Linux SLL e Linux SLL2.
- Interpretação de Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 e ARP.
- Despacho por `EtherType`, protocolo IPv4 e `Next Header` IPv6.
- Tratamento de pacotes curtos, truncados ou com cabeçalho inválido.
- Saída no terminal e gravação em `.log`.
- Limite opcional de quantidade de pacotes processados.
- Alertas para conflitos e comportamentos suspeitos em tráfego ARP.
- Testes automatizados com `unittest`.

## Requisitos

- Linux para captura ao vivo.
- Python 3.10 ou superior.
- Permissão de root ou `CAP_NET_RAW` para `--live`.
- Nenhuma dependência externa de Python.

Para analisar arquivos `.pcap`, não é necessário executar como root.

## Estrutura do projeto

```text
sniff-it.py                  Entrada do CLI
sniffit/
  capture.py                 Captura ao vivo com raw socket
  cli.py                     Argumentos e fluxo principal
  constants.py               Constantes de protocolos
  formatters.py              Formatação dos pacotes
  output.py                  Saída no terminal e log
  parsers.py                 Parsers binários dos cabeçalhos
  pcap.py                    Leitura e normalização de PCAP
tools/
  arp_detector.py            Detector de anomalias ARP
  generate_validation_pcap.py Gerador da captura de validação
tests/                       Testes automatizados
validation-ipv6-icmp-arp.pcap Captura pequena usada nos testes
```

## Uso rápido

Veja as opções disponíveis:

```bash
python3 sniff-it.py --help
```

Analise a captura de validação do projeto:

```bash
python3 sniff-it.py --pcap validation-ipv6-icmp-arp.pcap --max-packets 5
```

Grave a saída em outro arquivo de log:

```bash
python3 sniff-it.py --pcap validation-ipv6-icmp-arp.pcap --log minha-analise.log
```

Processe todos os pacotes de um PCAP:

```bash
python3 sniff-it.py --pcap captura.pcap --max-packets 0
```

Capture pacotes ao vivo:

```bash
sudo python3 sniff-it.py --live
```

Capture ao vivo e pare depois de 50 pacotes:

```bash
sudo python3 sniff-it.py --live --max-packets 50 --log sniff-it-live.log
```

## Opções do CLI

`--live`

Captura pacotes da rede ao vivo usando socket raw. Esse modo funciona em Linux e
exige root ou permissão equivalente para abrir sockets raw.

`--pcap CAMINHO`

Lê pacotes de um arquivo `.pcap`. Esse é o modo recomendado para testes,
validação e análise reproduzível.

`--log CAMINHO`

Define o arquivo onde a saída também será gravada. O valor padrão é
`sniff-it.log`.

`--max-packets N`

Para depois de `N` pacotes. O valor padrão é `0`, que significa sem limite.
Valores negativos são recusados.

Os modos `--live` e `--pcap` são mutuamente exclusivos. Um deles sempre deve ser
informado.

## Saída

Para cada pacote, o programa mostra:

- número do pacote;
- cabeçalho Ethernet;
- protocolo de rede identificado;
- campos principais do protocolo de transporte, quando suportado;
- alertas ARP, quando houver.

Exemplo resumido:

```text
Pacote 1
############### Ethernet ###############
MAC Destino: 66:77:88:99:aa:bb
MAC Origem: 00:11:22:33:44:55
EtherType: 0x0800
############### IPv4 ###############
Versão: 4
TTL: 64
Protocolo: 1
IP Origem: 192.0.2.10
IP Destino: 192.0.2.1
########## ICMP ##########
Tipo: 8
Código: 0
Checksum: 0x0000
```

## Detector de ARP spoofing

O detector fica em `tools/arp_detector.py` e mantém estado em memória durante a
execução. Ele observa associações entre IPs e MACs e emite alertas quando
encontra padrões suspeitos:

- mesmo IP aparecendo com MAC diferente;
- ARP gratuito repetido várias vezes dentro de uma janela curta;
- mesmo MAC reivindicando vários IPs.

Alertas aparecem junto do pacote ARP no terminal e também são gravados no log.

Exemplo de alerta:

```text
[ALERTA 2026-07-02T09:15:30] Conflito de associação IP-MAC: IP 192.0.2.1 estava associado ao MAC 00:11:22:33:44:55 e agora foi visto com o MAC 66:77:88:99:aa:bb.
```

Importante: o detector sinaliza comportamentos suspeitos, mas não bloqueia nem
previne ataques. Falsos positivos podem ocorrer em cenários legítimos, como
DHCP, troca de placa de rede, reinício de máquinas ou mudanças de topologia.

## Arquivos PCAP

O modo `--pcap` aceita arquivos no formato PCAP clássico. Arquivos `.pcapng` não
são suportados diretamente nesta versão.

Para gerar captura com `tcpdump`:

```bash
sudo tcpdump -i any -w captura.pcap
```

Depois, analise sem `sudo`:

```bash
python3 sniff-it.py --pcap captura.pcap --log sniff-it.log
```

## Testes

Execute todos os testes:

```bash
python3 -m unittest discover -s tests
```

Os testes cobrem:

- parser de Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 e ARP;
- leitura de PCAP;
- formatação dos pacotes;
- alertas do detector ARP usando a captura de validação;
- comportamento básico do CLI.

## Limitações conhecidas

- Captura ao vivo focada em Linux.
- `--live` exige root ou `CAP_NET_RAW`.
- Leitura offline suporta `.pcap`, não `.pcapng`.
- IPv6 extension headers não são percorridos; o parser usa o `Next Header` do
  cabeçalho base.
- O projeto interpreta cabeçalhos e metadados principais; payload de aplicação
  não é decodificado.
- A detecção ARP é heurística e focada em ARP sobre Ethernet/IPv4.

## Licença

Este projeto deriva de um packet sniffer didático originalmente licenciado sob
[Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/).
Mantenha os termos da licença original ao reutilizar ou distribuir o código.
