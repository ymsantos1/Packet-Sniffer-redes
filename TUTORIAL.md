# Tutorial de Uso do Sniff-It

Este tutorial mostra como usar a versao atual do `sniff-it.py` de forma mais
segura, dando preferencia para analise de arquivos `.pcap` em vez de captura ao
vivo com privilegio de administrador.

## Modo recomendado: analisar arquivo PCAP

O modo recomendado e usar um arquivo `.pcap` ja capturado:

```bash
uv run sniff-it.py --pcap arquivo.pcap
```

Esse modo nao precisa de `root`, porque o programa apenas le pacotes salvos em
arquivo.

Exemplo com log:

```bash
uv run sniff-it.py --pcap arquivo.pcap --log sniff-it.log
```

## Erro comum: arquivo PCAP nao existe

Se voce executar:

```bash
uv run sniff-it.py --pcap captura.pcap --log sniff-it.log
```

e receber:

```text
[Errno 2] No such file or directory: 'captura.pcap'
```

isso significa que `captura.pcap` foi usado como nome de exemplo, mas esse
arquivo nao existe no diretorio atual.

Use o caminho real do arquivo:

```bash
uv run sniff-it.py --pcap /caminho/para/captura.pcap --log sniff-it.log
```

Ou coloque o arquivo `.pcap` dentro deste projeto e use:

```bash
uv run sniff-it.py --pcap nome-do-arquivo.pcap --log sniff-it.log
```

## Como procurar arquivos de captura no projeto

Para verificar se existe algum arquivo de captura no diretorio atual:

```bash
find . -name "*.pcap" -o -name "*.pcapng" -o -name "*.cap"
```

Observacao: a versao atual do `sniff-it.py` le arquivos `.pcap`. Arquivos
`.pcapng` ainda nao sao suportados diretamente.

## Como gerar um arquivo PCAP

Voce pode gerar um arquivo `.pcap` usando uma ferramenta propria para captura,
como Wireshark, tcpdump ou tshark.

Exemplo com `tcpdump`:

```bash
sudo tcpdump -i any -w captura.pcap
```

Depois de capturar alguns pacotes, pare com `Ctrl+C`.

Em seguida, analise o arquivo sem `sudo`:

```bash
uv run sniff-it.py --pcap captura.pcap --log sniff-it.log
```

## Limitar quantidade de pacotes

Por padrao, o programa para depois de 10 pacotes:

```bash
uv run sniff-it.py --pcap captura.pcap
```

Para escolher outro limite:

```bash
uv run sniff-it.py --pcap captura.pcap --max-packets 50
```

Para processar todos os pacotes:

```bash
uv run sniff-it.py --pcap captura.pcap --max-packets 0
```

## Payload dos pacotes

Por seguranca e privacidade, o payload TCP nao e exibido por padrao. O programa
mostra apenas a quantidade de bytes.

Para mostrar o payload em hexadecimal:

```bash
uv run sniff-it.py --pcap captura.pcap --show-payload
```

Use essa opcao apenas em capturas de laboratorio ou em redes onde voce tem
permissao para analisar o conteudo.

## Captura ao vivo

Tambem existe modo de captura ao vivo:

```bash
uv run sniff-it.py --live
```

Porem, no Linux, sockets raw exigem privilegio especial. Um usuario comum nao
consegue abrir esse tipo de socket. Por isso, para estudar e testar o programa,
prefira o fluxo:

1. Capturar com ferramenta propria, como Wireshark ou tcpdump.
2. Salvar como `.pcap`.
3. Analisar com `sniff-it.py --pcap`.

## Comando de ajuda

Para ver todas as opcoes disponiveis:

```bash
uv run sniff-it.py --help
```

## Exemplos rapidos

Analisar uma captura:

```bash
uv run sniff-it.py --pcap captura.pcap
```

Analisar e salvar log:

```bash
uv run sniff-it.py --pcap captura.pcap --log sniff-it.log
```

Analisar 100 pacotes:

```bash
uv run sniff-it.py --pcap captura.pcap --max-packets 100
```

Analisar todos os pacotes e salvar log:

```bash
uv run sniff-it.py --pcap captura.pcap --max-packets 0 --log sniff-it.log
```
