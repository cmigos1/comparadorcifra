# Comparador de Desempenho Criptográfico (AES vs. DES)

Este projeto consiste num script Python (`main.py`) que mede e compara o desempenho dos algoritmos criptográficos DES (Data Encryption Standard) e AES (Advanced Encryption Standard) com chaves de 128 e 256 bits.

## Funcionalidades

O script realiza as seguintes tarefas:

- Gera dados aleatórios simulando ficheiros de 1KB, 1MB e 10MB.
- Cifra e Decifra os dados usando DES-CBC, AES-128-CBC e AES-256-CBC.
- Implementa padding PKCS7 para garantir que os dados se alinhem com o tamanho do bloco.
- Usa um IV (Vetor de Inicialização) aleatório para cada operação de cifragem, garantindo segurança (modo CBC).
- Mede o tempo de processamento (cifrar e decifrar) para cada combinação de algoritmo e tamanho de ficheiro.
- Calcula o throughput (débito) em Megabytes por segundo (MB/s).
- Executa cada teste 10 vezes e calcula a média para obter resultados mais estáveis.
- Gera um relatório em formato de tabela no console.
- Plota gráficos de desempenho (Throughput vs. Tamanho do Ficheiro) usando matplotlib e salva-os como `comparacao_throughput.png`.

## Algoritmos Testados

- **DES-CBC**: (Block size: 8 bytes, Key size: 8 bytes)
- **AES-128-CBC**: (Block size: 16 bytes, Key size: 16 bytes)
- **AES-256-CBC**: (Block size: 16 bytes, Key size: 32 bytes)

## Requisitos

- Python 3.x
- pycryptodome
- pandas
- matplotlib

## Instalação

Pode instalar todas as dependências necessárias usando o pip:

```bash
pip install pycryptodome pandas matplotlib
```

Ou usando o ficheiro de requisitos:

```bash
pip install -r requirements.txt
```

## Como Executar

Basta executar o script Python diretamente do seu terminal:

```bash
python main.py
```

## Saída Esperada

Ao executar o script, verá:

- **No terminal**: Mensagens de progresso à medida que os testes são executados.
- **No terminal**: Uma tabela de resumo completa, formatada pelo pandas, mostrando os tempos e o throughput para todos os testes.
- **Na pasta do projeto**: Um ficheiro de imagem chamado `comparacao_throughput.png` será gerado, contendo os gráficos de desempenho.