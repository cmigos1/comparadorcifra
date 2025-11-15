import os
import time
import pandas as pd
import matplotlib.pyplot as plt
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# --- Configurações do Teste ---

# Tamanhos dos arquivos em bytes
FILE_SIZES = {
    '1KB': 1 * 1024,
    '1MB': 1 * 1024 * 1024,
    '10MB': 10 * 1024 * 1024
}
# Número de execuções para tirar a média
NUM_RUNS = 10

# --- Funções de Cifração e Decifração ---

def encrypt(data, key, cipher_mode, block_size):
    # 1. Gerar IV aleatório
    iv = get_random_bytes(block_size)
    
    # 2. Criar o objeto de cifra
    if len(key) == 8: # DES
        cipher = DES.new(key, cipher_mode, iv=iv)
    else: # AES
        cipher = AES.new(key, cipher_mode, iv=iv)
        
    # 3. Aplicar padding PKCS7
    padded_data = pad(data, block_size)
    
    # 4. Cifrar
    ciphertext = cipher.encrypt(padded_data)
    
    # Retorna o IV + texto cifrado (prática comum)
    return iv + ciphertext

def decrypt(encrypted_data, key, cipher_mode, block_size):
    # 1. Extrair IV e texto cifrado
    iv = encrypted_data[:block_size]
    ciphertext = encrypted_data[block_size:]
    
    # 2. Criar o objeto de cifra
    if len(key) == 8: # DES
        cipher = DES.new(key, cipher_mode, iv=iv)
    else: # AES
        cipher = AES.new(key, cipher_mode, iv=iv)
        
    # 3. Decifrar
    padded_data = cipher.decrypt(ciphertext)
    
    # 4. Remover padding PKCS7
    try:
        data = unpad(padded_data, block_size)
    except ValueError as e:
        print(f"Erro ao remover padding: {e}")
        return None
        
    return data

# --- Função de Medição de Desempenho ---

def measure_performance(algo_name, key, mode, block_size, data):

    encrypt_times = []
    decrypt_times = []
    data_size_mb = len(data) / (1024 * 1024) # Tamanho em Megabytes

    print(f"  Executando {algo_name} (Média de {NUM_RUNS} execuções)...")

    for _ in range(NUM_RUNS):
        # Medir Cifração
        start_enc = time.perf_counter()
        encrypted = encrypt(data, key, mode, block_size)
        end_enc = time.perf_counter()
        encrypt_times.append(end_enc - start_enc)
        
        # Medir Decifração
        start_dec = time.perf_counter()
        decrypted = decrypt(encrypted, key, mode, block_size)
        end_dec = time.perf_counter()
        decrypt_times.append(end_dec - start_dec)
        
        # Verificação de integridade
        assert data == decrypted, "Erro: Dados decifrados não correspondem aos originais!"

    # Calcular médias
    avg_enc_time = sum(encrypt_times) / NUM_RUNS
    avg_dec_time = sum(decrypt_times) / NUM_RUNS
    
    # Calcular throughput (MB/s)
    # Evitar divisão por zero se o tempo for muito pequeno
    enc_throughput = data_size_mb / avg_enc_time if avg_enc_time > 0 else 0
    dec_throughput = data_size_mb / avg_dec_time if avg_dec_time > 0 else 0
    
    return {
        'Algorithm': algo_name,
        'File Size (MB)': data_size_mb,
        'File Size Label': f"{data_size_mb:.2f} MB" if data_size_mb >= 1 else f"{data_size_mb*1024:.0f} KB",
        'Encrypt Time (s)': avg_enc_time,
        'Decrypt Time (s)': avg_dec_time,
        'Encrypt Throughput (MB/s)': enc_throughput,
        'Decrypt Throughput (MB/s)': dec_throughput
    }

# --- Execução Principal ---

def main():
    print("Iniciando Comparador de Desempenho Criptográfico...")
    
    # Definir os algoritmos, chaves e modos
    algorithms = {
        'DES-CBC': {
            'key': get_random_bytes(8), # DES usa 64 bits (8 bytes), mas 56 são efetivos
            'mode': DES.MODE_CBC,
            'block_size': DES.block_size
        },
        'AES-128-CBC': {
            'key': get_random_bytes(16), # 16 bytes = 128 bits
            'mode': AES.MODE_CBC,
            'block_size': AES.block_size
        },
        'AES-256-CBC': {
            'key': get_random_bytes(32), # 32 bytes = 256 bits
            'mode': AES.MODE_CBC,
            'block_size': AES.block_size
        }
    }
    
    results = []
    
    # Iterar sobre os tamanhos de arquivo
    for size_label, size_bytes in FILE_SIZES.items():
        print(f"\n--- Testando com Tamanho de Arquivo: {size_label} ({size_bytes} bytes) ---")
        
        # Gerar dados aleatórios (simulando um arquivo)
        data = get_random_bytes(size_bytes)
        
        # Iterar sobre os algoritmos
        for algo_name, params in algorithms.items():
            result = measure_performance(
                algo_name, 
                params['key'], 
                params['mode'], 
                params['block_size'], 
                data
            )
            results.append(result)

    # --- Geração de Relatório (Tabela) ---
    df = pd.DataFrame(results)
    
    # Organizar colunas para o relatório
    report_df = df.pivot(index='File Size Label', columns='Algorithm', values=[
        'Encrypt Time (s)', 
        'Decrypt Time (s)', 
        'Encrypt Throughput (MB/s)', 
        'Decrypt Throughput (MB/s)'
    ])
    
    # Criar uma ordem customizada para os tamanhos de arquivo
    size_order = ['1 KB', '1.00 MB', '10.00 MB']
    # Reordenar para melhor legibilidade usando a ordem dos labels reais
    report_df = report_df.reindex(size_order, axis=0)

    print("\n\n--- Relatório Comparativo (Média de 10 Execuções) ---")
    print(report_df.to_string(float_format="%.4f"))

    # --- Geração de Gráficos (Matplotlib) ---
    print("\nGerando gráficos de desempenho...")

    # Usar 'File Size Label' para os ticks do eixo X
    size_labels = [r['File Size Label'] for r in results if r['Algorithm'] == 'DES-CBC']
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 7), sharex=True)
    fig.suptitle('Comparação de Desempenho Criptográfico (Throughput)', fontsize=16)

    # Agrupar por algoritmo para plotar linhas
    for algo_name, group in df.groupby('Algorithm'):
        # Ordenar por tamanho de arquivo para garantir a ordem correta no gráfico
        group_sorted = group.sort_values(by='File Size (MB)')
        
        # Gráfico de Throughput de Cifração
        ax1.plot(
            size_labels, 
            group_sorted['Encrypt Throughput (MB/s)'], 
            marker='o', 
            linestyle='--',
            label=algo_name
        )
        
        # Gráfico de Throughput de Decifração
        ax2.plot(
            size_labels, 
            group_sorted['Decrypt Throughput (MB/s)'], 
            marker='s',
            label=algo_name
        )

    ax1.set_title('Throughput de Cifração')
    ax1.set_ylabel('Throughput (MB/s)')
    ax1.set_xlabel('Tamanho do Arquivo')
    ax1.legend()
    ax1.grid(True, linestyle=':')

    ax2.set_title('Throughput de Decifração')
    ax2.set_ylabel('Throughput (MB/s)')
    ax2.set_xlabel('Tamanho do Arquivo')
    ax2.legend()
    ax2.grid(True, linestyle=':')

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig("comparacao_throughput.png")
    print("Gráfico 'comparacao_throughput.png' salvo.")
    plt.close()

if __name__ == "__main__":
    main()