####################################################################
#
#                 S-DES - Algoritmo de cifra de bloco
# 
#     Trabalho 1 da disciplina de Segurança Computacional - 2025.1
#
#####################################################################


# Geração de chaves subjacentes
def PermutacaoP10(chave):
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    chavePermutada = []

    for i in p10:
        chavePermutada.append(chave[i - 1]) 
    
    resultado = ''.join(chavePermutada)
    print(f'Chave P10: {resultado}')
    return resultado


# Deslocamento Circular
def deslocamentoCircular(chave, shift):
    left = chave[:5]
    right = chave[5:]

    # Deslocamento circular à esquerda 
    shiftedLeft = left[shift:] + left[:shift]
    shiftedRight = right[shift:] + right[:shift]

    print(f'Chave após deslocamento circular: {shiftedLeft} {shiftedRight}')
    return shiftedLeft + shiftedRight



def PermutacaoP8(chave):
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]
    chavePermutada = []

    for i in p8:
        chavePermutada.append(chave[i - 1]) 
    
    resultado = ''.join(chavePermutada)
    print(f'Chave P8: {resultado}')
    return resultado



# Permutação Inicial (IP)
def PermutacaoInicial(bloco):
    ip = [2, 6, 3, 1, 4, 8, 5, 7]
    blocoPermutado = []

    for i in ip:
        blocoPermutado.append(bloco[i - 1]) 
    
    resultado = ''.join(blocoPermutado)

    print(f'Permutação inicial: {resultado}')
    return resultado



# Expansão e Permutação (E/P)
def ExpansaoPermutacao(bits):
    ep = [4, 1, 2, 3, 2, 3, 4, 1]
    bitsPermutados = []

    for i in ep:
        bitsPermutados.append(bits[i - 1]) 
    
    resultado = ''.join(bitsPermutados)
    print(f'Expansão e Permutação: {resultado}')
    return resultado



# XOR bit a bit entre x e y
def XOR(x, y):
    listaXor = []  
    tamanho = len(x)

    for i in range(tamanho):  
        bit1 = int(x[i])  
        bit2 = int(y[i])  
        xor = bit1 ^ bit2
        listaXor.append(str(xor))

    resultado = ''.join(listaXor)
    print(f'XOR: {resultado}')
    return (resultado)


# S-Boxes
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


def SBoxes(bits):
    left, right = bits[:4], bits[4:]

    def CalcularSBox(bloco, sbox):
        
        linha = int(bloco[0] + bloco[3], 2)  # Bits 1 e 4 para linha
        coluna = int(bloco[1] + bloco[2], 2)  # Bits 2 e 3 para coluna
        
        return format(sbox[linha][coluna], '02b') 

    saidaS0 = CalcularSBox(left, S0)
    saidaS1 = CalcularSBox(right, S1)  
    print(f'S-Boxes: {saidaS0} {saidaS1}')

    return saidaS0 + saidaS1    



def PermutacaoP4(bits):
    p4 = [2, 4, 3, 1]
    bitsPermutados = []

    for i in p4:
        bitsPermutados.append(bits[i - 1]) 
    
    resultado = ''.join(bitsPermutados)
    print(f'Permutação P4: {resultado}')
    return resultado


# Divisão das metades do bloco de dados + Função Fk
def Fk(bits, subchave, rodada):
    left, right = bits[:4], bits[4:] 
    
    epBits = ExpansaoPermutacao(right)
    saidaXor = XOR(epBits, subchave)
    saidaSbox = SBoxes(saidaXor)
    saidaP4 = PermutacaoP4(saidaSbox)
    saidaFk = XOR(left, saidaP4)
    
    bloco = saidaFk + right
    print(f'{rodada}º rodada de Feistel: {bloco}')
    
    return bloco


def RodadasFeistel(bloco, K1, K2):
    # Primeira rodada com K1
    bloco1 = Fk(bloco, K1, 1)
    
    blocoInvertido = bloco1[4:] + bloco1[:4] 
    
    # Segunda rodada com K2
    bloco2 = Fk(blocoInvertido, K2, 2)
    
    return bloco2


# Permutação Final Inversa (IP⁻¹)
def PermutacaoFinal(bloco):
    ipInversa = [4, 1, 3, 5, 7, 2, 8, 6]
    blocoPermutado = []

    for i in ipInversa:
        blocoPermutado.append(bloco[i - 1]) 
    
    resultado = ''.join(blocoPermutado)
    print(f'Permutação final Inversa: {resultado}')
    return resultado


def GerarSubchaves(chaveInicial):
    
    novaChave = PermutacaoP10(chaveInicial)
    novaChave = deslocamentoCircular(novaChave, 1)
    
    k1 = PermutacaoP8(novaChave)
    print(f'Chave K1: {k1}')
    
    # Deslocamento Circular é aplicado novamente, deslocando 2 bits
    novaChave = deslocamentoCircular(novaChave, 2) 
    
    k2 = PermutacaoP8(novaChave)
    print(f'Chave K2: {k2}')

    return k1, k2


def Decriptar(blocoCifrado, chave10): 
    print("Saídas intermediárias:") 
    
    # Gerar subchaves
    k1, k2 = GerarSubchaves(chave10)
    
    # Permutação inicial no bloco cifrado
    ip = PermutacaoInicial(blocoCifrado)
    
    # Rodadas de Feistel na ordem invertida: primeiro K2, depois K1
    # Primeira rodada com K2
    bloco1 = Fk(ip, k2, 1)
    blocoInvertido = bloco1[4:] + bloco1[:4]
    
    # Segunda rodada com K1
    bloco2 = Fk(blocoInvertido, k1, 2)
    
    # Permutação final inversa
    blocosDecriptado = PermutacaoFinal(bloco2)
    
    print(f'\nBloco Decriptado Binário: {blocosDecriptado}')
    print(f'Bloco Decriptado Hexadecimal: {int(blocosDecriptado, 2):02x}')
    
    return blocosDecriptado


###########################
#    Modos de Operação    #
###########################

# Modo ECB
def ECB_encriptar(blocos, chave10):
    k1, k2 = GerarSubchaves(chave10)
    blocosCifrado = []

    for bloco in blocos:
        ip = PermutacaoInicial(bloco)
        blocoFeistel = RodadasFeistel(ip, k1, k2)
        cifra = PermutacaoFinal(blocoFeistel)
        blocosCifrado.append(cifra)
    
    return blocosCifrado


def ECB_decriptar(blocosCifrado, chave10):
    k1, k2 = GerarSubchaves(chave10)
    blocosDecriptado = []

    for cifra in blocosCifrado:
        ip = PermutacaoInicial(cifra)
        bloco1 = Fk(ip, k2, 1)
        blocoInvertido = bloco1[4:] + bloco1[:4]
        bloco2 = Fk(blocoInvertido, k1, 2)
        texto = PermutacaoFinal(bloco2)
        blocosDecriptado.append(texto)
    
    return blocosDecriptado


# Modo CBC
def CBC_encriptar(blocos, chave10, IV):
    k1, k2 = GerarSubchaves(chave10)
    blocosCifrado = []
    anterior = IV

    for bloco in blocos:
        entrada = XOR(bloco, anterior)
        ip = PermutacaoInicial(entrada)
        blocoFeistel = RodadasFeistel(ip, k1, k2)
        cifra = PermutacaoFinal(blocoFeistel)
        blocosCifrado.append(cifra)
        anterior = cifra
    
    return blocosCifrado


def CBC_decriptar(blocosCifrado, chave10, IV):
    k1, k2 = GerarSubchaves(chave10)
    blocosDecriptado = []
    anterior = IV

    for cifra in blocosCifrado:
        ip = PermutacaoInicial(cifra)
        bloco1 = Fk(ip, k2, 1)
        blocoInvertido = bloco1[4:] + bloco1[:4]
        bloco2 = Fk(blocoInvertido, k1, 2)
        texto = PermutacaoFinal(bloco2)
        bloco = XOR(texto, anterior)
        blocosDecriptado.append(bloco)
        anterior = cifra
    
    return blocosDecriptado


####################
#      Main        #
####################

if __name__ == "__main__":

    IV = "01010101"
    mensagem = ["11010111", "01101100", "10111010", "11110000"]
    
    chave10 = "1010000010"
    bloco8 = "11010111"
    
    # Encriptação
    print("----------------------------------------------")
    print(f'Algoritmo S-DES: Encriptação \nChave: {chave10} \nBloco de Dados: {bloco8}\n')
    print("Saídas intermediárias:")
    
    k1, k2 = GerarSubchaves(chave10)
    ip = PermutacaoInicial(bloco8)
    blocoFeistel = RodadasFeistel(ip, k1, k2)
    blocoCifrado = PermutacaoFinal(blocoFeistel)
    
    print(f'\nBloco Cifrado Binário: {blocoCifrado}')
    print(f'Bloco Cifrado Hexadecimal: {int(blocoCifrado, 2):02x}\n')

    # Decriptação
    print("----------------------------------------------")
    print(f'Algoritmo S-DES: Decriptação \nChave: {chave10} \nBloco de Dados: {bloco8}\n')
    Decriptar(blocoCifrado, chave10)

"""    
    # Modo de Operação ECB
    print("----------------------------------------------")
    print(f'Algoritmo S-DES: Modo de Operação ECB (Encriptacao) \nChave: {chave10} \nMensagem: {mensagem}\n')
    print("Saídas intermediárias:")
    
    encriptadoEcb = ECB_encriptar(mensagem, chave10)
    print(f'Blocos Cifrados: {encriptadoEcb}')
    print(f'Blocos Cifrados Hexadecimal: {[format(int(b, 2), "02x") for b in encriptadoEcb]}')
    
    print("----------------------------------------------")
    print(f'Algoritmo S-DES: Modo de Operação ECB (Decriptacao) \nChave: {chave10} \nMensagem: {mensagem}\n')
    print("Saídas intermediárias:")
    
    decriptadoEcb = ECB_decriptar(encriptadoEcb, chave10)
    print(f'Blocos Decriptados: {decriptadoEcb}')
    print(f'Blocos Decriptados Hexadecimal: {[format(int(b, 2), "02x") for b in decriptadoEcb]}')

    # Modo de Operação CBC
    print("----------------------------------------------")
    print(f'Algoritmo S-DES: Modo de Operação CBC (Encriptaçao) \nChave: {chave10} \nMensagem: {mensagem}\n')
    print("Saídas intermediárias:")
    
    encriptadoCbc = CBC_encriptar(mensagem, chave10, IV)
    print(f'Blocos Cifrados: {encriptadoCbc}')
    print(f'Blocos Cifrados Hexadecimal: {[format(int(b, 2), "02x") for b in encriptadoCbc]}')
    
    print("----------------------------------------------")
    print(f'Algoritmo S-DES: Modo de Operação CBC (Decriptaçao)\nChave: {chave10} \nMensagem: {mensagem}\n')
    print("Saídas intermediárias:")
    
    decriptadoCbc = CBC_decriptar(encriptadoCbc, chave10, IV)
    print(f'Blocos Decriptados: {decriptadoCbc}')
    print(f'Blocos Decriptados Hexadecimal: {[format(int(b, 2), "02x") for b in decriptadoCbc]}')
"""