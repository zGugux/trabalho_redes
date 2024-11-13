import tkinter as tk
import os
from tkinter import messagebox
import json
import socket
import hashlib
import base64
from cryptography.fernet import Fernet

# Variáveis globais
User = ""  # Armazena o nome do usuário
Pass = ""  # Armazena a senha do usuário
IP = ""    # Armazena o endereço IP do servidor
PORTA = 0  # Armazena a porta do servidor
json_text = None
aux_destinatario = None
flag = True
after_id = None

# Gera uma chave válida de 32 bytes a partir da string 'qweasd' e converte para Base64
KEY = base64.urlsafe_b64encode(hashlib.sha256(b'qweasd').digest())
cipher_suite = Fernet(KEY)  # Cria o objeto para criptografia e descriptografia com a chave gerada

def recv_full_data(sock):
    """Função auxiliar para receber o comprimento da mensagem seguido da mensagem completa."""
    try:
        # Recebe o comprimento da mensagem
        message_length = int(sock.recv(10).decode().strip())
        data = b""  # Inicia a variável que vai armazenar os dados recebidos
        while len(data) < message_length:
            # Recebe os dados em partes até atingir o comprimento total
            data += sock.recv(1024)
        return data  # Retorna os dados recebidos
    except ValueError:
        # Em caso de erro ao processar os dados, retorna uma mensagem de erro
        return b'{"erro": "Erro ao receber dados"}'

def enviar_dados_criptografados(data, socket):
    """Criptografa e envia o JSON via socket."""
    encrypted_data = cipher_suite.encrypt(data.encode())  # Criptografa os dados
    encrypted_length = f"{len(encrypted_data):<10}"  # Formata o comprimento dos dados criptografados
    print("menssagem encriptografada enviada", encrypted_data)  # Debug: Exibe a mensagem criptografada
    # Envia o comprimento seguido dos dados criptografados
    socket.sendall(encrypted_length.encode() + encrypted_data)

def envioServer():
    """Função para enviar dados ao servidor e tratar a resposta."""
    global User, Pass, IP, PORTA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Conecta ao servidor usando IP e porta definidos
            s.connect((IP, PORTA))
            # Cria o JSON com as credenciais do usuário
            data = json.dumps({"flag": 0, "User": User, "Pass": Pass})
            print("Enviando JSON criptografado para o servidor:", data)  # Debug
            # Envia os dados criptografados para o servidor
            enviar_dados_criptografados(data, s)
            
            # Recebe a resposta completa do servidor e descriptografa
            resposta = recv_full_data(s)
            print("Resposta encriptografada Recebida", resposta)  # Debug
            resposta = cipher_suite.decrypt(resposta).decode()  # Descriptografa a resSposta
            print("Resposta recebida do servidor:", resposta)  # Debug
            resultado = json.loads(resposta)  # Converte a resposta em JSON
            
            # Processa o resultado conforme o código de resposta
            if resultado == 0:
                messagebox.showerror("Erro", "A senha digitada está errada")
            elif resultado == 1:
                messagebox.showinfo("Informação", "Não foi possível encontrar um usuário")
            elif isinstance(resultado, dict):  # Se o resultado for um JSON, processa os dados
                salvar_json(User, resultado)  # Salva os dados em um arquivo
                abrir_selecionar_destinatario(resultado)
                #exibir_dados(resultado)  # Exibe os dados na interfaceS
            
        except json.JSONDecodeError as e:
            print("Erro ao decodificar JSON recebido:", e)
            messagebox.showerror("Erro de Conexão", f"Erro ao decodificar resposta JSON: {e}")
        except Exception as e:
            print("Erro ao conectar ou receber dados do servidor:", e)  # Exibe erro de conexão
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")

def criarUsuario(nickname_entry, password_entry, ip_entry, porta_entry):
    """Função para criar um novo usuário."""
    global IP, PORTA
    # Obtém os valores inseridos na interface
    User = nickname_entry.get().strip()
    Pass = password_entry.get().strip()
    IP = ip_entry.get().strip()
    PORTA = int(porta_entry.get().strip())
    
    # Verifica se os campos obrigatórios foram preenchidos
    if not User or not Pass:
        messagebox.showerror("Erro", "User e senha são obrigatórios.")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((IP, PORTA))  # Conecta ao servidor
            # Cria o JSON com as credenciais do novo usuário
            data = json.dumps({"flag": 3, "User": User, "Pass": Pass})
            print("Enviando JSON para criação de usuário criptografado:", data)  # Debug
            # Envia os dados criptografados para o servidor
            enviar_dados_criptografados(data, s)
            
            # Recebe a resposta do servidor e descriptografa
            resposta = recv_full_data(s)
            resposta = cipher_suite.decrypt(resposta).decode()  # Descriptografa a resposta
            print("Resposta recebida do servidor:", resposta)  # Debug
            resultado = json.loads(resposta)  # Converte a resposta em JSON
            
            # Processa o resultado conforme o código de resposta
            if resultado == 0:
                messagebox.showerror("Erro", "Usuário inválido")
            elif resultado == 1:
                messagebox.showinfo("Sucesso", "Usuário criado com sucesso!")
            elif resultado == 3:
                messagebox.showinfo("Erro", "Usuário já existe")
        
        except json.JSONDecodeError as e:
            print("Erro ao decodificar JSON recebido:", e)
            messagebox.showerror("Erro de Conexão", f"Erro ao decodificar resposta JSON: {e}")
        except Exception as e:
            print("Erro ao conectar ou receber dados do servidor:", e)
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")


def salvar_json(nome_arquivo, dados_json):
    """Salva o JSON recebido no diretório raiz com o nome do usuário."""
    with open(f"{nome_arquivo}.json", "w") as file:
        json.dump(dados_json, file)  # Salva os dados JSON no arquivo





# Função intermediária para abrir a seleção de destinatário após autenticação.
def abrir_selecionar_destinatario(resultado):
    """Abrir a seleção de destinatário após autenticação, verificando o status da flag."""
    global flag, aux_destinatario  # Certifique-se de que flag esteja declarada como global se usada em outros lugares
    if flag:
        selecionar_destinatario(resultado, "id")
        flag = False  # Corrigido o operador de atribuição (era '==' e agora é '=')
    else:
        exibir_dados(resultado, aux_destinatario)


# Função intermediária que redefine flag, cancela o after loop e chama envioServer
def tratar_novo_email():
    """Redefine flag, para o loop de atualização e inicia o processo de envio do servidor."""
    global flag, after_id
    flag = True
    if after_id is not None:  # Verifica se existe uma atualização em andamento
        root.after_cancel(after_id)  # Cancela o loop de atualização
        after_id = None  # Redefine a variável para evitar chamadas múltiplas
    envioServer()



def selecionar_destinatario(dados_json, pasta_usuarios):
    """Função para exibir a lista de destinatários e permitir a seleção para acessar a conversa."""
    
    # Verifica se a pasta de usuários existe
    if not os.path.exists(pasta_usuarios):
        messagebox.showerror("Erro", "A pasta de usuários não existe.")
        return
    
    # Limpa os widgets existentes na interface para atualizar os dados
    for widget in root.winfo_children():
        widget.destroy()

    # Nova janela
    janela_destinatario = tk.Toplevel(root)
    janela_destinatario.title("Selecionar Destinatário")
    
    # Lista todos os arquivos JSON na pasta e extrai o nome de usuário a partir dos arquivos
    destinatarios = []
    for arquivo in os.listdir(pasta_usuarios):
        if arquivo.endswith(".json"):  # Verifica se é um arquivo JSON
            nome_usuario = arquivo.replace(".json", "")
            destinatarios.append(nome_usuario)
    
    # Adiciona a opção de iniciar uma nova conversa
    destinatarios.append("Novo Usuário")
    
    # Exibe os destinatários em botões
    for destinatario in destinatarios:
        tk.Button(janela_destinatario, text=destinatario, 
                  command=lambda d=destinatario: acessar_conversa(d, dados_json) if d != "Novo Usuário" else iniciar_nova_conversa(dados_json, pasta_usuarios, janela_destinatario), 
                  font=("Arial", 12), bg="#2196F3", fg="white").pack(pady=5)
    
    # Botão para fechar a janela e retornar à interface principal
    def fechar_e_retornar():
        janela_destinatario.destroy()
        exibir_interface_principal()  # Retorna para a interface principal
    
    tk.Button(janela_destinatario, text="Logout", command=fechar_e_retornar, font=("Arial", 12), bg="#f44336", fg="white").pack(pady=10)



def iniciar_nova_conversa(dados_json, pasta_usuarios, janela_destinatario):
    """Função para iniciar uma nova conversa com um usuário existente."""

    # Nova janela para iniciar a conversa
    janela_novo_usuario = tk.Toplevel(root)
    janela_novo_usuario.title("Iniciar Nova Conversa")
    
    tk.Label(janela_novo_usuario, text="Digite o nome do usuário com o qual deseja conversar:", font=("Arial", 12)).pack(pady=10)
    
    # Caixa de entrada para o nome do usuário
    nome_usuario_entry = tk.Entry(janela_novo_usuario, font=("Arial", 12))
    nome_usuario_entry.pack(pady=10)
    
    # Função para iniciar a conversa com o usuário
    def confirmar_usuario_existente():
        nome_usuario = nome_usuario_entry.get().strip()
        if nome_usuario:
            # Verifica se o arquivo JSON do usuário já existe na pasta de usuários
            caminho_arquivo = os.path.join(pasta_usuarios, nome_usuario + ".json")
            if os.path.exists(caminho_arquivo):
                # Se o usuário existe, inicia a conversa
                acessar_conversa(nome_usuario, dados_json)
            else:
                # Se o usuário não existir, exibe uma mensagem de erro, fecha a janela e traz a lista de usuários para frente
                messagebox.showerror("Erro", f"O usuário {nome_usuario} não existe. Não é possível iniciar a conversa.")
                janela_novo_usuario.destroy()
                janela_destinatario.lift()  # Traz a janela de lista de usuários para frente
        else:
            messagebox.showerror("Erro", "Por favor, digite um nome de usuário válido.")
    
    # Botão para confirmar o nome do usuário e iniciar a conversa
    tk.Button(janela_novo_usuario, text="Iniciar Conversa", command=confirmar_usuario_existente, font=("Arial", 12), bg="#4CAF50", fg="white").pack(pady=10)
    
    # Botão para cancelar a criação de uma nova conversa
    tk.Button(janela_novo_usuario, text="Cancelar", command=janela_novo_usuario.destroy, font=("Arial", 12), bg="#f44336", fg="white").pack(pady=10)


def acessar_conversa(destinatario, dados_json):
    """Função para abrir a conversa do destinatário selecionado sem fechar a lista de usuários."""
    global aux_destinatario
    aux_destinatario = destinatario  # Armazena o destinatário selecionado globalmente
    
    # Verifica se a chave "Email" está presente em dados_json; caso contrário, cria-a como uma lista vazia
    if "Email" not in dados_json:
        dados_json["Email"] = []  # Cria uma lista vazia para armazenar as mensagens
    
    # Filtra os emails do destinatário selecionado
    mensagens = [email["Mensagem"] for email in dados_json["Email"] if email["id"] == destinatario]
    
    # Cria uma nova janela para exibir a conversa, mantendo a janela principal aberta
    janela_conversa = tk.Toplevel(root)
    janela_conversa.title(f"Conversa com {destinatario}")
    
    # Exibe as mensagens
    conversa_text = tk.Text(janela_conversa, height=15, width=50, font=("Courier", 10), bg="#f0f0f0")
    for mensagem in mensagens:
        conversa_text.insert(tk.END, f"{destinatario}: {mensagem}\n")
    conversa_text.config(state="disabled")  # Desabilita a edição
    conversa_text.pack(pady=10)
    
    # Botão para fechar a janela de conversa
    tk.Button(janela_conversa, text="Fechar", command=janela_conversa.destroy, font=("Arial", 12), bg="#f44336", fg="white").pack(pady=10)

    # Atualiza a lista de emails na janela principal sem fechá-la
    exibir_dados(dados_json, destinatario)



# Função para exibir os dados do servidor na interface
def exibir_dados(dados_json, destinatario):
    """Atualiza a interface para mostrar os emails filtrados por destinatário e exibe o nome do usuário logado."""
    global json_text, email_entry, after_id
    # Limpa os widgets existentes na interface para atualizar os dados
    for widget in root.winfo_children():
        widget.destroy()

    # Frame principal para organizar os elementos na interface
    main_frame = tk.Frame(root)
    main_frame.pack(expand=True, fill="both")

    # Exibe o nome do usuário logado no topo da interface
    tk.Label(main_frame, text=f"Usuário: {User}", font=("Arial", 16, "bold")).pack(pady=10)
    tk.Label(main_frame, text=f"Conversa com: {destinatario}", font=("Arial", 16, "bold")).pack(pady=10)

    # Caixa de texto para exibir emails recebidos, com formato e estilo personalizados
    json_text = tk.Text(main_frame, height=15, width=50, font=("Courier", 10), bg="#f0f0f0")
    
    # Filtra e exibe apenas as mensagens do destinatário selecionado
    if "Email" in dados_json:
        for email in dados_json["Email"]:
            # Verifica se o ID do remetente coincide com o destinatário selecionado
            if email.get("id") == destinatario:
                remetente = email.get("id", "Desconhecido")  # Recupera o remetente
                mensagem = email.get("Mensagem", "")  # Recupera a mensagem
                # Exibe o remetente e a mensagem na caixa de texto
                json_text.insert(tk.END, f"Remetente: {remetente}\n")
                json_text.insert(tk.END, f"Mensagem: {mensagem}\n")
                json_text.insert(tk.END, "-" * 30 + "\n\n")

    json_text.yview(tk.END)
    json_text.config(state="disabled")  # Desabilita a edição do texto
    json_text.pack(pady=10)

    # Campo para conteúdo do email
    tk.Label(main_frame, text="Conteúdo do Email", font=("Arial", 12)).pack(pady=5)
    global email_entry
    email_entry = tk.Text(main_frame, height=5, width=50, font=("Courier", 10))
    email_entry.pack(pady=5)

    # Botões de envio e atualização
    btn_enviar = tk.Button(main_frame, text="Enviar Email", command=lambda: send_email(destinatario), bg="#4CAF50", fg="white")
    btn_enviar.pack(pady=10)

    btn_atualizar = tk.Button(main_frame, text="Atualizar Email", command=envioServer, bg="#4CAF50", fg="white")
    btn_atualizar.pack(pady=5)

    

    btn_new_email = tk.Button(main_frame, text="Novo Email", command=tratar_novo_email, bg="red", fg="white")
    btn_new_email.place(x=10, y=10)  # Ajuste leve para espaçamento do canto superior esquerdo

    after_id = root.after(7000, envioServer)
    
    # Atualiza a interface para garantir que todos os elementos sejam exibidos corretamente
    root.update_idletasks()


def send_email(destinatario):
    """Função chamada pelo botão 'Enviar Email' para enviar o conteúdo do email direto da interface principal."""
    global json_text
    # Recupera o conteúdo do email inserido na interface
    conteudo_email = email_entry.get("1.0", tk.END).strip()

    # Verifica se o conteúdo do email não está vazio
    if not conteudo_email:
        json_text.config(state="normal")
        json_text.insert(tk.END, "Erro: O conteúdo do email não pode estar vazio.\n")
        json_text.config(state="disabled")
        return

    # Conexão com o servidor para enviar o email
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Conecta ao servidor com IP e porta fornecidos
            s.connect((IP, PORTA))
            # Cria o JSON com os dados do email
            data = json.dumps({
                "flag": 1,
                "User": User,
                "destinatario": destinatario,
                "conteudo_email": conteudo_email
            })
            # Envia os dados criptografados para o servidor
            enviar_dados_criptografados(data, s)
            # Recebe e descriptografa a resposta do servidor
            resposta = recv_full_data(s)
            resposta = cipher_suite.decrypt(resposta).decode()
            resultado = json.loads(resposta)

            # Exibe mensagens de erro ou sucesso baseado no resultado do servidor diretamente na interface
            json_text.config(state="normal")
            if resultado == 0:
                json_text.insert(tk.END, "Erro: Usuário do destinatário não encontrado.\n")
            elif resultado == 1:
                json_text.insert(tk.END, "Sucesso: Email enviado com sucesso!\n")
            json_text.config(state="disabled")

            # Limpar o campo de conteúdo do email após o envio
            email_entry.delete("1.0", tk.END)
        
        except Exception as e:
            # Exibe erro caso não consiga conectar ao servidor
            json_text.config(state="normal")
            json_text.insert(tk.END, f"Erro de Conexão: Não foi possível conectar ao servidor: {e}\n")
            json_text.config(state="disabled")



def enviar(nickname_entry, password_entry, ip_entry, porta_entry):
    """Função de envio quando o botão 'Enviar' é clicado, realiza login e comunicação com o servidor."""
    global User, Pass, IP, PORTA
    # Recupera os dados inseridos para login e conexão
    User = nickname_entry.get()
    Pass = password_entry.get()
    IP = ip_entry.get()
    PORTA = int(porta_entry.get())
    # Chama a função de envio ao servidor para autenticar o usuário
    envioServer()


# Função para adicionar placeholder no campo de entrada
def add_placeholder(entry, placeholder_text):
    entry.insert(0, placeholder_text)
    entry.config(fg="grey")
    
    def on_focus_in(event):
        if entry.get() == placeholder_text:
            entry.delete(0, tk.END)
            entry.config(fg="black")
    
    def on_focus_out(event):
        if entry.get() == "":
            entry.insert(0, placeholder_text)
            entry.config(fg="grey")
    
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)


def exibir_interface_principal():
    """Função para exibir a interface principal de login."""
    for widget in root.winfo_children():
        widget.destroy()
    
    root.title("Login")  
    root.geometry("500x700")  

    frame = tk.Frame(root)
    frame.pack(pady=20)  

    tk.Label(frame, text="Login", font=("Arial", 12)).pack(pady=5)
    nickname_entry = tk.Entry(frame, font=("Arial", 12))
    nickname_entry.pack(pady=5)

    tk.Label(frame, text="Senha", font=("Arial", 12)).pack(pady=5)
    password_entry = tk.Entry(frame, show="*", font=("Arial", 12))
    password_entry.pack(pady=5)

    tk.Label(frame, text="IP", font=("Arial", 12)).pack(pady=5)
    ip_entry = tk.Entry(frame, font=("Arial", 12))
    ip_entry.pack(pady=5)
    add_placeholder(ip_entry, "127.0.0.1")

    tk.Label(frame, text="Porta", font=("Arial", 12)).pack(pady=5)
    porta_entry = tk.Entry(frame, font=("Arial", 12))
    porta_entry.pack(pady=5)
    add_placeholder(porta_entry, "7555") 

    # Passe as entradas como argumentos ao chamar a função `enviar`
    tk.Button(frame, text="Login", command=lambda: enviar(nickname_entry, password_entry, ip_entry, porta_entry), bg="#4CAF50", fg="white").pack(pady=10)
    tk.Button(frame, text="Cadastrar", command=lambda: criarUsuario(nickname_entry, password_entry, ip_entry, porta_entry), bg="#2196F3", fg="white").pack(pady=5)



root = tk.Tk()
exibir_interface_principal()  # Chama a função para mostrar a interface principal
root.mainloop()