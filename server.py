# coding: utf-8

import os
import sqlite3
from flask import Flask
from flask import redirect, url_for
from flask import request
from flask import send_from_directory
from flask import session
from flaskext.mail import Mail, Message
from jinja2 import Environment
from jinja2 import PackageLoader
import crypt, hashlib
import requests
import sys

#Tratar o erro de codificação que deu aqui em casa: Wagner
reload(sys)
sys.setdefaultencoding("utf-8")

_SALT = "$6$RY+-S?u4=4g"
_SALT1 = 'm;4slF=Y6]Afb/.p9Xd7iO8(V0yU~R*'
_ARQUIVO_BANCO_ = './banco.sqlite'

#Constantes utilizadas para fazer a busca pelo recaptcha.
RECAPTCHA_SITE_KEY = '6LeJFQsUAAAAAGvSk-rw5k_uepb7MwTPy4s0bhax'
RECAPTCHA_SECRET_KEY = '6LeJFQsUAAAAADTCToGqab0xmbFOVyAkFvIWSNab'
URL_RECAPTCHA = "https://www.google.com/recaptcha/api/siteverify"

#Constantes utilizadas para Envio de Emails.
EMAIL_SENDER = "meusite.labredes@gmail.com"
TEMPLATE_TEXTO = """
    Seja Bem-Vindo ao Meu Site\n Para validar seu cadastro favor clicar no link abaixo.\n\n\t\t http://localhost:5000/validar/{0}\n\n\n
"""


app = Flask(__name__, static_url_path='/static')
app.config.from_object(__name__)
mail=Mail(app)

app.config.update(
	DEBUG=True,
	#EMAIL SETTINGS
	MAIL_SERVER='smtp.gmail.com',
	MAIL_PORT=465,
	MAIL_USE_SSL=True,
	MAIL_USERNAME = EMAIL_SENDER,
	MAIL_PASSWORD = 'labredesmeusite'
	)

mail=Mail(app)
env = Environment(loader=PackageLoader(__name__, 'templates'))

# Checa se o banco de dados já foi criado
if not os.path.isfile(_ARQUIVO_BANCO_):
    con = sqlite3.connect(_ARQUIVO_BANCO_)
    cursor = con.cursor()
    cursor.execute('''
        CREATE TABLE usuario (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            senha TEXT NOT NULL,
            valido BOOLEAN NOT NULL,
            acesso TEXT NOT NULL
        );
    ''')
    con.close()

def sqlite_cadastra_usuario(email, senha, acesso,valido=False):
    con = sqlite3.connect(_ARQUIVO_BANCO_)
    cursor = con.cursor()
    cursor.execute('INSERT INTO usuario (email, senha,valido,acesso) VALUES (?, ?, ?, ?)', (email, senha,valido,acesso))
    con.commit()
    con.close()

def sqlite_atualiza_usuario(chave_acesso):
    con = sqlite3.connect(_ARQUIVO_BANCO_)
    cursor = con.cursor()
    cursor.execute('UPDATE usuario SET valido = 1 WHERE acesso = (?)', [chave_acesso])
    con.commit()
    con.close()

def sqlite_consulta_email(email):
    usuario = ''
    con = sqlite3.connect(_ARQUIVO_BANCO_)
    cursor = con.cursor()
    cursor.execute('SELECT * from usuario WHERE usuario.email = ?;', [email])
    for linha in cursor.fetchall():
        usuario = linha
    con.close()
    return usuario

def sqlite_consulta_usuario(email, senha):
    usuario = ''
    con = sqlite3.connect(_ARQUIVO_BANCO_)
    cursor = con.cursor()
    cursor.execute('SELECT * from usuario WHERE usuario.email = ? AND usuario.senha = ? AND usuario.valido = 1', (email, senha))
    for linha in cursor.fetchall():
        usuario = linha
    con.close()
    return usuario


# Arquivos estáticos (CSS, JS, etc.)
@app.route('/static/<path:path>', methods=['GET'])
def static_file(path):
    return app.send_static_file(path)

def envia_email(assunto,tos,body):
    msg = Message(assunto,sender=EMAIL_SENDER,recipients=tos)
    msg.body=body
    mail.send(msg)

@app.route('/', methods=['GET'])
def home():
    #envia_email("Teste de Função",['samuelgonalves00@gmail.com','wdmeida@gmail.com'],'Olá, se chegou essa msg... so responder... kkkkkkkkkkkkkk ')
    session['erro'] = ''
    session['num_tentativas'] = '0'
    
    # Verifica se o usuário está autenticado
    if 'email' in session:
        return env.get_template('index.html').render()

    else:
        return env.get_template('login.html').render(captcha="visibility: visible;")#hidden

@app.route('/cadastro', methods=['GET'])
def cadastro():
    session['erro'] = ''
    if 'email' in session:
        return env.get_template('index.html').render()

    return env.get_template('cadastro.html').render()


@app.route('/login', methods=['GET'])
def login():
    if 'email' in session:
        return env.get_template('index.html').render()
    
    email = session['erro']
    session['erro'] = ''
    if session['num_tentativas'] >= 3:
        return env.get_template('login.html').render(e=email,captcha="visibility: visible;")
    return env.get_template('login.html').render(e=email,captcha="visibility: visible;") #hidden

@app.route('/sair', methods=['GET'])
def sair():
    if 'email' in session:
        del session['email']

    return env.get_template('login.html').render()


@app.route('/autenticar', methods=['POST'])
def autenticar():
    
    email = request.form.get('email')
    senha = request.form.get('senha')

    recaptcha = request.form['g-recaptcha-response']
    
    if not recaptcha:
        session['num_tentativas'] = int(float(session['num_tentativas'])) + 1
        return redirect('/login')

    if not valida_recaptcha(recaptcha):
        session['num_tentativas'] = int(float(session['num_tentativas'])) + 1
        return redirect('/login')    

    if email and senha:
        sc = criptografa(senha)
        usuario = sqlite_consulta_usuario(email,sc)

        if usuario:
            session['email'] = email    
            session['num_tentativas'] = 0

        else:
            session['num_tentativas'] = int(float(session['num_tentativas'])) + 1
            session['erro'] = email
            return redirect('login')

    return redirect('/')


@app.route('/cadastrar', methods=['POST'])
def cadastrar():
    session['erro'] = ''
    session['num_tentativas'] = '0'
    email = request.form['email']
    senha = request.form['senha']
    senha2 = request.form['senha2']

    recaptcha = request.form['g-recaptcha-response']

    if not recaptcha:
        return redirect('/cadastro')

    if not valida_recaptcha(recaptcha):
        return redirect('/cadastro')    

    if not senha or not senha2:
        return redirect('/cadastro')

    if senha == senha2:
        sc = criptografa(senha)
        # Verifica se o usuário não existe
        if not sqlite_consulta_email(email):
            acesso = chave_acesso(email,senha,recaptcha)
            sqlite_cadastra_usuario(email, sc,acesso)
            MSG = TEMPLATE_TEXTO.format(acesso)
            envia_email("Confirmação de Cadastro",[email],MSG)
            return env.get_template('cadastrado.html').render()

    return redirect('/cadastro')

#Valida Cadastro
@app.route('/validar/<acesso>', methods=['GET'])
def validar_cadastro(acesso):
    sqlite_atualiza_usuario(acesso)
    print acesso
    return env.get_template('/login.html').render(captcha="visibility: visible;")

#Verifica se o recaptcha é válido.
def valida_recaptcha(recaptcha):

    response = {}
    #Defini os parâmetros que serão enviados para fazer a verificação.
    params = {
        'secret' : RECAPTCHA_SECRET_KEY,
        'response' : recaptcha,
        'remoteip' : 'localhost'
    }

    verify_rs = requests.get(URL_RECAPTCHA, params=params, verify=True)
    verify_rs = verify_rs.json()

    response['status'] = verify_rs.get("success", False)
    response['message'] = verify_rs.get('error_codes', None) or "Unspecified error."

    return response['status']

def chave_acesso(email,senha,recaptcha):
    h = hashlib.new('ripemd160')
    h.update(email+recaptcha+senha)
    return h.hexdigest()

def criptografa(senha):
    senha_cript = crypt.crypt(_SALT1+senha,"$6$")
    return senha_cript

if __name__ == "__main__":
    # Chave para o flask gerenciar a sessão HTTP
    app.secret_key = 'm;4slF=Y6]Afb/.p9Xd7iO8(V0yU~R"'
    app.run(debug=True, host="localhost")