from flask import Flask, request, jsonify, redirect, url_for, render_template, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Numeric
import json


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///meuapp.db'
app.config['SECRET_KEY'] = 'uma_chave_secreta_bem_segura'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
correct_token = "uhdfaAADF123"


class Usuario(db.Model):
    id = Column(Integer, primary_key=True)
    nome = Column(String(120), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    senha = Column(String(120), nullable=False)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Webhook(db.Model):
    id = Column(Integer, primary_key=True)
    nome = Column(String(120), nullable=False)
    email = Column(String(120), nullable=False)
    status = Column(String(120), nullable=False)
    valor = Column(Numeric(10, 2), nullable=False)
    forma_pagamento = Column(String(120), nullable=False)
    parcelas = Column(Integer, nullable=False)
    acao = Column(String(120), nullable=False)

def init_db():
    with app.app_context():
        db.create_all()



@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


@app.route('/webhook', methods=['POST'])
def receive_webhook():
    headers = request.headers
    print(headers)
    raw_data = request.data
    print(raw_data)
    try:
        data = json.loads(raw_data)
        print(data)
    except:
        print("NÃO TRANSFORMANDO PARA JSON")
        return "ERRO 1"
    try:
        nome = data.get('nome')
        email = data.get('email')
        status = data.get('status')
        valor = data.get('valor')
        forma_pagamento = data.get('forma_pagamento')
        parcelas = data.get('parcelas')

        if status == 'aprovado':
            acao = "Acesso liberado, mensagem de boas vindas enviada!"
        elif status == 'recusado':
            acao = "Mensagem de pagamento recusado enviada"
        elif status == 'reembolsado':
            acao = "Retirado o acesso ao curso"
        
        print(acao)

        new_webhook = Webhook(
            nome=nome,
            email=email,
            status=status,
            valor=valor,
            forma_pagamento=forma_pagamento,
            parcelas=parcelas,
            acao = acao
        )

        db.session.add(new_webhook)
        db.session.commit()
        print(request.json, "JSON recebido com SUCESSO")
        return jsonify({'message': 'Webhook received and stored successfully'}), 201

    except Exception as e:
        print("ERRO!!")
        app.logger.error(f"Erro ao processar webhook: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('user', user_id=current_user.id))
    else:
        return render_template("home.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Usuario.query.filter_by(email=email).first()
        print("Email:", email, "Password:", password)
        if user and bcrypt.check_password_hash(user.senha, password):
            login_user(user)
            return redirect(url_for('user', user_id=user.id))  
        else:
            flash('Login inválido, verifique suas informações', 'error')
            return redirect(url_for('home'))
    else:
        return redirect(url_for('home'))
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        token = request.form["token"]
        nome = request.form["nome"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirmPassword"]

        existing_user = Usuario.query.filter_by(email=email).first()
        if existing_user:
            flash('Já existe uma conta com esse e-mail.', 'error')
            return redirect(url_for('register'))
        
        if token != correct_token: 
            flash('Token inválido, não foi possível realizar o cadastro.', 'error')
            return redirect(url_for('register'))

        if password!=confirm_password:
            flash('As senhas não coincidem', 'error')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Usuario(nome=nome, email=email, senha=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Conta criada com sucesso! Faça o login', 'success')
        return redirect(url_for('login'))
    else:
        return render_template("register.html")


@app.route('/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def user(user_id):
    if current_user.id == user_id:
        primeiro_nome = current_user.nome.split(' ')[0]
        if request.method == 'POST':
            nome = request.form.get('nome')
            email = request.form.get('email')
            status = request.form.get('status')  

            if not nome and not email and not status:
                resultados = Webhook.query.all() 
            else:
                query = Webhook.query
                if nome:
                    query = query.filter(Webhook.nome.ilike(f'%{nome}%'))
                if email:
                    query = query.filter(Webhook.email.ilike(f'%{email}%'))
                if status:
                    query = query.filter(Webhook.status.ilike(f'%{status}%'))

                resultados = query.all()
                if not resultados:
                    resultados = query.all()
        else:
            resultados = Webhook.query.all() 
        return render_template("usuario.html", user_name=primeiro_nome, webhooks=resultados) 
    else:
        return redirect(url_for('login')) 


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))



if __name__ == '__main__':
    init_db() 
    app.run(debug=True)

