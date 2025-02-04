document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault(); // Previne o envio padrão do formulário

    console.log('Formulário enviado!'); // DEBUG

    const cpf = document.getElementById('cpf').value;
    const senha = document.getElementById('senha').value;
    const message = document.getElementById('message');

    console.log('CPF:', cpf); // DEBUG
    console.log('Senha:', senha); // DEBUG

    if (!cpf || !senha) {
        message.textContent = 'Preencha todos os campos!';
        return;
    }

    message.textContent = 'Fazendo login...';

    try {
        const response = await fetch('http://localhost:3000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cpf, senha }) 
        });

        const data = await response.json();
        console.log('Resposta do servidor:', data);

        if (response.ok && data.success) {
            localStorage.setItem('token', data.token);
            window.location.href = 'menu.html'; // Redireciona para a página do usuário
        } else {
            message.textContent = data.message || 'Erro ao fazer login';
        }
    } catch (error) {
        console.error('Erro na requisição:', error);
        message.textContent = 'Erro ao fazer login. Tente novamente.';
    }
});
