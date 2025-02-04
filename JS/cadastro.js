document.getElementById('form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const nome = document.getElementById('nome').value;
    const cpf = document.getElementById('cpf').value;
    const senha = document.getElementById('senha').value;
    const dataNascimento = document.getElementById('dataNascimento').value;
    const genero = document.getElementById('genero').value;
    const email = document.getElementById('email').value;
    const telefone = document.getElementById('telefone').value;
    const endereco = document.getElementById('endereco').value;
    const message = document.getElementById('message');

    message.textContent = 'Processando cadastro...';
    message.style.color = 'blue';

    try {
        const response = await fetch('http://localhost:3000/cadastro', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nome, cpf, senha, dataNascimento, genero, email, telefone, endereco }),
        });

        if (response.ok) {
            message.textContent = 'Cadastro efetuado com sucesso! Redirecionando...';
            message.style.color = 'green';

            // Limpa o formulário
            document.getElementById('form').reset();

            setTimeout(() => {
                window.location.href = 'login.html';
            }, 3001);
        } else {
            const errorMessage = await response.text();
            message.textContent = `Erro: ${errorMessage}`;
            message.style.color = 'red';
        }
    } catch (error) {
        message.textContent = 'Erro ao conectar com o servidor. Tente novamente.';
        message.style.color = 'red';
    }
});
