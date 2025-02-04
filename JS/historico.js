document.addEventListener('DOMContentLoaded', () => {
    carregarRegistros();
});

document.getElementById('form-historico').addEventListener('submit', function (event) {
    event.preventDefault();

    const condicao = document.getElementById('condicao-saude').value.trim();
    const alergia = document.getElementById('alergias').value.trim();

    if (condicao || alergia) {
        fetch('http://localhost:3000/historico', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ condicao, alergia })
        })
        .then(response => response.json())
        .then(() => {
            carregarRegistros();
            this.reset();
        })
        .catch(error => console.error('Erro ao salvar:', error));
    }
});

function carregarRegistros() {
    fetch('http://localhost:3000/historico')
        .then(response => response.json())
        .then(data => {
            const listaCondicoes = document.getElementById('lista-condicoes');
            const listaAlergias = document.getElementById('lista-alergias');

            listaCondicoes.innerHTML = '';
            listaAlergias.innerHTML = '';

            data.forEach(item => {
                if (item.condicao) {
                    const li = document.createElement('li');
                    li.textContent = item.condicao;
                    listaCondicoes.appendChild(li);
                }

                if (item.alergia) {
                    const li = document.createElement('li');
                    li.textContent = item.alergia;
                    listaAlergias.appendChild(li);
                }
            });
        })
        .catch(error => console.error('Erro ao carregar registros:', error));
}
