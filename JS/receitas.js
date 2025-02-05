document.addEventListener('DOMContentLoaded', () => {
    carregarReceitas();  // Carregar receitas quando a página for carregada
});

// Envio do formulário de receita
document.getElementById('receita-form').addEventListener('submit', function (event) {
    event.preventDefault();  // Previne o envio padrão do formulário

    const nomeMedicamento = document.getElementById('nome_medicamento').value.trim();
    const dataValidade = document.getElementById('validade').value;
    const anexo = document.getElementById('anexo-receita').files[0];  // Obtém o arquivo enviado

    if (nomeMedicamento && dataValidade && anexo) {
        const formData = new FormData();
        formData.append('nome_medicamento', nomeMedicamento);
        formData.append('validade', dataValidade);
        formData.append('anexo_receita', anexo);

        fetch('http://localhost:3000/receitas', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(() => {
            carregarReceitas();  // Atualiza a lista de receitas após o envio
            this.reset();  // Reseta o formulário
        })
        .catch(error => console.error('Erro ao salvar receita:', error));
    }
});

// Função para carregar e exibir as receitas na lista
function carregarReceitas() {
    fetch('http://localhost:3000/receitas')
        .then(response => response.json())
        .then(data => {
            const listaExames = document.getElementById('lista-exames');
            listaExames.innerHTML = '';  // Limpa a lista antes de adicionar novos itens

            data.forEach(item => {
                const li = document.createElement('li');
                const anexoUrl = `http://localhost:3000/uploads/${item.anexo_receita}`;  // URL do arquivo

                // Adiciona a receita à lista com o link para o anexo
                li.innerHTML = `
                    Medicamento: ${item.nome_medicamento} <br>
                    Validade: ${item.validade} <br>
                    <a href="${anexoUrl}" target="_blank">Ver Receita</a>
                `;
                listaExames.appendChild(li);
            });
        })
        .catch(error => console.error('Erro ao carregar receitas:', error));
}

