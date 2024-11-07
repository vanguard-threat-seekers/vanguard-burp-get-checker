# GetChecker Extension

GetChecker é uma extensão do Burp Suite que verifica potenciais vulnerabilidades ao permitir que uma requisição HTTP POST seja aceita como GET, o que pode indicar uma má configuração de segurança.

## Funcionalidades

- Monitora requisições HTTP POST.
- Tenta reenviar a requisição como GET.
- Registra uma mensagem de log no Burp Suite se a resposta for bem-sucedida (código de status HTTP 2xx), indicando uma potencial vulnerabilidade.

## Estrutura do Projeto

- **Pacote**: `com.vanguard.burp.pii`
- **Classe Principal**: `GetChecker`
- **Dependências**: Burp Suite API Montoya

## Requisitos

- **Burp Suite**: Versão compatível com a API Montoya.
- **Java**: Versão 11 ou superior.
- **IDE**: IntelliJ IDEA (opcional, mas recomendado para editar o código).

## Instalação

1. Clone o repositório ou baixe o código-fonte.
2. Compile o código e gere um arquivo JAR usando Maven ou seu IDE preferido.
3. Abra o Burp Suite.
4. Navegue até `Extensions`.
5. Clique em `Add` e selecione o arquivo JAR gerado para carregar a extensão.

   ![image](https://github.com/user-attachments/assets/5d42c418-8544-4805-a698-a7fd1908f2e9)


## Uso

1. Inicie o Burp Suite e ative o proxy para capturar o tráfego HTTP.
2. Faça uma requisição POST para um endpoint.
3. A extensão `GetChecker` tentará reenviar a mesma requisição como GET.
4. Se a resposta com GET retornar um código de sucesso (2xx), a extensão registrará uma mensagem no log indicando a URL com a potencial vulnerabilidade.

   ![image](https://github.com/user-attachments/assets/8575b047-cb3d-4c1b-8f40-5577137fa60e)


## Exemplo de Log de Saída

Ao detectar uma vulnerabilidade, o log exibirá uma mensagem como esta:

Potential vulnerability detected: POST request also accepted as GET URL: http://exemplo.com/api/endpoint


## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir uma *issue* ou enviar um *pull request*.

## Licença
Este projeto é licenciado sob a Licença Pública Geral GNU (GNU GPL v3.0) - veja o arquivo [LICENSE](LICENSE) para mais detalhes.
