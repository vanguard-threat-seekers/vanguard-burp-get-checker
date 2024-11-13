package com.vanguard.burp.getchecker;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.HashMap;
import java.util.Map;

public class GetChecker implements BurpExtension {

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("GetChecker Extension");
        api.logging().logToOutput("GetChecker Extension Initialized");

        // Define o handler para interceptar requisições e respostas HTTP
        HttpHandler handler = new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
                checkPostToGet(httpRequestToBeSent);
                return RequestToBeSentAction.continueWith(httpRequestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
                return ResponseReceivedAction.continueWith(httpResponseReceived);
            }
        };
        // Registra o handler para interceptar o tráfego HTTP
        Registration registration = api.http().registerHttpHandler(handler);
    }

    public void checkPostToGet(HttpRequestToBeSent request) {
        // Verifica se a requisição é POST e contém parâmetros no corpo
        if ("POST".equals(request.method()) && request.bodyToString() != null && !request.bodyToString().isEmpty()) {
            // Extrai os parâmetros do corpo da requisição POST como um mapa
            Map<String, String> postParams = parseParameters(request.bodyToString());

            // Constrói a query string para a requisição GET com os parâmetros do POST
            StringBuilder queryString = new StringBuilder();
            for (Map.Entry<String, String> entry : postParams.entrySet()) {
                if (queryString.length() > 0) {
                    queryString.append("&");
                }
                queryString.append(entry.getKey()).append("=").append(entry.getValue());
            }

            // Cria um HttpService com o host, porta e esquema da requisição original
            HttpService httpService = request.httpService();
            String urlPathWithParams = request.path() + "?" + queryString.toString();

            // Cria a requisição GET usando HttpRequest com HttpService e caminho
            HttpRequest getRequest = HttpRequest.httpRequest(httpService, urlPathWithParams);

            // Envia a requisição GET e obtém o HttpRequestResponse completo
            HttpRequestResponse requestResponse = api.http().sendRequest(getRequest);

            // Extrai a resposta do HttpRequestResponse
            HttpResponse response = requestResponse.response();
            short statusCode = response.statusCode();

            // Verifica se o código de status está no intervalo de sucesso (200-299)
            if (statusCode >= 200 && statusCode < 300) {
                api.logging().logToOutput("Potential vulnerability detected:\n" +
                        "POST request also accepted as GET\n" +
                        "Request: " + httpService.toString() + urlPathWithParams + "\n");
            }
        }
    }

    private Map<String, String> parseParameters(String body) {
        Map<String, String> params = new HashMap<>();
        String[] pairs = body.split("&");

        for (String pair : pairs) {
            String[] keyValue = pair.split("=");
            if (keyValue.length == 2) {
                params.put(keyValue[0], keyValue[1]);
            }
        }
        return params;
    }
}
