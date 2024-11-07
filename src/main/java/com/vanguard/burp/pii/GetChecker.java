package com.vanguard.burp.pii;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;

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
        // Verifica se a requisição é POST
        if ("POST".equals(request.method())) {
            // Cria uma nova requisição GET baseada na requisição original
            HttpRequest getRequest = request.withMethod("GET");

            // Envia a requisição GET e obtém o HttpRequestResponse completo
            HttpRequestResponse requestResponse = api.http().sendRequest(getRequest);

            // Extrai a resposta do HttpRequestResponse
            HttpResponse response = requestResponse.response();
            short statusCode = response.statusCode();

            // Verifica se o código de status está no intervalo de sucesso (200-299)
            if (statusCode >= 200 && statusCode < 300) {
                String url = request.url();
                api.logging().logToOutput("Potential vulnerability detected:\n" +
                        "POST request also accepted as GET\n" +
                        "URL: " + url + "\n");
            }
        }
    }
}
