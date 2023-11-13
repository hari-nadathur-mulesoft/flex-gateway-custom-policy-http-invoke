use log::*;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use std::time::Duration;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CustomRootContext {
            config: CustomConfig::default(),
        })
    });
}}

// Policy configuration
#[derive(Default, Clone, Deserialize)]
struct CustomConfig {

    #[serde(alias = "header")]
    header: Option<String>,
}


// ROOT CONTEXT
// The struct will implement the trait RootContext and contain the Policy configuration
struct CustomRootContext {
    config: CustomConfig,
}

impl Context for CustomRootContext {}

// The trait RootContext is required by Proxy WASM
impl RootContext for CustomRootContext {

    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            self.config = serde_json::from_slice(config_bytes.as_slice()).unwrap();
        }

        true
    }

    // Other implemented methods
    // ...

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(CustomHttpContext {
            config: self.config.clone(),
            context_id: context_id
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

// HTTP CONTEXT
// The struct will implement the trait Http Context to support the HTTP headers and body operations

struct CustomHttpContext {
    pub config: CustomConfig,
    context_id: u32,
}

impl HttpContext for CustomHttpContext {

    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        debug!("on_http_request_headers");

        let client_id = self.get_http_request_header("client_id");
        let client_secret = self.get_http_request_header("client_secret");

        //Create the payload to pass to the API invocation as the HTTP POST body
        let payload = 
            "grant_type=client_credentials&audience=https://dev-ducugjkrhx01p8h3.us.auth0.com/api/v2/&client_id=".to_owned() + client_id.as_ref().unwrap() + "&client_secret=" + client_secret.as_ref().unwrap();

        //upstream URL is defined in API Manager against the entry corresponding to the Service "okta-token-service".
        //This is an async call and the response is handled by the function "on_http_call_response".
        match self.dispatch_http_call(
            "okta-token-service-19068467-a1aca501-ee9c-4b04-b252-5d41a388064a.0d0204ae-4811-4fca-81ea-af032b186b49.svc",
            vec![
                (":method", "POST"),
                (":path", "/oauth/token"),
                (":authority", "dev-ducugjkrhx01p8h3.us.auth0.com"),
                ("content-type", "application/x-www-form-urlencoded")
            ],
            Some(payload.as_bytes()),
            vec![],
            Duration::from_secs(10)
        )
        {
            Ok(response) => {
                debug!("#{} <- on_http_request_headers: {}", self.context_id, response);
            }   
            Err(e) => {
                debug!("#{} <- on_http_request_headers: {:#?}", self.context_id, e);
                self.send_http_response(
                    403,
                    vec![("Powered-By", "proxy-wasm")],
                    Some(b"API invocation failure\n"),
                );        
            }
        }

        //The flow _has_ to be paused for the invocation to complete, and continues upon execution of on_http_call_response().
        Action::Pause
    }

    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        debug!("on_http_request_body");
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        debug!("on_http_response_headers");
        for (name, value) in &self.get_http_response_headers() {
            debug!("#{} <- {}: {}", self.context_id, name, value);
        }
        Action::Continue
    }

    fn on_http_response_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        debug!("on_http_response_body");

        Action::Continue
    }

}

impl Context for CustomHttpContext {
    fn on_http_call_response(&mut self, _: u32, _: usize, body_size: usize, _: usize) {
        debug!("#{} <- on_http_call_response", self.context_id);

        if let Some(body) = self.get_http_call_response_body(0, body_size) {
            let s = String::from_utf8_lossy(&body);
        
            debug!("#{} <- on_http_call_response: result: {}", self.context_id, s);

            if !s.is_empty() && s.contains("access_token"){
                debug!("#{} <- on_http_call_response: access_token retrieved", self.context_id);

                self.resume_http_request();
                return;
            }
        }

        debug!("API invocation failure.");
        self.send_http_response(
            403,
            vec![("Powered-By", "proxy-wasm")],
            Some(b"Access Denied\n"),
        );
    }
}

