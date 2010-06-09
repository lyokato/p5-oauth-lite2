use strict;
use Test::More tests => 47;
BEGIN {
    # core
    use_ok('OAuth::Lite2');

    use_ok('OAuth::Lite2::Error');

    use_ok('OAuth::Lite2::Formatters');
    use_ok('OAuth::Lite2::Formatter');
    use_ok('OAuth::Lite2::Formatter::JSON');
    use_ok('OAuth::Lite2::Formatter::XML');
    use_ok('OAuth::Lite2::Formatter::FormURLEncoded');

    use_ok('OAuth::Lite2::ParamMethods');
    use_ok('OAuth::Lite2::ParamMethod::AuthHeader');
    use_ok('OAuth::Lite2::ParamMethod::FormEncodedBody');
    use_ok('OAuth::Lite2::ParamMethod::URIQueryParameter');

    use_ok('OAuth::Lite2::Signer');
    use_ok('OAuth::Lite2::Signer::Algorithms');
    use_ok('OAuth::Lite2::Signer::Algorithm');
    use_ok('OAuth::Lite2::Signer::Algorithm::HMAC_SHA1');
    use_ok('OAuth::Lite2::Signer::Algorithm::HMAC_SHA256');

    use_ok('OAuth::Lite2::Util');

    use_ok('OAuth::Lite2::Agent');
    use_ok('OAuth::Lite2::Agent::Dump');
    use_ok('OAuth::Lite2::Agent::Strict');
    use_ok('OAuth::Lite2::Agent::PSGIMock');

    # client
    use_ok('OAuth::Lite2::Client');
    use_ok('OAuth::Lite2::Client::Token');
    use_ok('OAuth::Lite2::Client::TokenResponseParser');

    use_ok('OAuth::Lite2::Client::ClientCredentials');
    use_ok('OAuth::Lite2::Client::UserAgent');
    use_ok('OAuth::Lite2::Client::WebServer');
    use_ok('OAuth::Lite2::Client::Device');
    use_ok('OAuth::Lite2::Client::UsernameAndPassword');

    # server
    use_ok('OAuth::Lite2::Server::Context');

    use_ok('OAuth::Lite2::Server::Action::Token');
    use_ok('OAuth::Lite2::Server::Action::Token::ClientCredentials');
    use_ok('OAuth::Lite2::Server::Action::Token::DeviceCode');
    use_ok('OAuth::Lite2::Server::Action::Token::DeviceToken');
    use_ok('OAuth::Lite2::Server::Action::Token::Refresh');
    use_ok('OAuth::Lite2::Server::Action::Token::Username');
    use_ok('OAuth::Lite2::Server::Action::Token::WebServer');

    use_ok('OAuth::Lite2::Server::Endpoint::Token');
    use_ok('OAuth::Lite2::Server::Endpoint::EndUser');
    #use_ok('OAuth::Lite2::Server::Endpoint::ProtectedResource');

    use_ok('OAuth::Lite2::Server::Flows');
    use_ok('OAuth::Lite2::Server::Flow');
    use_ok('OAuth::Lite2::Server::Flow::ClientCredentials');
    use_ok('OAuth::Lite2::Server::Flow::Device');
    use_ok('OAuth::Lite2::Server::Flow::UserAgent');
    use_ok('OAuth::Lite2::Server::Flow::WebServer');
    use_ok('OAuth::Lite2::Server::Flow::UsernameAndPassword');

    use_ok('Plack::Middleware::Auth::OAuth2::ProtectedResource');
};



