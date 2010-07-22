use strict;
use Test::More tests => 33;
BEGIN {
    # core
    use_ok('OAuth::Lite2');


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
    use_ok('OAuth::Lite2::Client::Error');
    use_ok('OAuth::Lite2::Client::Token');
    use_ok('OAuth::Lite2::Client::TokenResponseParser');
    use_ok('OAuth::Lite2::Client::WebServer');
    use_ok('OAuth::Lite2::Client::UsernameAndPassword');

    # server
    use_ok('OAuth::Lite2::Server::Error');

    use_ok('OAuth::Lite2::Server::Context');

    use_ok('OAuth::Lite2::Server::GrantHandlers');
    use_ok('OAuth::Lite2::Server::GrantHandler::AuthorizationCode');
    use_ok('OAuth::Lite2::Server::GrantHandler::Password');
    use_ok('OAuth::Lite2::Server::GrantHandler::RefreshToken');

    use_ok('OAuth::Lite2::Server::Endpoint::Token');

    use_ok('Plack::Middleware::Auth::OAuth2::ProtectedResource');
};



