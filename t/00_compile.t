use strict;
use Test::More tests => 28;
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

    # server
    use_ok('OAuth::Lite2::Server::Context');

    use_ok('OAuth::Lite2::Server::GrantHandlers');
    use_ok('OAuth::Lite2::Server::GrantHandler::AuthorizationCode');
    use_ok('OAuth::Lite2::Server::GrantHandler::BasicCredentials');
    use_ok('OAuth::Lite2::Server::GrantHandler::RefreshToken');

    use_ok('OAuth::Lite2::Server::Endpoint::Token');

    use_ok('Plack::Middleware::Auth::OAuth2::ProtectedResource');
};



