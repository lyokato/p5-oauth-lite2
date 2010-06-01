package OAuth::Lite2::Server::Action::Token::WebServer;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Action::Token';
use OAuth::Lite2::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $dh  = $ctx->data_handler;
    my $req = $ctx->request;

    my $code = $req->param("code");
    OAuth::Lite2::Server::Error::MissingParam->throw("code")
        unless $code;

    my $redirect_url = $req->param("redirect_url");
    OAuth::Lite2::Server::Error::MissingParam->throw("redirect_url")
        unless $redirect_url;

    my $client_id = $req->param("client_id");
    OAuth::Lite2::Server::Error::MissingParam->throw("client_id")
        unless $client_id;

    my $client_secret = $req->param("client_secret");
    OAuth::Lite2::Server::Error::MissingParam->throw("client_secret")
        unless $client_secret;

    my $auth_info = $dh->get_auth_info_by_code($code);
    OAuth::Lite2::Server::Error::InvalidCode->throw()
        unless $auth_info;

    if ( $auth_info->redirect_url eq $redirect_url
      && $auth_info->client_id    eq $client_id ) {

        my $secret_type = $req->param("secret_type");

        my $access_token = $dh->create_or_update_access_token(
            auth_id     => $auth_info->id,
            secret_type => $secret_type,
        );

    } else {

        OAuth::Lite2::Server::Error::InvalidClient->throw;

    }
}

1;
