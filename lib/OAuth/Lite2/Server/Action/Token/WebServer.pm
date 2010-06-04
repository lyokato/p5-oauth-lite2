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
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'code' not found"
    ) unless $code;

    my $redirect_url = $req->param("redirect_url");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'redirect_url' not found"
    ) unless $redirect_url;

    my $client_id = $req->param("client_id");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'client_id' not found"
    ) unless $client_id;

    my $client_secret = $req->param("client_secret");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'client_secret' not found"
    ) unless $client_secret;

    my $auth_info = $dh->get_auth_info_by_code($code)
        or OAuth::Lite2::Error::Server::BadVerificationCode->throw;

    OAuth::Lite2::Error::Server::InvalidClient->throw
        unless ($auth_info->client_id eq $client_id);

    # TODO
    #$dh->validate_client($client_id, $client_secret)
    #    or OAuth::Lite2::Error::Server::InvalidClient->throw;

    OAuth::Lite2::Error::Server::RedirectURIMismatch->throw
        unless ( $auth_info->redirect_url
            && $auth_info->redirect_url eq $redirect_url);

    my $secret_type = $req->param("secret_type");

    my $access_token = $dh->create_or_update_access_token(
        auth_info   => $auth_info,
        secret_type => $secret_type,
    );

    # TODO check returned $access_token?

    my $res = {
        access_token => $access_token->token,
    };
    $res->{expires_in} = $access_token->expires_in
        if $access_token->expires_in;
    $res->{access_token_secret} = $access_token->secret
        if $access_token->secret;
    $res->{refresh_token} = $auth_info->refresh_token
        if $auth_info->refresh_token;
    $res->{scope} = $auth_info->scope
        if $auth_info->scope;
    $res->{secret_type} = $secret_type
        if $secret_type;

    return $res;
}

1;
