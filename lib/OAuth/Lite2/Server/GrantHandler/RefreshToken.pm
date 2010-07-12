package OAuth::Lite2::Server::GrantHandler::RefreshToken;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::GrantHandler';
use OAuth::Lite2::Server::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $req = $ctx->request;
    my $dh  = $ctx->data_handler;

    my $client_id     = $req->param("client_id");
    my $client_secret = $req->param("client_secret");

    my $refresh_token = $req->param("refresh_token")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'refresh_token' not found"
        );

    my $auth_info = $dh->get_auth_info_by_refresh_token($refresh_token)
        or OAuth::Lite2::Server::Error::InvalidGrant->throw;
    # TODO check returned $auth_info?

    OAuth::Lite2::Server::Error::InvalidClientID->throw
        unless $auth_info->client_id eq $client_id;

    my $access_token = $dh->create_or_update_access_token(
        auth_info => $auth_info,
    );
    # TODO check returned $access_token?

    my $res = {
        access_token => $access_token->token,
    };
    $res->{expires_in} = $access_token->expires_in
        if $access_token->expires_in;
    $res->{refresh_token} = $auth_info->refresh_token
        if $auth_info->refresh_token;
    $res->{scope} = $auth_info->scope
        if $auth_info->scope;

    return $res;
}

1;
