package OAuth::Lite2::Server::GrantHandler::Password;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::GrantHandler';
use OAuth::Lite2::Server::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $req = $ctx->request;
    my $dh  = $ctx->data_handler;

    my $client_id = $req->param("client_id");

    my $username = $req->param("username");
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'username' not found"
    ) unless $username;

    my $password = $req->param("password")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'password' not found"
        );

    my $user_id = $dh->get_user_id($username, $password)
        or OAuth::Lite2::Server::Error::InvalidGrant->throw;

    my $scope = $req->param("scope");

    my $auth_info = $dh->create_or_update_auth_info(
        client_id => $client_id,
        user_id   => $user_id,
        scope     => $scope,
    );
    # TODO check $auth_info

    my $access_token = $dh->create_or_update_access_token(
        auth_info => $auth_info,
    );
    # TODO check $access_token

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
