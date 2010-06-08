package OAuth::Lite2::Server::Action::Token::Username;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Action::Token';
use OAuth::Lite2::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $dh  = $ctx->data_handler;
    my $req = $ctx->request;

    my $client_id = $req->param("client_id");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'client_id' not found"
    ) unless $client_id;

    my $client_secret = $req->param("client_secret");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'client_secret' not found"
    ) unless $client_secret;

    my $username = $req->param("username");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'username' not found"
    ) unless $username;

    my $password = $req->param("password");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'password' not found"
    ) unless $password;

    my $client_user_id = $dh->get_client_user_id($client_id, $client_secret)
        or OAuth::Lite2::Error::Server::InvalidClient->throw;

    my $user_id = $dh->get_user_id($username, $password)
        or OAuth::Lite2::Error::Server::InvalidUser->throw;

    my $scope = $req->param("scope");

    my $auth_info = $dh->create_or_update_auth_info(
        client_id => $client_id,
        user_id   => $user_id,
        scope     => $scope,
    );

    # TODO check $auth_info

    my $secret_type = $req->param("secret_type");

    my $access_token = $dh->create_or_update_access_token(
        auth_info   => $auth_info,
        secret_type => $secret_type,
    );

    # TODO check $access_token

    return $access_token;
}

1;
