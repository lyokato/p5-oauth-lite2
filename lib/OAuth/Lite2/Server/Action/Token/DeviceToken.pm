package OAuth::Lite2::Server::Action::Token::DeviceToken;

use strict;
use warnings;

use base 'OAuth::Lite2::Server::Action::Token';
use OAuth::Lite2::Server::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $dh  = $ctx->data_handler;
    my $req = $ctx->request;

    my $code = $req->param("code");
    OAuth::Lite2::Server::Error::MissingParam->throw("code")
        unless $code;

    my $client_id = $ctx->req->param("client_id");
    OAuth::Lite2::Server::Error::MissingParam->throw("client_id")
        unless $client_id;

    my $auth_info = $dh->get_auth_info_by_code($code);

    if ($auth_info->client_id eq $client_id) {

        my $secret_type = $req->param("secret_type");

        my $access_token = $dh->create_or_update_access_token(
            auth_id     => $auth_info->id,
            secret_type => $secret_type,
        );

        return $access_token;

    } else {

        OAuth::Lite2::Server::Error::InvalidClient->throw;

    }
}

1;
